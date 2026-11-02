# Copyright (c) 2026 Ankerin
# SPDX-License-Identifier: MIT

"""Record advancing execution and durable certified-node TPS, one process at a time."""

import argparse
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time


def run(command, **kwargs):
    return subprocess.run(command, check=True, text=True, encoding="utf-8", capture_output=True, **kwargs)


def summarize(rows):
    elapsed = [int(row["elapsed_ns"]) for row in rows]
    count = sum(int(row["transactions"]) for row in rows)
    ordered = sorted(elapsed)
    return {
        "samples": len(rows), "transactions": count,
        "sustained_tps": count * 1e9 / sum(elapsed),
        "median_block_tps": int(rows[0]["count"]) * 1e9 / statistics.median(elapsed),
        "block_latency_ms": {
            f"p{p}": ordered[max(0, math.ceil(len(ordered) * p / 100) - 1)] / 1e6
            for p in (50, 95, 99)
        },
        "median_stage_ms": {
            key.removesuffix("_ns"): statistics.median(int(row[key]) for row in rows) / 1e6
            for key in ("admission_ns", "production_ns", "publication_ns") if key in rows[0]
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    parser.add_argument("--execution", type=Path, required=True, help="built local_tps binary")
    parser.add_argument("--node", type=Path, help="built certified_tps binary")
    parser.add_argument("--reference-node", type=Path, help="baseline certified_tps binary, measured alongside the current node")
    parser.add_argument("--reference-source", type=Path, help="baseline worktree containing the transplanted equivalent fixture")
    parser.add_argument("--sizes", default="256,4096")
    parser.add_argument("--rounds", type=int, default=40)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    if bool(args.reference_node) != bool(args.reference_source) or (args.reference_node and not args.node):
        parser.error("reference-node and reference-source require each other and --node")
    sizes = [int(n) for n in args.sizes.split(",")]
    if not sizes or any(n < 2 or n > 8192 for n in sizes):
        parser.error("sizes must be in [2,8192]")
    if not (1 <= args.rounds <= 1000 and 1 <= args.repeats <= 10 and 1 <= args.workers <= 32):
        parser.error("invalid rounds, repeats or workers")
    args.output.mkdir(parents=True, exist_ok=False)
    binaries = {"execution": args.execution.resolve()}
    if args.node:
        binaries["node"] = args.node.resolve()
    if args.reference_node:
        binaries["reference_node"] = args.reference_node.resolve()
    report = {
        "schema": 1, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "revision": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
        "dirty_status": run(["git", "status", "--short"]).stdout,
        "diff_sha256": hashlib.sha256(run(["git", "diff", "--no-ext-diff"]).stdout.encode()).hexdigest(),
        "rustc": run(["rustc", "--version", "--verbose"]).stdout,
        "host": {"platform": platform.platform(), "processor": platform.processor(), "logical_cpus": os.cpu_count()},
        "config": {"sizes": sizes, "rounds": args.rounds, "repeats": args.repeats, "workers": args.workers, "warmup_blocks": 3},
        "binaries": {key: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for key, path in binaries.items()},
        "source_sha256": {
            str(path).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for root in ("crates/execution", "crates/state", "crates/node", "crates/mempool", "crates/rpc", "apps/daemon")
            for path in sorted(Path(root).rglob("*.rs"))
        },
        "build_input_sha256": {
            str(path).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [Path("Cargo.toml"), Path("Cargo.lock"), Path("rust-toolchain.toml"),
                         *sorted(Path("crates").rglob("Cargo.toml"))]
        },
        "runs": [],
        "scope": {
            "execution": "pre-signed transactions, advancing state and atomic RAM commit; excludes transport, signing, consensus and disk",
            "node": "pre-signed transactions over TCP loopback; admission, production, three locally generated quorum signatures, certificate verification, synchronized append log and durable acknowledgement; excludes distributed agreement, PoTB transitions and TLS",
            "validation": "three warmups advance state; all final account balances/nonces checked; node additionally reopens log and checks every certificate and successful receipt",
        },
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    if args.reference_source:
        reference = args.reference_source.resolve()
        report["reference"] = {
            "revision": run(["git", "rev-parse", "HEAD"], cwd=reference).stdout.strip(),
            "fixture": "same pre-signed loopback/certificate/durable-recovery workload; scalar admission on the reference API",
            "source_sha256": {
                str(path.relative_to(reference)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
                for root in ("crates/execution", "crates/state", "crates/node", "crates/mempool")
                for path in sorted((reference / root).rglob("*.rs"))
            },
        }
    if platform.system() == "Windows":
        report["host"]["windows_hardware"] = json.loads(run([
            "powershell", "-NoProfile", "-Command",
            "$p=Get-CimInstance Win32_Processor; $c=Get-CimInstance Win32_ComputerSystem; "
            "@{cpu=$p.Name;physical_cores=$p.NumberOfCores;logical_cpus=$p.NumberOfLogicalProcessors;ram_bytes=$c.TotalPhysicalMemory}|ConvertTo-Json -Compress",
        ]).stdout)
    configurations = [("execution", shape, size, mode) for size in sizes
                      for shape in ("sender", "recipient", "ring", "independent")
                      for mode in ("waves", "fold", "seal")]
    if args.node:
        configurations += [(kind, shape, size, "default") for size in sizes
                           for shape in ("recipient", "ring", "independent")
                           for kind in (("node", "reference_node") if args.reference_node else ("node",))]
    for repeat in range(args.repeats):
        # Alternate direction to reduce fixed-order thermal/drift bias.
        order = configurations if repeat % 2 == 0 else list(reversed(configurations))
        for kind, shape, size, mode in order:
            name = f"{kind}-{shape}-{size}-{mode}-{repeat}"
            if kind == "execution":
                command = [str(binaries[kind]), str(size), str(args.rounds), str(args.workers), shape, mode]
            else:
                command = [str(binaries[kind]), str(size), str(args.rounds), str((args.output / name).resolve()), shape]
            result = run(command, timeout=600)
            (args.output / f"{name}.csv").write_text(result.stdout, encoding="utf-8")
            (args.output / f"{name}.stderr.txt").write_text(result.stderr, encoding="utf-8")
            rows = list(csv.DictReader(io.StringIO(result.stdout)))
            if len(rows) != args.rounds or any(int(r["transactions"]) != size or int(r["elapsed_ns"]) <= 0 for r in rows):
                raise ValueError(f"incomplete benchmark {name}")
            record = {"name": name, "kind": kind, "shape": shape, "size": size, "mode": mode, "repeat": repeat,
                      "command": command, "csv_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(), **summarize(rows)}
            report["runs"].append(record)
            (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(f"{name}: {record['sustained_tps']:.0f} sustained TPS", flush=True)
    report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report["source_unchanged"] = all(
        hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
        for path, digest in report["source_sha256"].items()
    )
    report["binaries_unchanged"] = all(
        hashlib.sha256(path.read_bytes()).hexdigest() == report["binaries"][key]["sha256"]
        for key, path in binaries.items()
    )
    report["build_inputs_unchanged"] = all(
        hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
        for path, digest in report["build_input_sha256"].items()
    )
    if args.reference_source:
        report["reference_unchanged"] = all(
            hashlib.sha256((reference / path).read_bytes()).hexdigest() == digest
            for path, digest in report["reference"]["source_sha256"].items()
        )
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not all(report.get(key, True) for key in ("source_unchanged", "binaries_unchanged", "build_inputs_unchanged", "reference_unchanged")):
        raise ValueError("benchmark sources or binaries changed during measurement")


if __name__ == "__main__":
    main()
