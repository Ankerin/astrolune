# Copyright (c) 2026 Astrolune contributors
# SPDX-License-Identifier: MIT

"""Package a native CI build; these archives are not signed release artifacts."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile


def main():
    target = sys.argv[1]
    suffix = ".exe" if target.endswith("-windows-msvc") else ""
    binaries = Path("target") / target / "release"
    output = Path("target/ci-artifacts")
    output.mkdir(parents=True, exist_ok=True)
    metadata = output / "BUILD.json"
    metadata.write_text(
        json.dumps(
            {
                "revision": os.environ["GITHUB_SHA"],
                "target": target,
                "rustc": subprocess.check_output(["rustc", "-Vv"], text=True).strip(),
                "profile": "release",
                "features": "all",
                "release": False,
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    archive = output / f"astrolune-{target}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name in ("cli", "daemon", "cargo-contract"):
            binary = binaries / f"{name}{suffix}"
            bundle.add(binary, arcname=binary.name)
        for name in ("LICENSE", "README.md", "Cargo.lock", "rust-toolchain.toml"):
            bundle.add(name, arcname=name)
        bundle.add(metadata, arcname=metadata.name)
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    (output / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    metadata.unlink()


if __name__ == "__main__":
    main()
