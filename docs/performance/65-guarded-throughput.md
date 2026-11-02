<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

[Documentation](../README.md) / [Performance and architecture research](README.md)

# 65. Guarded payment execution and reproducible local throughput

Date: November 2, 2026. VeyraFold is implemented and enabled for supported payment
batches. LuneSeal is implemented as an explicit experiment and remains disabled
by default. These changes do not establish a world throughput record or a new
consensus protocol. The native LLVM implementation and its qualification remain
documented in [64](../languages/trocto/64-trocto-native-llvm.md).

## Comparable published measurements

Sources were checked on November 2–3, 2026. Published TPS values require their
workload, hardware and completion boundary:

| Primary source | Reported result | Machine and measured boundary |
| --- | ---: | --- |
| [Firedancer tuning guide](https://docs.firedancer.io/guide/tuning.html) | about 112,000 TPS stock; 389,500 TPS tuned | One 64-core AMD EPYC 9555P. Locally generated signed independent transfers reach the validator over QUIC loopback. The tuned experiment raises block/shred limits. |
| [Block-STM paper, §4.1](https://aptoslabs.com/pdf/2203.06871.pdf) | up to 170,000 TPS for Aptos payments | AWS c5a.16xlarge, AMD EPYC, 128 GB, up to 32 physical cores, Ubuntu 18.04. Move execution and outputs; persistence is excluded. |
| [Solana's historical architecture article](https://solana.com/uk/news/8-innovations-that-make-solana-the-first-web-scale-blockchain) | 50,000 TPS | A testnet of over 200 separate nodes, rather than a one-host result. |

Firedancer distinguishes packet ingress above one million TPS per network tile
from execution. Its guide gives a protocol-limited estimate around 81,000 TPS
and explicitly calls its local benchmark synthetic. The 65,000 number commonly
associated with Solana is not used here as proof of a same-host comparison.
No competitor was executed on this Ryzen host. Neither division by core count
nor comparison to a different pipeline stage proves superiority.

## VeyraFold implementation

`crates/execution/src/fold.rs` constructs account event streams from decoded
native-payment payloads, rather than trusting producer access plans. It supports
whole batches of 64–8192 payments, at most 8 MiB of encoded input, with existing
sender and recipient accounts. Self-transfers, missing accounts, mixed contract
batches and larger inputs retain the existing executor. Unsupported input is an
acceleration boundary, not a new transaction rejection rule.

An event is a partial balance translation `(delta, low, high)`. Composition uses
the algebra in [62](62-original-architecture-proposals.md). Sender guards reserve
`amount + cost(resource_limit, authenticated_prices)`, while their actual delta
uses `amount + actual_fee`. Recipient guards retain the upper balance bound.
Checked `i128` arithmetic prevents intermediate representation overflow.

Each account stream is split into at most 128-event segments. One retained,
bounded worker pool performs three phases:

1. Compose each segment's guards and count outgoing operations independently.
2. After the coordinator scans segment summaries in account order, reconstruct
   the exact balance and nonce before every debit and credit independently.
3. Execute every transaction through the complete existing `PaymentSession` on
   its reconstructed two-account input. This includes strict Ed25519 verification,
   shape, chain, expiry, nonce, prices, declared access, resource reservation,
   actual charging, overflow, canonical diffs, leases and receipts.

The implementation uses a blocked prefix scan, not an unbounded logarithmic-depth
scan: within an account its balance arithmetic depth is bounded by the number of
segments plus 128. The important practical change is that a shared sender or
recipient no longer serializes signature verification and receipt construction.
All transaction outputs are restored to their original order. Total resources
are checked by an ordered reduction before atomic commit.

Reconstructed inputs cannot issue authenticated state proofs. Every speculative
error discards the entire result and replays the ordinary signed session from the
same parent, preserving canonical error precedence and publishing no prefix.
Existing local native-backend failure handling remains unchanged.

### Correspondence to sequential execution

For a successful supported batch, each account event prefix starts at its parent
account state and uses exactly the debit/credit delta of the reference payment.
Incoming credits preserve nonce; outgoing events add one. Induction over the
ordered events therefore gives the reference input account state at each
transaction. `PaymentSession` then checks and materializes that transaction's
complete reference transition. Aggregate guard acceptance forbids temporary
underflow/overflow even when later funding would repair the net balance. Ordered
resource checks and the ordinary state backend complete the correspondence.

If any reference check fails, no correspondence assumption is used to publish
state: serial replay returns the actual first failure. This argument supplements
the differential tests; it is not a machine-checked proof of the whole network.

## LuneSeal implementation and activation gate

`CommitSeals` in the state tree partitions affected existing-key subtrees into
regions of at most 64 leaves. A private plan retains the parent root, ordered
transaction commitment, exact base subtree handles, key ranges and last writer
for each actual account key. Plans are bounded to 8192 transactions, two keys
per transaction, and require at least 512 distinct changed keys.

Execution publishes a final value into its single-assignment slot only when the
successful transaction is that key's last writer. An acquire/release countdown
allows the final completing writer to hash its subtree immediately. There is no
global execution lock and no per-value mutex. Other transactions can still be
checking signatures. Failed attempts discard their unpublished seals.

Commit still performs every state size/bounds check in operation order before
collapsing final writes. It reuses a sealed subtree only when the base node's
identity and every actual final key/value match. Incomplete, stale, changed or
unsupported hints use ordinary hashing; insertion/deletion uses the existing
topology fallback. Version-1 sorted leaves, odd-node promotion, root count wrapper,
proof and snapshot bytes remain unchanged. `ready_partitions` and
`reused_partitions` permit verification that early hashing really occurred.

`ExecutionAcceleration::FoldAndSeal` selects this experiment explicitly.
`execute_parallel` defaults to `Fold`: LuneSeal must pass the proposed ≥10%
execution-plus-commit improvement and ≤5% regression gates before automatic
activation. Correctness alone does not justify making the network slower.

## Production and public admission

The reference network now selects up to 256 transactions under its actual
1 MiB encoded block-body budget, replacing the previous worst-case cap of 15.
The fixed 208-byte envelope, each four-byte transaction framing length and exact
canonical transaction size are counted before execution. Oversized and rejected
candidates consume neither state nor byte budget. Rotating/PoTB production
reserves the system envelope before selecting application transactions. Received
blocks and local proposals enforce the same budget. The codec's count/byte bounds
and format are unchanged. Both validator and observer gossip limit pending
transaction payloads to 2 MiB per response, including with large valid pools.
All validators/observers in a cluster must upgrade
together before producing blocks above 15 transactions: older versions reject
them. Stored blocks that already met the old limits remain readable.

The producer first attempts bounded parallel execution of its candidate prefix.
When the whole prefix succeeds, its order and outputs equal the old selector.
On transaction rejection it runs the original selector, which skips invalid pool
entries while continuing valid work. State/native infrastructure failures remain
local failures. Static-committee production retains its verified execution under
the existing complete snapshot/proposal binding; certificate checks and durable
storage still precede publication. Rotating/PoTB production retains its existing
system-effect binding and validation path.

Bulk admission checks every transaction against the same finalized admission
view concurrently and inserts results in input order. It preserves single-submit
errors, duplicate/nonce handling, sequence numbers and pool limits. It does not
admit future nonces or spend pending incoming funds. A transaction ID index removes
the mempool's previous linear duplicate search on every insertion.

The network validator and observer expose this through JSON-RPC
`submit_transactions`, with `params.data` an array of hex transactions. The typed
client returns an ordered list of individual IDs or errors. The public bound is
1024 entries and 480 KiB total canonical bytes within the existing 1 MiB JSON
frame; malformed framing/canonical decoding rejects the request before admission.
Acceptance remains distinct from finalization. The demonstration RPC service
does not expose this network optimization.

## Novelty and prior art

The two names originate in the project's earlier research proposals, not in a
claim of globally unique branding. Prefix scans, partial translations, dependency
DAGs, persistent Merkle trees, single-assignment slots, indexed pools and cached
validation are established techniques. The specific contributions under review
are complete guarded native-payment input reconstruction with reference error
replay, and last-writer execution readiness driving same-block v1 subtree reuse.

[Block-STM](https://arxiv.org/abs/2203.06871) handles arbitrary VM execution by
detecting stale reads and re-executing transactions. VeyraFold's supported payment
amounts are signed inputs and its successful path constructs exact account
prefixes before reference checks. It does not replace the arbitrary contract DAG.

[SWMT](https://doi.org/10.1145/3786701), an accepted SIGMOD 2026 paper, explicitly
studies delayed writes and separating commitment work from execution. Its
publisher abstract is evidence of closely related work; the complete paper was
not accessible in this session. LuneSeal keeps this block's root synchronous and
unchanged. This distinction is a design description, not proof that equivalent
prior algorithms do not exist. Global architectural uniqueness is unproven.

## Reproduction and completion boundaries

Build with the pinned Rust toolchain. On Windows first run `tools/enter-dev.ps1`.

```powershell
. ./tools/enter-dev.ps1
cargo build --locked --release -p execution --example local_tps -p node --example certified_tps
python -B tools/local-tps.py --output target/my-tps-run --execution target/release/examples/local_tps.exe --node target/release/examples/certified_tps.exe --sizes 256,4096 --rounds 40 --repeats 3 --workers 8
```

On Linux omit `.exe` and use the installed pinned Rust toolchain. Each run needs
a new output directory. The runner executes processes sequentially, alternates
configuration order across repetitions, records raw CSV, per-stage latency,
compiler/hardware/binary/source hashes, and never erases previous evidence.

To reproduce the reference comparison, use a detached checkout of `fd4a1da` and
the retained [equivalent reference fixture](../assets/tps-qualification-2026-11-03/reference-certified-tps.rs).
That fixture changes only admission to the original scalar API and omits the new
byte-budget field, which was unrestricted in the reference producer. Its loads,
canonical bytes, account model, loopback, certificates, persistence and recovery
checks match the current fixture. Build it into a separate target directory:

```powershell
git worktree add --detach target/tps-baseline fd4a1da
New-Item -ItemType Directory -Path target/tps-baseline/crates/node/examples -Force
Copy-Item docs/assets/tps-qualification-2026-11-03/reference-certified-tps.rs target/tps-baseline/crates/node/examples/certified_tps.rs
cargo build --locked --release --manifest-path target/tps-baseline/Cargo.toml --target-dir target/tps-baseline-build -p node --example certified_tps
python -B tools/local-tps.py --output target/my-comparison --execution target/release/examples/local_tps.exe --node target/release/examples/certified_tps.exe --reference-node target/tps-baseline-build/release/examples/certified_tps.exe --reference-source target/tps-baseline --sizes 256,4096 --rounds 40 --repeats 3 --workers 8
```

Reference/current node runs alternate within each workload and reverse order on
alternate repetitions. Every comparison retains both source sets and binary
hashes. The runner refuses a run whose sources, build inputs or binaries changed
while it measured them. This controls accidental build drift; it does not provide
independent machines, statistically estimated confidence intervals or external
background-process control.

Both fixtures pre-sign transactions outside the timed interval. Each measured
block has new IDs/nonces and really advances state; three untimed warmup blocks
also advance it. Every final account balance/nonce is checked against an
independent accounting model. Transactions transfer one positive native unit and
burn one compute fee. No vote/system transaction inflates the TPS numerator.
The same-sender execution fixture supplies ordered nonces directly to the block
executor. Public finalized-state admission rejects future nonces, so that fixture
cannot be injected as a single public admission batch. The node fixture instead
uses distinct senders whose current nonces are admissible together.

The execution benchmark includes strict verification, actual effects, receipts
and atomic RAM commit. It excludes transport, client signing, consensus and disk.
The certified-node benchmark includes canonical decode over TCP loopback,
admission, production, three locally generated quorum signatures, certificate
verification, synchronized append-log/head publication and a client acknowledgement.
Reopening additionally checks all historical certificates, successful receipts
and the full final state. It excludes distributed agreement, real PoTB system
transitions, peer TLS and an online signing load generator. It is a certified
single-node pipeline measurement, not mainnet/network TPS.

The 256-transaction fixture fits the reference network's block-count limit. The
4096-transaction fixture deliberately uses a generic producer with a 16 MB byte
budget and a custom loopback load frame; it measures backend pipeline scaling
above the reference network's 256-transaction wire limit. A separate integration
test finalizes 80 signed payments through real `NetworkNode` consensus, authenticates
the certificate, checks every final balance/nonce, synchronizes an observer and
reopens both roles with identical state and all 80 receipts. That test establishes
network integration, not a timed TPS result.

Each report states sustained TPS as total successful transactions divided by total
measured elapsed time. A median block rate is reported separately. Block p50/p95/p99
latencies describe this closed-loop pre-signed load; they are not per-transaction
tail latencies under independent arrivals or confidence intervals. Independent
competitor runs, geographical consensus, mixed contracts, invalid-load throughput,
memory high-water marks and power-loss durability qualification remain necessary
before a network record can be claimed.

## Verification and evidence

Differential tests compare all outputs, diffs, leases, resources, errors, roots and
snapshot bytes on contended random payments, segment boundaries, reserve/fee
differences, nonce exhaustion, intermediate funding/overflow and malformed inputs.
State tests cover reverse/concurrent final-writer completion, actual subtree
reuse, stale/incomplete seals, altered effects, topology changes and transient
bounds. Producer tests cover per-entry bulk errors and the invalid-prefix selector
fallback. RPC/client/daemon tests cover batch bounds, result order, malformed
responses and live validator/observer admission semantics.
An observer regression test admits a valid pending pool larger than the 8 MiB
exchange bound and verifies that its bounded gossip response still encodes.

CI exercises all three accelerators and durable reopening on Windows and Linux,
retaining raw evidence. That job has no timing threshold: shared runners cannot
establish a performance ranking.

### Local qualification, November 3, 2026 (Moscow)

The [qualification record](../assets/tps-qualification-2026-11-03/qualification.json),
[complete report](../assets/tps-qualification-2026-11-03/report.json) and
[numeric summary](../assets/tps-qualification-2026-11-03/summary.json) retain 108
sequential runs: three repetitions of 40 measured blocks per configuration,
plus three excluded advancing warmups. All 4,320 measured blocks contain their
complete intended transaction count, totaling 9,400,320 successful transactions
across execution/current-node/reference-node configurations.

Host: AMD Ryzen 7 7800X3D, 8 physical and 8 exposed logical CPUs, approximately
32 GB RAM, Windows build 26200, Rust 1.99.0. The measured executable and both
source sets/build inputs remained unchanged throughout the measurement. The
current working tree is based on `fd4a1da`; the report retains source and binary
hashes instead of presenting uncommitted changes as a separate Git revision.
No builds or tests ran concurrently with this qualified series.

The following rates are **medians of three sustained rates**. Each sustained
rate divides the 40 successful block counts by the sum of their elapsed times.
Raw CSV and the summary also retain each repetition's range, pooled sustained
rate and pooled block latency quantiles.

| Execution workload | Transactions/block | Waves TPS | VeyraFold TPS | Fold/Waves |
| --- | ---: | ---: | ---: | ---: |
| Shared sender | 256 | 24,078 | 89,910 | 3.73× |
| Shared recipient | 256 | 22,848 | 87,736 | 3.84× |
| Ring | 256 | 23,077 | 77,892 | 3.38× |
| Independent pairs | 256 | 70,488 | 72,006 | 1.02× |
| Shared sender | 4096 | 24,821 | 165,845 | 6.68× |
| Shared recipient | 4096 | 22,563 | 116,758 | 5.17× |
| Ring | 4096 | 22,283 | 116,018 | 5.21× |
| Independent pairs | 4096 | 91,796 | 97,877 | 1.07× |

This is an ablation against the retained wave executor in the current build.
The independent 256-transaction result is small relative to observed run drift;
it does not establish a robust universal gain. Small-batch scheduling also causes
large differences between modes with identical execution work. Affinity/noise and
confidence-interval qualification remain open.

| Certified-node workload | Transactions/block | Reference `fd4a1da` TPS | Current TPS | Current/reference |
| --- | ---: | ---: | ---: | ---: |
| Shared recipient | 256 | 6,728 | 20,297 | 3.02× |
| Ring | 256 | 6,641 | 19,930 | 3.00× |
| Independent pairs | 256 | 8,180 | 19,077 | 2.33× |
| Shared recipient | 4096 | 6,618 | 30,457 | 4.60× |
| Ring | 4096 | 6,536 | 30,661 | 4.69× |
| Independent pairs | 4096 | 8,460 | 28,840 | 3.41× |

The 4096 rows exceed reference-network wire limits and measure a generic backend
pipeline. Neither table measures distributed consensus or an online signing
generator. The integration test above establishes actual network behavior at 80
transactions, without assigning it a TPS value.

For the 4096 shared-recipient node workload, pooled median stage times are 30.8 ms
for TCP/decode/admission, 47.9 ms for proposal construction/execution and 51.1 ms
for certificate/publication. Block p50/p95/p99 are 131.5/144.1/155.1 ms. At 256,
the same latency quantiles are 12.6/13.4/13.6 ms. Admission and durable publication
remain substantial costs after the executor optimization.

LuneSeal's median 4096 TPS is 97,589 for shared recipients, 93,095 for rings and
79,036 for independent pairs: about 16–20% below ordinary Fold. The proposed
benefit gate fails, so sealing stays experimental and off by default. Shared
sender and small recipient/ring cases do not construct actual seals; their mode
differences cannot be attributed to Merkle sealing. Tests separately confirm
that supported seals become ready and are actually reused with identical roots.

Release workspace suites passed 1,405 tests on Windows and 1,408 on Linux/WSL;
platform-specific ignored tests remain reported in the retained suite records.
Strict all-feature Clippy and rustdoc passed on both platforms. Additional native
checks passed three execution contract tests and two node recovery tests per OS.
Formatting, actionlint and 125 workflow-tool Python tests passed; the two TPS
accounting tests and a serializer smoke run also passed. These local checks do
not replace the CI dev/release matrix or independent-machine qualification.

Archive CSV files preserve captured UTF-8 stdout with LF newlines and match every
recorded CSV digest. The exact [measured runner](../assets/tps-qualification-2026-11-03/measured-runner.py)
is retained. After measurement, the current runner's Windows text writes were
made explicitly LF to produce byte-matching CSV directly; a smoke run checks all
resulting byte hashes. This serialization change affects no measured executable,
Rust source, transaction input or timed interval.

The goal of the world's fastest network is **not achieved by this qualification**.
The highest execution row is a different workload/boundary from Firedancer's
389,500 independent-transfer TPS, and the certified-node rows are far lower.
No same-host competitor run or complete distributed finalization benchmark was
performed. These implementations demonstrate guarded execution speedups and
correct network integration; globally unique architecture and world TPS
leadership remain unestablished.
