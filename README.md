<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# AstroLune

AstroLune is a Rust-first blockchain engineering project centered on Proof of Trusted Behavior (PoTB), weighted VRF committee selection, partial committee rotation, and fast prevote/precommit BFT finality.

> **Status:** this repository is a compileable architecture and interface baseline. It is not a functioning network, has not been independently audited, and must not secure economic value.

## Design pillars

- **PoTB consensus weight:** finalized time, behavior, trust, penalties, and caps feed validator weight.
- **Verifiable committees:** weighted VRF selection with gradual committee rotation.
- **Fast finality:** proposal, prevote, and precommit with voting power strictly above two thirds.
- **Separated execution:** consensus fixes order; deterministic execution computes state transitions.
- **Parallel performance:** state leasing, execution waves, optimistic replay, lanes, batching, locality, and prefetch.
- **Deterministic Rust contracts:** restricted Rust source compiled to a versioned canonical runtime target, with interpreter/AOT/JIT parity.
- **Lean networking:** bounded binary P2P frames and compact-block reconstruction.
- **Independent ecosystem services:** DNS, Proxy, Pages, and wallet-mediated ID.

## Repository map

```text
apps/
  cli/                  operator and developer CLI
  daemon/               node daemon entry point
crates/
  codec                 canonical bounded encoding
  config                validated non-secret configuration
  consensus             PoTB committees and BFT finality
  contract-sdk          Rust contract host boundary
  crypto                hashes, signatures, and VRF interfaces
  execution             deterministic parallel scheduling
  genesis               validated chain configuration
  keystore              purpose-separated signing interfaces
  mempool               bounded admission and proposal policy
  node                  subsystem pipeline coordination
  p2p                   binary frames and compact blocks
  rpc                   external wallet/application API
  runtime               contract module and backend interfaces
  state                 snapshots, leases, and state diffs
  storage               validator-local durable persistence
  sync                  finalized block and snapshot sync
  telemetry             local-only observability
  testkit               non-production deterministic fixtures
  transaction           transaction validation boundaries
  types                 canonical shared protocol types
services/
  dns                   authenticated in-network naming
  id                    wallet authorization
  pages                 static site manifests and serving
  proxy                 internal access gateway
tests/
  integration           workspace-level conformance tests
tools/
  cargo-contract        planned contract developer workflow
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`docs/README.md`](docs/README.md) for the detailed architecture.

## Prerequisites

The repository pins Rust `1.93.1` with `rustfmt` and Clippy through [`rust-toolchain.toml`](rust-toolchain.toml). Install Rust with [rustup](https://rustup.rs/); entering the repository selects the pinned toolchain.

Cryptographic foundations use pinned BLAKE2s and Ed25519 backends; dependency versions are recorded in `Cargo.lock`. Reference state and [whole-chain archive persistence](docs/11-chain-archives.md) use standard-library file I/O and locks. The daemon still uses memory storage.

## Validate the workspace

```sh
cargo metadata --no-deps --format-version 1
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

On PowerShell, set rustdoc flags with:

```powershell
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --workspace --no-deps
```

Try the intentionally minimal entry points:

```sh
cargo run -p cli -- --help
cargo run -p daemon -- --help
cargo run -p cargo-contract -- --help
```

## Data flow

```text
binary P2P ingress
  -> canonical decode and transaction validation
  -> bounded mempool and compact proposal reconstruction
  -> PoTB committee proposal/prevote/precommit ordering
  -> immutable state snapshot
  -> deterministic parallel execution and conflict replay
  -> receipt, resource, and state commitment verification
  -> atomic validator-local commit
  -> external RPC and ecosystem notifications
```

Prediction, telemetry, cache state, worker count, SIMD availability, and JIT availability may change latency only. They cannot change canonical results.

## Non-goals

- The baseline does not claim production cryptography, consensus safety, anonymity, or benchmark figures.
- AstroLune does not include a general-purpose user storage or file-sharing marketplace. `storage` is validator-local blockchain persistence.
- External RPC does not carry internal consensus traffic.
- Arbitrary native Rust binaries are not deployable contracts.
- Ecosystem services do not receive validator signing authority.

## Project documents

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Governance](GOVERNANCE.md)
- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Release process](RELEASING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## License

AstroLune is available under the [MIT License](LICENSE).
