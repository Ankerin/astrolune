<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# Changelog

All notable changes to AstroLune will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will use [Semantic Versioning](https://semver.org/) until a protocol-specific compatibility policy supersedes it.

## [Unreleased]

### Fixed

- Compute strict two-thirds quorum without saturation for the full `u128` validator-weight range.
- Remove the workspace member reference to the deleted isolation service.
- Bound and preflight genesis lists before allocation; reject unsupported versions, invalid identities/order/committee parameters, and aggregate validator-weight overflow before hashing or materialization.
- Reject malformed daemon arguments and fail startup on listener errors; expose only durably committed heads and bound the service observation history.
- Replace XOR block IDs and receipt commitments with canonical domain-separated BLAKE2s; reject child headers after height exhaustion.
- Authenticate the genesis header contents and first-child height when checking synchronized ancestry.
- Verify stored transaction bodies against header commitments before publication, and enforce the transaction decoder's access-list count limit.
- Replace truncated XOR state/diff commitments with domain-separated BLAKE2s commitments and count-bound Merkle state roots.
- Stage state before checking finalized roots; preserve state, checkpoints, and pending transactions on rejected proposals or failed commits.
- Propagate node commit failures, enforce parent linkage and checked heights, and preserve the latest checkpoint during pruning.

- Replace the custom hash and forgeable signature placeholders with standard BLAKE2s-256 and strict Ed25519; reject unknown validator keys and unsupported VRF proofs.
- Bind transaction IDs to every canonical field and signature, and use consistent transaction IDs and cryptographic Merkle roots in block assembly.
- Check exact transaction sizes, resource-cost overflow, and nonce exhaustion; preserve sender nonce and admission sequence when mempool insertion fails.
- Reject non-minimal length prefixes, reserved length markers, and non-canonical receipt booleans without changing canonical encoder output.
- Validate complete transaction structure before allocating access lists and payloads; enforce state-key limits before reading key content.
- Make the codec fuzz package independently resolvable and add exact-byte re-encoding checks for transactions, state keys, and execution receipts.

### Added

- Daemon `--genesis PATH` activation with atomic height-zero state installation, genesis identity checks on restart, configured chain/capacity and demonstration committee, plus recovery/failure conformance tests.
- Deterministic genesis account/validator materialization, canonical shared account records, authenticated snapshot reads, independent commitment vectors, recovery/admission tests, and a genesis decoder fuzz target.
- Read-only `cli genesis <file>` verification reporting the genesis hash and initial state root.
- Authenticated state absence proofs with adjacent Merkle witnesses, bounded versioned transport, immutable snapshot/file recovery coverage, and a decoder fuzz target.
- File-backed node service and daemon recovery of block height, parent hash, and execution state; strict data-directory/listener options and recovery-only startup.
- Daemon RPC status follows recovered and newly committed checkpoints; unwired account and transaction operations return unavailable.
- Process restart/failure tests and differential state/block checks across repeated node service restarts.
- Bounded file-backed whole-chain archives with atomic commit/import/pruning, retained historical snapshots, writer locks, corruption checks, and process-recovery tests.
- Independent block/receipt hash fixtures and archive format/compatibility documentation in `docs/11-chain-archives.md`.
- Immutable shared state snapshots, bounded transitions, and strict Merkle membership proofs.
- Versioned state files with synchronized atomic replacement, process-held writer locks, corruption detection, and recovery tests.
- Bounded historical snapshot export and staged import against an independently authenticated checkpoint, plus a snapshot decoder fuzz target.
- State-format compatibility specification in `docs/10-state-and-recovery.md`; old flat files and XOR roots require explicit migration.
- State-aware signed transaction admission with explicit resource prices, address/public-key binding, and ordered validation stages.
- Normalized access leases and deterministic greedy execution waves that preserve conflict and sender order, with serial-equivalence tests.
- Standard cryptographic vectors and signed admission-to-mempool integration tests.
- Rust 2024 workspace with protocol, execution, state, networking, node, service, and tooling boundaries.
- PoTB weighted committee and fast BFT finality interfaces.
- Deterministic Rust contract SDK and runtime architecture.
- AstroLune DNS, Proxy, Pages, and ID service baselines.
- Validator-local persistence, finalized sync, configuration, keystore, telemetry, RPC, mempool, genesis, and canonical codec crates.
- Workspace integration tests, CI, dependency checks, contribution templates, and project documentation.

### Removed

- C/C++ implementation architecture and primary C ABI.
- ALVM, Trocto, Regol, and Kreep language architecture.
- General-purpose user storage/share service scope.

[Unreleased]: https://github.com/Ankerin/astrolune
