<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# Changelog

All notable changes to AstroLune will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will use [Semantic Versioning](https://semver.org/) until a protocol-specific compatibility policy supersedes it.

## [Unreleased]

### Fixed

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
