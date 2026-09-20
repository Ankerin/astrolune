<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# Changelog

All notable changes to AstroLune will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases will use [Semantic Versioning](https://semver.org/) until a protocol-specific compatibility policy supersedes it.

## [Unreleased]

### Fixed

- Replace the custom hash and forgeable signature placeholders with standard BLAKE2s-256 and strict Ed25519; reject unknown validator keys and unsupported VRF proofs.
- Bind transaction IDs to every canonical field and signature, and use consistent transaction IDs and cryptographic Merkle roots in block assembly.
- Check exact transaction sizes, resource-cost overflow, and nonce exhaustion; preserve sender nonce and admission sequence when mempool insertion fails.
- Reject non-minimal length prefixes, reserved length markers, and non-canonical receipt booleans without changing canonical encoder output.
- Validate complete transaction structure before allocating access lists and payloads; enforce state-key limits before reading key content.
- Make the codec fuzz package independently resolvable and add exact-byte re-encoding checks for transactions, state keys, and execution receipts.

### Added

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
