<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# AstroLune Roadmap

Dates are intentionally absent until maintainers publish resourced release targets. Milestones describe dependency order, not promises.

## Baseline — in progress

- [x] Rust 2024 workspace and strict lint policy.
- [x] Core protocol, execution, storage, network, service, and tooling crate boundaries.
- [x] Repository documentation, CI, dependency policy, and contribution templates.
- [x] Initial pure invariant and integration tests.
- [ ] Review and stabilize public interface naming before implementation begins.

## M1 — canonical foundations

Canonical encodings, protocol domains, hashes, addresses, signatures, checked resource arithmetic, golden vectors, property tests, and decoder fuzzing.

- [x] Strict primitive/current-transaction codecs and canonical-byte regression tests.
- [x] Standard BLAKE2s-256, strict Ed25519, transaction signing/ID domains, and address derivation.
- [x] Checked resource pricing and cryptographic conformance vectors.
- [ ] Complete versioned protocol envelopes and replace remaining placeholder commitments.
- [ ] Long fuzz campaigns, dependency/security review, and cross-platform suite qualification.

## M2 — transactions and state

Signed envelopes, validation order, account/state commitments, immutable snapshots, proofs, state diffs, atomic commit, recovery, pruning, and snapshot exchange.

Current progress: signed admission validates existing transaction fields against an account view. Finalized account overlays, the complete versioned envelope, and production persistence remain open.

## M3 — deterministic Rust contracts

Pinned contract toolchain, canonical target selection, validator, interpreter, host ABI, metering, SDK, reproducible artifacts, source verification, and differential backends.

## M4 — parallel execution

Access leasing, execution waves, multiple lanes, optimistic validation, deterministic conflict replay, locality, fusion, caches, prefetch, object pools, and signature batches.

## M5 — PoTB and finality

PoTB state transitions and evidence, audited VRF provider, weighted sampler, partial rotation, producer selection, prevote/precommit state machine, certificates, anti-equivocation journal, formal models, and adversarial simulations.

## M6 — node and networking

Authenticated encrypted transport, peer discovery, rate limiting, compact blocks, finalized sync, bounded queues, stage pipelining, speculative work, external RPC, and adaptive-capacity governance.

## M7 — ecosystem

Wallet integration, AstroLune ID, DNS registry and resolver, access Proxy, and static Pages publishing and serving.

## M8 — public testnet and production gates

Distributed calibration, interoperability, long fuzz campaigns, reproducible releases, dependency review, external cryptography/consensus/runtime/security audits, key ceremonies, monitoring, incident response, and operator runbooks.

Detailed status and unresolved decisions are tracked in [`docs/08-implementation-status.md`](docs/08-implementation-status.md).
