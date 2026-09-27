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
- [x] Bounded version-1 genesis, validated commitments, initial account/validator state, and CLI verification.
- [x] Atomic daemon genesis activation, restart identity checks, and preserved initial account state.
- [x] Version-1 signed transactions with expiry, explicit lanes, signed prices, and strict decoding.
- [x] Version-1 signed votes and finality certificates, checked committee commitments, and independent Ed25519 quorum verification.
- [x] Versioned reference-network envelopes and opt-in certified daemon finality.
- [x] Canonical RFC 9381 VRF proofs, role-bound context, RFC vectors and malformed-proof rejection.
- [ ] Complete production protocol envelopes and compatibility qualification.
- [ ] Long fuzz campaigns, dependency/security review, and cross-platform suite qualification.

## M2 — transactions and state

Signed envelopes, validation order, account/state commitments, immutable snapshots, proofs, state diffs, atomic commit, recovery, pruning, and snapshot exchange.

Current progress: signed admission validates existing transaction fields against an account view. Merkle state commitments, membership and absence proofs, immutable snapshots, bounded transitions, atomic state/whole-chain archive recovery, and verified snapshot exchange are implemented with rollback tests. Proposal execution stays private until successful commit. Sequential signed payment overlays, balance/nonce transitions, fixed reference fees, execution revalidation, and daemon account/submission RPC are implemented. The [versioned transaction envelope](docs/14-versioned-transactions.md), expiry enforcement, and post-commit expiry eviction are implemented. [Append-only block/delta logs](docs/22-append-only-chain-storage.md) now provide durable publication, disk history reads, linear replay and legacy compatibility for new network directories. [Protected signing-journal rollover](docs/23-signing-journal-rollover.md) now continues after the former decision cap with constant file size and lock-preserving recovery. Production fee governance, state indexing, retention and rollback-resistant key custody remain open. Local daemon block/state restart integration is implemented; daemon signing-state integration and independent authentication of recovered history are implemented in the certified reference-network profile. See [state and recovery](docs/10-state-and-recovery.md) and [chain archives](docs/11-chain-archives.md).

## M3 — deterministic Rust contracts

Pinned contract toolchain, canonical target selection, validator, interpreter, host ABI, metering, SDK, reproducible artifacts, source verification, and differential backends.

- [x] Integer-only WebAssembly ABI v2 validator and interpreter with bounded memory, fuel, state access and staged writes/events.
- [x] Pinned Rust 1.93.1 standalone contract builds, repeated-byte comparison, artifact validation, sandbox execution and code-hash verification CLI.
- [x] Signed deployment/call transactions, nonce/fee transitions, explicit genesis activation and certified restart/catch-up tests.
- [x] Allocation-free Rust SDK bindings, bundled builds and real wasm32 host-call tests.
- [x] Restricted Cargo package/source manifests and offline published-source verification.
- [ ] Qualified alternate backends and contract fuzz campaigns.

Implemented behavior and the remaining activation boundary are specified in [document 29](docs/29-parallel-payments-and-wasm.md).

## M4 — parallel execution

Access leasing, execution waves, multiple lanes, optimistic validation, deterministic conflict replay, locality, fusion, caches, prefetch, object pools, and signature batches.

- [x] Parallel signed payment waves with checked actual access, private overlays and serial error replay.
- [x] Node verification/replay integration and serial/parallel differential tests across worker counts.
- [x] Mixed contract/payment waves, aggregate capacity enforcement and deterministic serial replay.
- [ ] Consensus-governed system lane and protocol capacity allocation.
- [ ] Measured locality/fusion/cache/prefetch/pool optimizations and signature batching with equivalence tests.

## M5 — PoTB and finality

PoTB state transitions and evidence, audited VRF provider, weighted sampler, partial rotation, producer selection, prevote/precommit state machine, certificates, anti-equivocation journal, formal models, and adversarial simulations.

- [x] Registered-key ECVRF proof generation/verification and offline operator commands.
- [x] Complete-roster weighted sampling without modulo bias, partial-rotation computation and producer-role sampling.
- [ ] Finalized VRF collection/availability, parent randomness and authenticated committee handoff in the daemon.
- [ ] Canonical evidence inclusion, active PoTB weights and admission transitions.
- [ ] Rotating-consensus adversarial simulations, formal safety/liveness and independent provider review.

The [VRF and sampler specification](docs/28-vrf-and-weighted-selection.md) distinguishes implemented selection from daemon activation.

Current progress: authenticated fixed-height vote collection separates rounds/phases/blocks, rejects equivocation and replays, and emits bounded canonical certificates. The producer can verify a trusted committee and certificate before atomic execution/state publication. [Protocol details](docs/15-authenticated-finality.md). [Durable signing](docs/16-durable-signing.md), monotonic decision recovery, process locking, and typed vote signing are implemented/tested. [Local BFT voting](docs/17-local-bft-voting.md), verified prevote proofs, timeout transitions, and atomic version-2 vote/lock recovery are implemented/tested, including payment execution and certified archive recovery. [Signed proposals and a reference round-robin participant](docs/18-signed-proposals-and-participants.md) now coordinate authenticated proposal signing, execution, vote collection, timeout events, and atomic publication. [Certified reference networking](docs/19-reference-network.md) now adds daemon integration, monotonic timers, persisted available values, explicit provisioning, and certified catch-up. Verified weighted VRF selection is implemented. Daemon VRF activation, committee handoff, formal distributed liveness, and production network qualification remain open.

PoTB progress: [double-vote evidence and a policy workbench](docs/25-potb-evidence.md)
now verify offences, retain durable bounded proofs and evaluate capped integer
scores over finalized history. Canonical evidence inclusion, active weight
transitions, admission, VRF collection/activation and committee handoff are still required.

## M6 — node and networking

Authenticated encrypted transport, peer discovery, rate limiting, compact blocks, finalized sync, bounded queues, stage pipelining, speculative work, external RPC, and adaptive-capacity governance.

Current progress: [certified reference networking](docs/19-reference-network.md) connects independent daemon processes with fixed genesis membership, signed proposals/votes, step timers, payment gossip, bounded mutually authenticated TLS 1.3 exchanges, protected journals, durable available-value recovery, and sequential certified catch-up. Local devnet generation and explicit signer provisioning are implemented. Real process tests cover quorum operation, RPC payments, restart, and late join. [TLS identity validation and provisioning](docs/20-authenticated-transport.md) are implemented with independent transport keys and deadline tests. [Non-voting full nodes](docs/21-observer-nodes.md) now independently authenticate history, execute imported blocks, relay payments, serve RPC, and recover without signing authority. Discovery, public-network hardening, production storage, and rotating consensus remain open.

## M7 — ecosystem

Wallet integration and DNS registry and resolver.

Current progress: the [native-payment CLI wallet](docs/24-wallet-and-rpc-client.md)
derives real public identities, signs payments offline to non-overwritable files,
checks signatures and policy, reads finalized accounts/status, and submits saved
transactions with explicit ambiguous-outcome handling. The typed RPC client has
bounded frames, strict response checks and whole-call deadlines. Encrypted wallet custody is implemented with fixed-cost Argon2id and authenticated encryption; see [SDK and vaults](docs/31-rust-sdk-and-wallet-vaults.md). Certified state membership/absence queries and the on-chain DNS registry with an authenticated resolver are implemented; see [state proofs](docs/32-certified-state-proofs.md) and [DNS](docs/33-authenticated-name-registry.md). Receipt queries and transaction finality waiting remain open.

## M8 — public testnet and production gates

Distributed calibration, interoperability, long fuzz campaigns, reproducible releases, dependency review, external cryptography/consensus/runtime/security audits, key ceremonies, monitoring, incident response, and operator runbooks.

Detailed status and unresolved decisions are tracked in [`docs/08-implementation-status.md`](docs/08-implementation-status.md).

## Remaining software for a closed network

Private membership does not remove the following unimplemented software work.
External audits, public-testnet calibration and key ceremonies are separate release activities.

- [ ] Activate PoTB/VRF and committee transitions, including restart, unavailable-proof and catch-up behavior.
- [x] Connect signed deploy/call transactions to the WebAssembly runtime.
- [x] Complete the Rust SDK host adapter.
- [x] Complete bounded source-package tooling and exact artifact reconstruction.
- [ ] Complete mixed-lane execution, capacity/fee governance and deterministic optimization qualification.
- [ ] Add state/transaction indexing and bounded retention with authenticated recovery.
- [x] Add encrypted wallet custody, OS-generated wallet keys and direct vault signing.
- [x] Add certified state membership/absence proofs and offline verification.
- [ ] Add receipt queries and transaction finality waiting.
- [x] Implement the authenticated on-chain DNS registry and operational resolver.
- [ ] Complete peer discovery/session management, operational telemetry and operator recovery tooling.
- [ ] Complete protocol compatibility fixtures, fuzzing, platform and reproducible-release qualification.
