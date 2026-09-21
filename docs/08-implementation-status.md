<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 8. Implementation Status and Roadmap

## 8.1 Current baseline

As of 2026-09-21, this repository contains a Rust 2024 workspace with:

- canonical shared types and bounded decoder primitives;
- standard BLAKE2s-256 and strict Ed25519 backends, canonical transaction commitments, and state-aware signed admission;
- normalized access leases and dependency-preserving greedy execution-wave planning;
- compileable interfaces for cryptography, genesis, transactions, PoTB committees, BFT votes, state, runtime, execution, persistence, synchronization, P2P, RPC, configuration, keystore, telemetry, and node coordination;
- a tested in-memory mempool reference policy, genesis validation, configuration secret redaction, quorum arithmetic, decoder boundary helpers, and workspace integration invariants;
- a Rust contract SDK boundary;
- library and executable scaffolds for DNS;
- intentionally minimal `cli`, `daemon`, and `cargo-contract` entry points;
- CI, dependency-policy automation, contribution templates, project governance documents, and engineering specifications;
- a block production pipeline (`BlockProducer`) that coordinates mempool selection, deterministic execution, and storage commitment;
- a local demonstration service (`FullNodeService`) that simulates finality while coordinating execution and storage;
- a local demonstration daemon with a durable block production loop, restart recovery, validated command-line options, and RPC status tied to durable commits.

This is predominantly an **interface baseline**. It is not a functioning blockchain network, contract runtime, wallet platform, or service deployment.

## 8.2 Component status

| Area | State |
|---|---|
| Canonical codec | primitive, version-1 transaction, block-header, and receipt codecs implemented; strict lengths/flags, version/lane rejection, and transaction preflight validation tested; version-1 consensus vote/certificate envelopes implemented/tested; remaining protocol envelopes planned |
| Shared protocol types | interface baseline |
| Genesis | bounded version-1 decoding, validated BLAKE2s commitment, account/validator state materialization, CLI verification, atomic daemon activation and restart identity checks implemented; validator-key registration planned |
| Cryptography and VRF | standard BLAKE2s-256 and strict Ed25519 implemented/tested; registered validator-key verification; VRF remains unimplemented and fails closed |
| PoTB and BFT | checked committee commitments, registered Ed25519 vote authentication, bounded round-specific quorum collection, and independently verified version-1 certificates implemented/tested; durable vote signing implemented/tested; local lock/timeout rules, VRF selection, and formal work remain open |
| Keystore | single-key Ed25519 signer, bounded append-only decision journal, chain/genesis/key binding, monotonic watermark, process locking, restart and uncertain-write recovery implemented/tested; encrypted key custody, anti-rollback anchors, and daemon provisioning remain open |
| Transactions | canonical signing/ID commitments and state-aware signed validator implemented/tested; native signed payment transitions and fixed reference fees implemented/tested; version-1 envelope, inclusive expiry, signed lane/prices, and expiry eviction implemented/tested |
| Mempool | bounded in-memory reference admission and deterministic selection implemented/tested |
| State and storage | bounded Merkle state, membership and absence proofs, immutable snapshots, atomic transitions, file-backed state and whole-chain archive recovery, and authenticated snapshot exchange implemented/tested; daemon block/state restart recovery implemented/tested; native payment account transitions implemented/tested; production-scale indexing remains planned |
| Runtime and execution | signed sequential native payment executor, serial contract demonstration, and dependency-preserving greedy wave planner; lease normalization and scheduler equivalence tested; production runtime and parallel execution remain planned |
| Sync, P2P, RPC, and node | node demonstration pipeline with staged proposal execution, atomic commit, retry preservation, and canonical transaction/receipt leaves; genesis-backed native payment admission/execution and daemon RPC implemented/tested; genesis-free admission and finality remain demonstrations; explicit producer certified proposal/commit APIs and archive roundtrip tests implemented; daemon/network authenticated integration remains planned |
| Configuration | pure validation and debug redaction baseline |
| Telemetry | no-op local sink |
| Contracts | SDK interface only; no compiler target or runtime |
| DNS | service data models and placeholder binaries |
| CLI and daemon | CLI genesis verification; local daemon with file-backed block/state recovery, genesis activation, strict arguments, startup failure propagation, and durable RPC head; signed native payments and committed account/submission RPC implemented/tested; consensus remains a demonstration |

## 8.3 Removed architecture

The current design removes:

- C and C++ as first-party implementation languages;
- the C ABI as the primary module boundary;
- ALVM and its custom instruction set;
- Trocto, Regol, and Kreep contract languages;
- a general-purpose off-chain user storage/share service;
- claims that VRF is intentionally absent;
- historical implementation claims not represented by this Rust repository.

Validator-local persistence remains required and is named `storage`; it is not a user content service.

## 8.4 Planned milestones

### M1 — canonical foundations

Canonical encodings, domain tags, hashing, addresses, signatures, checked resource arithmetic, golden vectors, property tests, and fuzz targets.

The codec now rejects alternate length prefixes and non-canonical receipt flags, and validates transaction structure before allocating owned fields. Regression coverage includes golden bytes, every supported sequence length, every receipt flag, truncations, and transaction byte mutations. The standalone fuzz package includes the accepted-input re-encoding invariant for transactions, state keys, and receipts. The [version-1 transaction envelope](14-versioned-transactions.md) adds signed expiry, explicit lane, and prices; transaction encoder output changes and old archives fail closed. See [the current codec baseline](04-state-and-transactions.md#current-codec-baseline).

Standard hashing and signing backends, signed transaction IDs, address derivation, and checked resource pricing are implemented with conformance tests. These replace incompatible placeholder cryptographic outputs; see [suite and compatibility details](09-cryptographic-foundations.md). The daemon is not yet a cryptographically authenticated blockchain node.

### M2 — state and transactions

Signed envelopes, validation order, account/state commitments, immutable snapshots, proofs, diffs, sequential atomic commit, crash recovery, pruning, receipts, and snapshot exchange.

Implemented reference state commitments, membership and absence proofs, bounded versioned snapshots, atomic file-backed state publication, writer locks, recovery, verified snapshot exchange, and proposal rollback are described in [state and recovery](10-state-and-recovery.md). [Whole-chain archives](11-chain-archives.md) now persist blocks, certificates, checkpoints, and historical state atomically. Local daemon block/state restart integration is implemented with process and differential recovery tests. [Genesis activation](12-genesis-and-accounts.md) creates committed account balances/nonces and validator weights, installs a durable height-zero anchor, and validates genesis identity on restart. Recovered accounts are tested against signed admission. [Native payments](13-native-payments.md) implement sequential account transitions, fixed reference fees, atomic revalidation/publication, and daemon account/submission RPC with process restart tests. Versioned transaction policy is enforced at admission, proposal execution, and commit; expiry eviction follows successful durable publication. Durable consensus signing decisions now recover independently through the signing journal. General execution/fee policy, daemon signer integration, and production-scale indexing remain open.

### M3 — deterministic runtime

Pinned Rust contract toolchain, target selection, validator, interpreter, host ABI, resource metering, SDK, reproducible artifacts, source verification, and differential execution.

### M4 — parallel execution

Deterministic waves, Adaptive Execution Leasing, lanes, optimistic access validation, replay bounds, locality, fusion, prefetch, caches, pools, and signature batches.

### M5 — consensus

PoTB transitions and evidence, audited VRF provider, unbiased weighted sampler, partial committee rotation, producer selection, prevote/precommit state machine, certificates, durable anti-equivocation, formal models, and adversarial simulations.

The [authenticated finality layer](15-authenticated-finality.md) verifies registered keys, chain/height/committee-bound vote digests, and weighted precommit certificates. The collector retains one round, rejects duplicate nil votes, distinguishes authenticated equivocation, and never combines weights across rounds or phases. Certified producer commits authenticate finality before existing execution/storage checks, with failed-write retry and restart verification tests. The [durable signing journal](16-durable-signing.md) now reserves a chain/genesis/key-bound decision before returning an Ed25519 signature, blocks stale coordinates, and recovers after process exit. Typed vote signing maps wire phases to protected journal coordinates. The daemon still simulates finality; local vote locks and signer provisioning remain open.

### M6 — P2P and node

Authenticated encrypted transport, peer discovery, rate limits, compact blocks, finalized sync, bounded queues, pipelining, speculation, external RPC, telemetry, and finalized adaptive-capacity observations.

### M7 — ecosystem

Wallet integration and DNS registry/resolver.

### M8 — production gates

Distributed calibration, interoperability suite, long fuzz campaigns, reproducible releases, dependency audit, independent cryptography/consensus/runtime/security reviews, key ceremonies, and incident/operator runbooks.

The concise checklist is maintained in [`../ROADMAP.md`](../ROADMAP.md).

## 8.5 Required continuous gates

Every protocol change must pass formatting, Clippy with warnings denied, unit/integration/doc tests, canonical serialization compatibility, cross-platform deterministic fixtures, and documentation-link checks. Relevant changes additionally require property testing, fuzzing, recovery tests, and optimized/reference differential checks.

Unsafe Rust remains forbidden unless a dedicated reviewed exception crate is introduced. CI currently covers Linux and Windows quality checks; dependency policy and advisory workflows are configured separately.

## 8.6 Open decisions

Before production implementation, resolve:

1. PoTB scoring, admission, penalties, evidence, governance, and formal claims.
2. VRF construction and unbiased weighted sampling.
3. Rotating weighted BFT lock, unlock, timeout, and handoff rules.
4. Canonical encoding and hash suite.
5. Rust contract target and reproducible compiler policy.
6. Production state indexing and concrete durable chain database engine; the reference Merkle commitment is specified.
7. Fees, transaction ordering, anti-MEV policy, and lane borrowing.
8. Adaptive-capacity observation, manipulation resistance, and activation.
9. P2P transport, discovery, topology, identities, and denial-of-service bounds.
10. DNS naming policy and registry economics.
11. Supported platforms, compatibility lifecycle, release signing, and maintainer authority.

## 8.7 Non-negotiable correctness properties

- Finalized transaction order is unique at each height.
- A finality certificate represents voting power strictly greater than two thirds.
- Committee selection is publicly verifiable and proportional to finalized PoTB weight under the specified sampler.
- Parallel, sequential, speculative, fused, cached, AOT, JIT, SIMD, and portable paths agree.
- Adaptive capacity cannot be changed by one node's local measurements.
- Canonical state is published only after finality and execution commitments validate.
- Sync and snapshot imports remain staged until verified.
- Configuration and logs do not expose secret key material.
- Ecosystem services cannot access validator signing authority.
