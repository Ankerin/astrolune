<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 8. Implementation Status and Roadmap

## 8.1 Current baseline

As of 2026-09-19, this repository contains a Rust 2024 workspace with:

- canonical shared types and bounded decoder primitives;
- compileable interfaces for cryptography, genesis, transactions, PoTB committees, BFT votes, state, runtime, execution, persistence, synchronization, P2P, RPC, configuration, keystore, telemetry, and node coordination;
- a tested in-memory mempool reference policy, genesis validation, configuration secret redaction, quorum arithmetic, decoder boundary helpers, and workspace integration invariants;
- a Rust contract SDK boundary;
- library and executable scaffolds for DNS, Proxy, Pages, and ID;
- intentionally minimal `cli`, `daemon`, and `cargo-contract` entry points;
- CI, dependency-policy automation, contribution templates, project governance documents, and engineering specifications;
- a block production pipeline (`BlockProducer`) that coordinates mempool selection, deterministic execution, and storage commitment;
- a full node service (`FullNodeService`) that wires together consensus, execution, and storage into a cohesive pipeline;
- a daemon with a real block production loop and configurable block limits.

This is predominantly an **interface baseline**. It is not a functioning blockchain network, contract runtime, wallet platform, or service deployment.

## 8.2 Component status

| Area | State |
|---|---|
| Canonical codec | cursor and exact-read/trailing-byte invariants implemented; complete protocol codecs planned |
| Shared protocol types | interface baseline |
| Genesis | structural validation baseline; encoding, hashing, and materialization planned |
| Cryptography and VRF | provider interfaces only; no production implementation |
| PoTB and BFT | type/state-machine interfaces and quorum helper; protocol implementation/formal work planned |
| Keystore | non-exporting signer and anti-equivocation interface only |
| Transactions | staged validator interface only |
| Mempool | bounded in-memory reference admission and deterministic selection implemented/tested |
| State and storage | snapshot/diff/persistence interfaces only |
| Runtime and execution | module/backend/scheduler interfaces only |
| Sync, P2P, RPC, and node | interfaces only |
| Configuration | pure validation and debug redaction baseline |
| Telemetry | no-op local sink |
| Contracts | SDK interface only; no compiler target or runtime |
| DNS, Proxy, Pages, ID | service data models and placeholder binaries |
| CLI and daemon | help/version engineering scaffolds only |

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

### M2 — state and transactions

Signed envelopes, validation order, account/state commitments, immutable snapshots, proofs, diffs, sequential atomic commit, crash recovery, pruning, receipts, and snapshot exchange.

### M3 — deterministic runtime

Pinned Rust contract toolchain, target selection, validator, interpreter, host ABI, resource metering, SDK, reproducible artifacts, source verification, and differential execution.

### M4 — parallel execution

Deterministic waves, Adaptive Execution Leasing, lanes, optimistic access validation, replay bounds, locality, fusion, prefetch, caches, pools, and signature batches.

### M5 — consensus

PoTB transitions and evidence, audited VRF provider, unbiased weighted sampler, partial committee rotation, producer selection, prevote/precommit state machine, certificates, durable anti-equivocation, formal models, and adversarial simulations.

### M6 — P2P and node

Authenticated encrypted transport, peer discovery, rate limits, compact blocks, finalized sync, bounded queues, pipelining, speculation, external RPC, telemetry, and finalized adaptive-capacity observations.

### M7 — ecosystem

Wallet integration, AstroLune ID, DNS registry/resolver, Proxy gateway, and static Pages publishing and serving.

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
6. State commitment and concrete database engine.
7. Fees, transaction ordering, anti-MEV policy, and lane borrowing.
8. Adaptive-capacity observation, manipulation resistance, and activation.
9. P2P transport, discovery, topology, identities, and denial-of-service bounds.
10. DNS naming policy and registry economics.
11. Proxy threat model and precise non-anonymity or anonymity claims.
12. Pages availability without adding a general storage/share marketplace.
13. AstroLune ID canonical messages, wallet UX, sessions, and revocation.
14. Supported platforms, compatibility lifecycle, release signing, and maintainer authority.

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
