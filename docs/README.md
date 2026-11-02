<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

# AstroLune Engineering Documentation

These documents specify AstroLune protocol requirements, implemented behavior, operational procedures and qualification evidence. Documentation is grouped by topic; document numbers remain stable. The [implementation status](overview/08-implementation-status.md) records the current grade and open work for each area.

For the source-tree map, read [ARCHITECTURE.md](../ARCHITECTURE.md). The [numbered catalog](catalog.md) lists all 65 documents in their original numeric order.

## Topics

| Section | Contents |
| --- | --- |
| [Project overview](overview/README.md) | Project scope, architecture, implementation status and release boundaries. |
| [Contract languages](languages/README.md) | Trocto syntax, language and metering profiles, state capabilities, LLVM tooling and native execution. |
| [Smart contracts](contracts/README.md) | Contract execution, metering, signed deployment and calls, SDK boundaries and reproducible packages. |
| [Consensus and PoTB](consensus/README.md) | Weighted committees, BFT finality, VRF rotation, evidence, governance and consensus models. |
| [Network and nodes](network/README.md) | Validator and observer networking, authenticated transport, compact propagation and admission control. |
| [State, transactions and storage](state/README.md) | Genesis, payments, transaction formats, state commitments, certified queries, persistence and retention. |
| [Node operations](operations/README.md) | Validator requirements, network setup, monitoring, recovery and calibration. |
| [Security and key custody](security/README.md) | Cryptographic foundations, durable signing, protected journals, dependency review and release authority. |
| [Development and compatibility](development/README.md) | Protocol qualification, toolchains, release verification, compatibility and public interface conventions. |
| [Wallets, RPC and ecosystem](ecosystem/README.md) | Wallet/RPC clients, explorer integration, DNS registry and proof-verifying resolution. |
| [Performance and architecture research](performance/README.md) | Measurement methods, architecture proposals, guarded execution and reproducible throughput evidence. |
| [Evidence archives](assets/) | Retained measurements, raw logs, qualification records and shared images. |

## Reading order

- **Contract authors:** [Trocto](languages/trocto/README.md) → [smart contracts](contracts/README.md) → [wallets and RPC](ecosystem/README.md).
- **Node operators:** [network and nodes](network/README.md) → [operations](operations/README.md) → [key custody](security/README.md).
- **Protocol developers:** [project overview](overview/README.md) → [consensus](consensus/README.md) → [state and transactions](state/README.md) → [development and compatibility](development/README.md).
- **Performance work:** [measurement and architecture research](performance/README.md), with each report's workload, machine and completion boundary.

Numbered filenames preserve document identities, including historical names. Canonical links now use topic directories. Evidence archives remain under `docs/assets`; their retained contents are unchanged.

## Status vocabulary

Every area in [the implementation status](overview/08-implementation-status.md) carries one grade from this ladder, recording how far that area has been carried:

- **planned** — specified in these documents, with no Rust interface yet;
- **interface baseline** — compileable types and traits fix the boundary before behavior lands;
- **implemented** — concrete behavior exists;
- **tested** — positive and negative behavior is automated;
- **benchmarked** — reproducible measurements exist for a stated machine and revision;
- **audited** — an independent external review has completed and its findings are addressed;
- **production-ready** — release gates, operations and a supported-version policy are complete.

## Normative language

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express protocol requirements. These documents are the current normative source; wire-level behavior is additionally pinned by explicit profile versions and the frozen binary fixtures under `tests/integration/fixtures`.

## Explicit scope decisions

- Node, compiler, and runtime orchestration are implemented in Rust; the native LLVM worker uses a fixed generated host harness.
- PoTB remains the primary consensus-weight model.
- Weighted VRF selection and partial committee rotation are required.
- Finality uses prevote/precommit and voting power strictly greater than two thirds.
- Consensus orders transactions; execution independently verifies state transitions.
- Trocto (`.tc`) is the contract-language development direction; native LLVM qualification and a new deployment profile precede validator activation.
- AstroLune DNS is an ecosystem service.
- General-purpose user storage or file sharing is outside scope; validator-local chain persistence remains required.

## License

MIT, copyright AstroLune contributors, 2026.
