<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# AstroLune Engineering Documentation

These documents define the Rust-first engineering direction for AstroLune. They replace the earlier C/C++ and custom contract-language design. Unless a feature is explicitly marked **implemented**, it is a target or compileable interface baseline rather than an audited claim.

For a concise source-tree map, read [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

## Reading order

| Document | Subject |
|---|---|
| [00-overview.md](00-overview.md) | goals, scope, principles, terminology |
| [01-consensus-potb.md](01-consensus-potb.md) | PoTB, weighted VRF committees, rotation, BFT finality |
| [02-architecture.md](02-architecture.md) | Rust workspace, node pipeline, P2P, adaptive capacity |
| [03-vm-and-gas.md](03-vm-and-gas.md) | deterministic Rust runtime, AOT/JIT, lanes, metering |
| [04-state-and-transactions.md](04-state-and-transactions.md) | transactions, leasing, parallel scheduling, snapshots, state commit |
| [05-contract-languages.md](05-contract-languages.md) | Rust smart-contract model and SDK boundary |
| [06-deferred-services.md](06-deferred-services.md) | AstroLune DNS, Proxy, Pages, and ID |
| [07-validator-requirements.md](07-validator-requirements.md) | validator behavior and preliminary requirements |
| [08-implementation-status.md](08-implementation-status.md) | baseline, roadmap, gates, and open risks |
| [09-cryptographic-foundations.md](09-cryptographic-foundations.md) | implemented hash/signature suite, signed admission, and compatibility |

Legacy-shaped filenames such as `03-vm-and-gas.md`, `05-contract-languages.md`, and `06-deferred-services.md` are retained temporarily to preserve links. Their contents describe the current Rust architecture.

## Status vocabulary

- **planned** — documented target without an interface;
- **interface baseline** — compileable types and traits, no operational implementation;
- **implemented** — concrete behavior exists;
- **tested** — positive and negative behavior is automated;
- **benchmarked** — reproducible measurements exist;
- **audited** — independent review completed and findings addressed;
- **production-ready** — supported release and operational gates completed.

## Normative language

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express intended protocol requirements. Normative consensus behavior eventually belongs in versioned specifications and test vectors; these engineering documents establish initial boundaries.

## Explicit scope decisions

- All first-party implementation is Rust.
- PoTB remains the primary consensus-weight model.
- Weighted VRF selection and partial committee rotation are required.
- Finality uses prevote/precommit and voting power strictly greater than two thirds.
- Consensus orders transactions; execution independently verifies state transitions.
- Contracts use a deterministic Rust subset; custom languages and ALVM are removed.
- AstroLune DNS, Proxy, Pages, and wallet authorization through AstroLune ID are ecosystem services.
- General-purpose user storage or file sharing is outside scope; validator-local chain persistence remains required.

## License

MIT, copyright AstroLune contributors, 2026.
