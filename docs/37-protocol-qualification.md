<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 37. Protocol qualification tools

The workspace's focused tests retain canonical transaction, receipt, state,
consensus and cryptographic fixtures. Version compatibility is checked through
strict decoding and exact accepted-input re-encoding. Add a new fixture when
changing a protocol domain, canonical field or activation rule; do not silently
update an expected hash merely to make tests pass.

The shared extension oracle in `tests/integration/tests/support/extensions.rs`
covers VRF envelopes and verification, committee states, role-paired contributions,
complete batches, certified handoffs, state value proofs, certified state and
receipt proofs, stored effects, scoped discovery envelopes, DNS registry calls
and bounded WASM validation/execution. The same oracle runs in a stable-toolchain
mutation test and the `decode_extensions` libFuzzer target. Accepted bytes must
re-encode identically. Accepted WASM modules execute twice with the same explicit
input/context and bounded fuel, and must return identical outputs or errors.

```text
cargo test -p integration --test mutations
cargo test -p integration --test mutations extended_extension_mutations -- --ignored
cargo check --manifest-path crates/codec/fuzz/Cargo.toml
```

The ordinary test performs 3,000 deterministic mutations; the extended test
performs 100,000. Seeds include valid proofs, an effects bundle, a DNS registration,
a discovery envelope, a returning WASM module and a fuel-exhausting loop. Four
additional valid rotation envelopes exercise the new handoff boundaries. Mutations
include byte substitutions, truncations, insertion, deletion and maximum-length
field patterns. The fixed PRNG seed makes failures reproducible across platforms.

All standalone libFuzzer targets compile locally. Running coverage-guided,
sanitizer-enabled campaigns additionally needs a suitable nightly/cargo-fuzz
installation. From `crates/codec`, the new target is selected with
`cargo +nightly fuzz run decode_extensions`. Set campaign time, maximum input
length and RSS/timeout bounds for the selected environment; retain and minimize
any crashing corpus. Existing transaction, genesis, consensus, network and state
fuzz targets remain separate entry points.

On 2026-09-28 the Windows Rust 1.93.1 build passed the 100,000-input deterministic
extension campaign, workspace tests, Clippy with warnings denied, rustdoc, native
and wasm32 SDK checks, and all four explicitly invoked real Rust-to-WASM tool
tests. These are local checks. Long coverage-guided campaigns, Linux qualification
of these changes, independent alternate execution backends and reproducible native
release binaries remain separate ROADMAP work; a mutation smoke test does not
establish those properties.

On 2026-09-29 the expanded 13-seed campaign, including the four new rotation
envelopes, passed 100,000 mutations. The same change passed workspace tests,
Clippy with warnings denied, rustdoc and standalone fuzz-target compilation.
