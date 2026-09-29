<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 39. Toolchain and release qualification

The native workspace and restricted Rust contract profile pin Rust 1.98.1.
`rust-toolchain.toml` installs Clippy, rustfmt, rust-analyzer and the
`wasm32-unknown-unknown` target. On Windows, `tools/enter-dev.ps1` puts the
rustup proxies ahead of older standalone Rust installations in the current shell.

The 2026-09-29/30 dependency upgrade keeps the canonical wire formats and existing
wallet-v1 format. The failing CI logs used `AeadInPlace` methods removed by
chacha20poly1305 0.11; vaults now use `AeadInOut` with checked fixed-size nonce/tag
conversion. A committed vault produced with Argon2 0.5.3 and
chacha20poly1305 0.10.1 checks backward compatibility. The seed is a public RFC
8032 test vector, not operator material. Source packages have an explicitly new
compiler-profile commitment; [old bundle handling](34-contract-source-packages.md).

All direct Cargo dependencies were checked against the crates.io stable releases;
both workspace and standalone fuzz lock resolutions were refreshed. Upstream
transitive requirements remain authoritative: forcing unrelated major versions
through a dependency's API does not establish compatibility. An OSV query over
all 132 registry packages in the workspace lockfile returned no known advisories
on 2026-09-30. This is a database check, not an independent implementation audit.

## Native artifacts

```text
python -B .github/scripts/verify-native-build.py x86_64-pc-windows-msvc --binaries-output target/verified-native
python -B .github/scripts/package-build.py x86_64-pc-windows-msvc --binaries target/verified-native --revision <full-commit-hash>
python -B -m unittest discover -s .github/scripts -p 'test_*.py' -v
```

The verifier builds the complete release workspace twice in separate fresh
directories, disables incremental compilation, remaps workspace/build paths,
strips debug information and enables the MSVC deterministic-link option. It
compares SHA-256 hashes of `cli`, `daemon`, `cargo-contract` and `dns`. An optional
output directory receives binaries only after all comparisons match.
`target/native-reproducibility.json` records compiler identity and binary hashes.
Linux uses the same command with `x86_64-unknown-linux-gnu`.

The archive builder includes those four binaries, documentation and banner,
license, README, lockfile and compiler manifest. Files have a sorted order,
fixed modes, zero ownership and an explicit timestamp (`SOURCE_DATE_EPOCH`,
default zero). The gzip header contains no host filename or current time.
`BUILD.json` records build identity and every payload's SHA-256; `SHA256SUMS`
commits the complete archive. Regression tests change filesystem timestamps and
permissions, check exact equality, inspect all hashes and reject incomplete
builds. These scripts perform no upload or signing.

CI's Linux/Windows build matrix now runs this two-build gate and packages its
verified output. Release-profile tests also invoke all four real Rust-to-WASM
SDK/package checks instead of leaving them permanently ignored.

## Local evidence

On Windows with Rust 1.98.1 the upgrade passed workspace tests in debug and
release, strict Clippy and rustdoc, formatting, all four explicit Rust-to-WASM
tests, standalone fuzz-target compilation, the 100,000-input extension mutation
campaign, the legacy vault fixture and archive reproducibility tests. Two fresh
native builds produced equal hashes for all four executables. Both repositories'
workflow files passed actionlint 1.7.12.

The companion web workspace uses Node 26.10.0, npm 12.1.0, Turbo 2.11.5 and
Next.js 16.3.7. TypeScript 7.0.2 supplies the native CLI; the supported TypeScript
6.0.2 API package remains available to Next.js/MDX/ESLint. Direct dependency
checks report no outdated packages, and npm audit reports no known vulnerabilities.
Content checks, nine RPC tests, type checking, lint, all three production builds
and 28 desktop/mobile browser scenarios passed. Browser tests used a newly
provisioned four-validator TLS devnet plus observer and a real finalized payment.

No hosted CI runs were started. Linux execution and reproducibility on independent
machines remain to be observed; equal builds on one Windows host establish only
the measured scope. Live rotating consensus, active PoTB, governance, physical
retention and alternate runtime qualification retain their own ROADMAP entries.
