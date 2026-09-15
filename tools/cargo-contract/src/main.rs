// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Cargo subcommand entry point for deterministic Rust contracts.

#![forbid(unsafe_code)]

const HELP: &str = "\
AstroLune contract toolchain (engineering baseline)

Usage: cargo contract <command> [options]

Commands:
  build     Compile a contract to the canonical deterministic target
  validate  Verify a compiled artifact against its source and toolchain
  test      Run contract tests in the deterministic sandbox
  deploy    Submit a contract deployment transaction
  verify    Verify a deployed contract matches its published source

Options:
  --help, -h       Print this help message
  --version, -V    Print version
";

fn main() {
    let mut arguments = std::env::args().skip(1);
    let first = arguments.next();
    let command = if first.as_deref() == Some("contract") {
        arguments.next()
    } else {
        first
    };

    match command.as_deref() {
        None | Some("--help" | "-h") => print!("{HELP}"),
        Some("--version" | "-V") => println!("cargo-contract {}", env!("CARGO_PKG_VERSION")),
        Some("build") => {
            println!("Deterministic contract build (engineering baseline)");
            println!("Planned: canonical target selection, AOT compilation, metering instrumentation");
            println!("Planned: reproducible artifacts, source hash, compiler version pinning");
        }
        Some("validate") => {
            println!("Contract artifact validation (engineering baseline)");
            println!("Planned: ABI conformance, metering bounds, signature verification");
            println!("Planned: toolchain version check, source verification");
        }
        Some("test") => {
            println!("Contract sandbox testing (engineering baseline)");
            println!("Planned: deterministic host mock, resource metering, event assertions");
        }
        Some("deploy") => {
            println!("Contract deployment (engineering baseline)");
            println!("Planned: unsigned transaction construction, gas estimation");
        }
        Some("verify") => {
            println!("Source verification (engineering baseline)");
            println!("Planned: on-chain hash comparison, toolchain attestation");
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n\n{HELP}");
            std::process::exit(2);
        }
    }
}
