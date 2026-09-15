// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune` operator and developer command-line entry point.

#![forbid(unsafe_code)]

const HELP: &str = "AstroLune command-line interface (engineering baseline)\n\nUsage: cli [--help | --version]\n";

fn main() {
    match std::env::args().nth(1).as_deref() {
        None | Some("--help" | "-h") => print!("{HELP}"),
        Some("--version" | "-V") => println!("cli {}", env!("CARGO_PKG_VERSION")),
        Some(command) => {
            eprintln!("unsupported command in engineering baseline: {command}\n\n{HELP}");
            std::process::exit(2);
        }
    }
}
