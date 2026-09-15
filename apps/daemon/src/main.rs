// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune` node daemon entry point.

#![forbid(unsafe_code)]

const HELP: &str = "AstroLune node daemon (engineering baseline)\n\nUsage: daemon [--help | --version]\n\nThe network runtime is not implemented.\n";

fn main() {
    match std::env::args().nth(1).as_deref() {
        None | Some("--help" | "-h") => print!("{HELP}"),
        Some("--version" | "-V") => println!("daemon {}", env!("CARGO_PKG_VERSION")),
        Some(argument) => {
            eprintln!("unsupported argument in engineering baseline: {argument}\n\n{HELP}");
            std::process::exit(2);
        }
    }
}
