// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Standalone `AstroLune` Pages service entry point.
//!
//! This binary serves static sites reachable through `AstroLune` DNS.
//! Pages verifies immutable asset hashes and applies strict path
//! normalization, MIME handling, and content security policy defaults.

#![forbid(unsafe_code)]

fn main() {
    println!("astrolune-pages: engineering baseline");
    println!("  features: static content, MIME detection, CSP, origin isolation");
    println!("  note: service runtime is not yet implemented");
}
