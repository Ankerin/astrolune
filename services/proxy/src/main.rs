// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Standalone `AstroLune` Proxy service entry point.
//!
//! This binary starts the access proxy gateway that routes bounded
//! requests to Pages or application endpoints after DNS resolution.

#![forbid(unsafe_code)]

fn main() {
    println!("astrolune-proxy: engineering baseline");
    println!("  features: request routing, bounds enforcement, service handlers");
    println!("  note: service runtime is not yet implemented");
}
