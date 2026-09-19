// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Standalone `AstroLune` Isolation service entry point.
//!
//! This binary provides shared service isolation primitives including
//! rate limiting and service-to-service authentication.

#![forbid(unsafe_code)]

fn main() {
    println!("astrolune-isolation: engineering baseline");
    println!("  features: rate limiting, service authentication, identity management");
    println!("  note: service runtime is not yet implemented");
}
