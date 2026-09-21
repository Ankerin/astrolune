// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Standalone `AstroLune` DNS service entry point.
//!
//! This binary starts the DNS resolver service that maps normalized
//! in-network names to wallet addresses or application service
//! records. The resolver verifies finalized registry state and proofs.

#![forbid(unsafe_code)]

fn main() {
    println!("astrolune-dns: engineering baseline");
    println!("  features: name normalization, reserved-name policy, lease/renewal");
    println!("  note: service runtime is not yet implemented");
}
