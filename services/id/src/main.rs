// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Standalone `AstroLune` ID service entry point.
//!
//! This binary runs the wallet authorization protocol that lets
//! applications request wallet authorization without receiving
//! the wallet secret key. Supports session management and revocation.

#![forbid(unsafe_code)]

fn main() {
    println!("astrolune-id: engineering baseline");
    println!("  features: challenge-response auth, session management, revocation");
    println!("  note: service runtime is not yet implemented");
}
