// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Key types: purpose classification, opaque handles, and signing coordinates.

/// Allowed key purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPurpose {
    /// Consensus proposals and votes.
    Consensus,
    /// Peer transport authentication.
    Network,
    /// Ecosystem service identity.
    Service,
    /// End-user wallet operations.
    Wallet,
}

/// Opaque key reference. Secret bytes are never returned by this API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyHandle {
    /// Provider-specific non-secret identifier.
    pub id: String,
    /// Operation family allowed for the key.
    pub purpose: KeyPurpose,
}

/// Consensus signing coordinates protected against equivocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SigningPosition {
    /// Consensus height.
    pub height: u64,
    /// Round within the height.
    pub round: u32,
    /// Domain-separated proposal, prevote, or precommit phase byte.
    pub phase: u8,
}
