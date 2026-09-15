// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Purpose-separated non-exporting signer and anti-equivocation boundaries.

#![forbid(unsafe_code)]

use types::{Hash256, ValidatorId};

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningPosition {
    /// Consensus height.
    pub height: u64,
    /// Round within the height.
    pub round: u32,
    /// Domain-separated proposal, prevote, or precommit phase byte.
    pub phase: u8,
}

/// Non-exporting signature provider.
pub trait Signer: Send + Sync {
    /// Returns the public validator identity for a handle.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError`] for an unknown handle or wrong key purpose.
    fn validator_id(&self, handle: &KeyHandle) -> Result<ValidatorId, KeystoreError>;

    /// Persists the decision and signs only when it cannot equivocate.
    ///
    /// # Errors
    ///
    /// Returns [`KeystoreError::ConflictingSign`] if the position was previously
    /// signed for a different message, or another error if durable signing fails.
    fn sign_consensus(
        &mut self,
        handle: &KeyHandle,
        position: SigningPosition,
        message: Hash256,
    ) -> Result<[u8; 64], KeystoreError>;
}

/// Signer and key isolation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeystoreError {
    /// Key handle does not exist.
    UnknownKey,
    /// Requested operation does not match the key purpose.
    WrongPurpose,
    /// Position already contains a different signing decision.
    ConflictingSign,
    /// Durable decision journal failed before signing.
    JournalFailure,
    /// Signing provider rejected the operation.
    ProviderFailure,
}
