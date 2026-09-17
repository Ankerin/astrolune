// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Signer and key isolation failure types.

use std::fmt;

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

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey => write!(f, "unknown key"),
            Self::WrongPurpose => write!(f, "wrong purpose"),
            Self::ConflictingSign => write!(f, "conflicting sign"),
            Self::JournalFailure => write!(f, "journal failure"),
            Self::ProviderFailure => write!(f, "provider failure"),
        }
    }
}

impl std::error::Error for KeystoreError {}
