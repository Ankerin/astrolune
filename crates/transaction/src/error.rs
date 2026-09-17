// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Transaction validation error types.

use std::fmt;

/// Pre-execution validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionError {
    /// Encoding, shape, or size is invalid.
    InvalidEnvelope,
    /// Transaction targets a different chain.
    WrongChain,
    /// Transaction is no longer valid at the next height.
    Expired,
    /// Sender nonce is not the exact expected value.
    InvalidNonce,
    /// Declared limits or available balance are insufficient.
    InsufficientResources,
    /// Signature verification failed.
    InvalidSignature,
    /// Payload cannot be assigned to a supported lane.
    UnsupportedPayload,
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelope => write!(f, "invalid transaction envelope"),
            Self::WrongChain => write!(f, "wrong chain identifier"),
            Self::Expired => write!(f, "transaction expired"),
            Self::InvalidNonce => write!(f, "invalid nonce"),
            Self::InsufficientResources => write!(f, "insufficient resources"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::UnsupportedPayload => write!(f, "unsupported payload"),
        }
    }
}

impl std::error::Error for TransactionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        assert!(!TransactionError::InvalidEnvelope.to_string().is_empty());
        assert!(!TransactionError::WrongChain.to_string().is_empty());
        assert!(!TransactionError::Expired.to_string().is_empty());
        assert!(!TransactionError::InvalidNonce.to_string().is_empty());
        assert!(
            !TransactionError::InsufficientResources
                .to_string()
                .is_empty()
        );
        assert!(!TransactionError::InvalidSignature.to_string().is_empty());
        assert!(!TransactionError::UnsupportedPayload.to_string().is_empty());
    }
}
