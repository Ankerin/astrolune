// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Purpose-separated non-exporting signer and anti-equivocation boundaries.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

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
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
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

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// In-memory keystore for testing and simulation.
///
/// Stores keys by string identifier, maps them to a [`ValidatorId`] and
/// [`KeyPurpose`], and tracks consensus signing positions to prevent
/// equivocation.
pub struct MockKeystore {
    keys: BTreeMap<String, (ValidatorId, KeyPurpose)>,
    signed: BTreeMap<(String, SigningPosition), Hash256>,
}

impl MockKeystore {
    /// Creates an empty mock keystore.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            signed: BTreeMap::new(),
        }
    }

    /// Registers a key with the given purpose and validator identity.
    pub fn insert(
        &mut self,
        id: impl Into<String>,
        validator_id: ValidatorId,
        purpose: KeyPurpose,
    ) {
        self.keys.insert(id.into(), (validator_id, purpose));
    }

    /// Returns `true` if at least one signing position has been recorded.
    #[must_use]
    pub fn has_conflict(&self) -> bool {
        !self.signed.is_empty()
    }
}

impl Default for MockKeystore {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer for MockKeystore {
    fn validator_id(&self, handle: &KeyHandle) -> Result<ValidatorId, KeystoreError> {
        match self.keys.get(&handle.id) {
            Some(&(vid, purpose)) => {
                if purpose == handle.purpose {
                    Ok(vid)
                } else {
                    Err(KeystoreError::WrongPurpose)
                }
            }
            None => Err(KeystoreError::UnknownKey),
        }
    }

    fn sign_consensus(
        &mut self,
        handle: &KeyHandle,
        position: SigningPosition,
        message: Hash256,
    ) -> Result<[u8; 64], KeystoreError> {
        let (vid, purpose) = self.keys.get(&handle.id).ok_or(KeystoreError::UnknownKey)?;

        if purpose != &KeyPurpose::Consensus {
            return Err(KeystoreError::WrongPurpose);
        }

        let key = (handle.id.clone(), position);
        if let Some(&prev) = self.signed.get(&key)
            && prev != message
        {
            return Err(KeystoreError::ConflictingSign);
        }

        self.signed.insert(key, message);

        Ok(deterministic_mock_signature(*vid, position, message))
    }
}

/// Generates a deterministic 64-byte mock signature from key material and
/// signing coordinates.
fn deterministic_mock_signature(
    validator_id: ValidatorId,
    position: SigningPosition,
    message: Hash256,
) -> [u8; 64] {
    let mut sig = [0u8; 64];

    sig[0..32].copy_from_slice(validator_id.as_bytes());
    sig[32..64].copy_from_slice(message.as_bytes());

    let height = position.height.to_le_bytes();
    let round = position.round.to_le_bytes();

    for (i, &b) in height.iter().enumerate() {
        sig[i] ^= b;
    }
    for (i, &b) in round.iter().enumerate() {
        sig[8 + i] ^= b;
    }

    sig[12] ^= position.phase;

    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(n: u8) -> ValidatorId {
        ValidatorId([n; 32])
    }

    fn handle(id: &str, purpose: KeyPurpose) -> KeyHandle {
        KeyHandle {
            id: id.to_string(),
            purpose,
        }
    }

    #[test]
    fn keystore_error_display() {
        assert_eq!(KeystoreError::UnknownKey.to_string(), "unknown key");
        assert_eq!(KeystoreError::WrongPurpose.to_string(), "wrong purpose");
        assert_eq!(
            KeystoreError::ConflictingSign.to_string(),
            "conflicting sign"
        );
        assert_eq!(KeystoreError::JournalFailure.to_string(), "journal failure");
        assert_eq!(
            KeystoreError::ProviderFailure.to_string(),
            "provider failure"
        );
    }

    #[test]
    fn keystore_error_is_std_error() {
        let err: &dyn std::error::Error = &KeystoreError::UnknownKey;
        assert_eq!(err.to_string(), "unknown key");
    }

    #[test]
    fn insert_and_lookup() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);

        let h = handle("k1", KeyPurpose::Consensus);
        assert_eq!(ks.validator_id(&h).unwrap(), vid(1));
    }

    #[test]
    fn unknown_key_returns_error() {
        let ks = MockKeystore::new();
        let h = handle("missing", KeyPurpose::Consensus);
        assert_eq!(ks.validator_id(&h), Err(KeystoreError::UnknownKey));
    }

    #[test]
    fn wrong_purpose_returns_error() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Network);

        let h = handle("k1", KeyPurpose::Consensus);
        assert_eq!(ks.validator_id(&h), Err(KeystoreError::WrongPurpose));
    }

    #[test]
    fn purpose_exact_match() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Service);

        for purpose in [
            KeyPurpose::Consensus,
            KeyPurpose::Network,
            KeyPurpose::Service,
            KeyPurpose::Wallet,
        ] {
            let h = handle("k1", purpose);
            if purpose == KeyPurpose::Service {
                assert_eq!(ks.validator_id(&h).unwrap(), vid(1));
            } else {
                assert_eq!(ks.validator_id(&h), Err(KeystoreError::WrongPurpose));
            }
        }
    }

    #[test]
    fn sign_consensus_unknown_key() {
        let mut ks = MockKeystore::new();
        let h = handle("missing", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        assert_eq!(
            ks.sign_consensus(&h, pos, Hash256([1u8; 32])),
            Err(KeystoreError::UnknownKey)
        );
    }

    #[test]
    fn sign_consensus_wrong_purpose() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Network);
        let h = handle("k1", KeyPurpose::Network);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        assert_eq!(
            ks.sign_consensus(&h, pos, Hash256([1u8; 32])),
            Err(KeystoreError::WrongPurpose)
        );
    }

    #[test]
    fn sign_consensus_success() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        let sig = ks.sign_consensus(&h, pos, Hash256([0xAB; 32])).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn sign_consensus_same_message_no_conflict() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 5,
            round: 1,
            phase: 2,
        };
        let msg = Hash256([42u8; 32]);

        let sig1 = ks.sign_consensus(&h, pos, msg).unwrap();
        let sig2 = ks.sign_consensus(&h, pos, msg).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn sign_consensus_different_message_equivocation() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 5,
            round: 1,
            phase: 2,
        };

        let msg1 = Hash256([1u8; 32]);
        let msg2 = Hash256([2u8; 32]);

        ks.sign_consensus(&h, pos, msg1).unwrap();
        assert_eq!(
            ks.sign_consensus(&h, pos, msg2),
            Err(KeystoreError::ConflictingSign)
        );
    }

    #[test]
    fn has_conflict_tracks_state() {
        let mut ks = MockKeystore::new();
        assert!(!ks.has_conflict());

        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };

        ks.sign_consensus(&h, pos, Hash256([0u8; 32])).unwrap();
        assert!(ks.has_conflict());
    }

    #[test]
    fn different_positions_do_not_conflict() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);

        let pos_a = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        let pos_b = SigningPosition {
            height: 1,
            round: 0,
            phase: 1,
        };

        let msg = Hash256([42u8; 32]);
        ks.sign_consensus(&h, pos_a, msg).unwrap();
        // different position, no conflict even with same message
        ks.sign_consensus(&h, pos_b, msg).unwrap();
    }

    #[test]
    fn mock_signature_deterministic() {
        let mut ks = MockKeystore::new();
        ks.insert("k1", vid(1), KeyPurpose::Consensus);
        let h = handle("k1", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 10,
            round: 3,
            phase: 1,
        };
        let msg = Hash256([0xFF; 32]);

        let sig1 = ks.sign_consensus(&h, pos, msg).unwrap();
        // reset and recreate
        let mut ks2 = MockKeystore::new();
        ks2.insert("k1", vid(1), KeyPurpose::Consensus);
        let sig2 = ks2.sign_consensus(&h, pos, msg).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn mock_signature_varies_by_validator() {
        let make_sig = |n: u8| {
            let mut ks = MockKeystore::new();
            ks.insert("k1", vid(n), KeyPurpose::Consensus);
            let h = handle("k1", KeyPurpose::Consensus);
            let pos = SigningPosition {
                height: 1,
                round: 0,
                phase: 0,
            };
            ks.sign_consensus(&h, pos, Hash256::ZERO).unwrap()
        };

        assert_ne!(make_sig(1), make_sig(2));
    }

    #[test]
    fn mock_signature_varies_by_message() {
        let make_sig = |m: u8| {
            let mut ks = MockKeystore::new();
            ks.insert("k1", vid(1), KeyPurpose::Consensus);
            let h = handle("k1", KeyPurpose::Consensus);
            let pos = SigningPosition {
                height: 1,
                round: 0,
                phase: 0,
            };
            ks.sign_consensus(&h, pos, Hash256([m; 32])).unwrap()
        };

        assert_ne!(make_sig(0), make_sig(1));
    }

    #[test]
    fn mock_signature_varies_by_position() {
        let make_sig = |height: u64| {
            let mut ks = MockKeystore::new();
            ks.insert("k1", vid(1), KeyPurpose::Consensus);
            let h = handle("k1", KeyPurpose::Consensus);
            let pos = SigningPosition {
                height,
                round: 0,
                phase: 0,
            };
            ks.sign_consensus(&h, pos, Hash256::ZERO).unwrap()
        };

        assert_ne!(make_sig(0), make_sig(1));
    }

    #[test]
    fn multiple_keys_independent() {
        let mut ks = MockKeystore::new();
        ks.insert("a", vid(1), KeyPurpose::Consensus);
        ks.insert("b", vid(2), KeyPurpose::Consensus);

        let ha = handle("a", KeyPurpose::Consensus);
        let hb = handle("b", KeyPurpose::Consensus);
        let pos = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };

        let sig_a = ks.sign_consensus(&ha, pos, Hash256([1u8; 32])).unwrap();
        let sig_b = ks.sign_consensus(&hb, pos, Hash256([2u8; 32])).unwrap();
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn default_is_empty() {
        let ks = MockKeystore::default();
        assert!(!ks.has_conflict());
        let h = handle("anything", KeyPurpose::Consensus);
        assert_eq!(ks.validator_id(&h), Err(KeystoreError::UnknownKey));
    }

    #[test]
    fn signing_position_ord() {
        let a = SigningPosition {
            height: 1,
            round: 0,
            phase: 0,
        };
        let b = SigningPosition {
            height: 2,
            round: 0,
            phase: 0,
        };
        let c = SigningPosition {
            height: 1,
            round: 1,
            phase: 0,
        };
        assert!(a < b);
        assert!(a < c);
        assert!(b > c);
    }
}
