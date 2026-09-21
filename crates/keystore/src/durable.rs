// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Ed25519 signing after a durable, monotonic journal reservation.

use crate::{
    ChainSigner, KeyHandle, KeyPurpose, KeystoreError, Signer, SigningContext, SigningPosition,
    journal::Journal,
};
use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use std::path::Path;
use types::{Hash256, ValidatorId};
use zeroize::Zeroizing;

/// Single-key reference signer with non-exporting, zeroizing in-memory key material.
///
/// The caller provisions the same raw Ed25519 seed and original journal on restart.
/// No private key is stored in the journal. This is not encrypted key storage, an
/// HSM, or protection against restoring an older valid journal or cloning a key.
pub struct DurableSigner {
    seed: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
    validator: ValidatorId,
    handle: KeyHandle,
    context: SigningContext,
    journal: Journal,
}

impl std::fmt::Debug for DurableSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableSigner")
            .field("handle", &self.handle)
            .field("context", &self.context)
            .field("last_position", &self.last_position())
            .finish_non_exhaustive()
    }
}

impl DurableSigner {
    /// Explicitly provisions a new journal; refuses to overwrite any existing file.
    ///
    /// # Errors
    /// Returns an error for an invalid namespace, existing file, lock, or failed write.
    pub fn create(
        path: impl AsRef<Path>,
        context: SigningContext,
        seed: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        Self::initialize(path.as_ref(), context, Zeroizing::new(seed), true)
    }

    /// Opens and verifies an existing journal and resynchronizes it before signing.
    ///
    /// # Errors
    /// Missing, corrupt, incomplete, locked, or incompatible journals fail closed.
    pub fn open(
        path: impl AsRef<Path>,
        context: SigningContext,
        seed: [u8; 32],
    ) -> Result<Self, KeystoreError> {
        Self::initialize(path.as_ref(), context, Zeroizing::new(seed), false)
    }

    fn initialize(
        path: &Path,
        context: SigningContext,
        seed: Zeroizing<[u8; 32]>,
        create: bool,
    ) -> Result<Self, KeystoreError> {
        if context.genesis == Hash256::ZERO {
            return Err(KeystoreError::ContextMismatch);
        }
        let public_key = ed25519_public_key(&seed);
        let validator = ValidatorId(blake2s(&public_key).0);
        let journal = if create {
            Journal::create(path, context, public_key)?
        } else {
            Journal::open(path, context, public_key)?
        };
        let handle = KeyHandle {
            id: Hash256(validator.0).to_string(),
            purpose: KeyPurpose::Consensus,
        };
        Ok(Self {
            seed,
            public_key,
            validator,
            handle,
            context,
            journal,
        })
    }

    /// Opaque consensus-only handle derived from the public identity, not a label.
    #[must_use]
    pub fn key_handle(&self) -> KeyHandle {
        self.handle.clone()
    }

    /// Public Ed25519 key for trusted committee registration.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Highest fully synchronized decision known by this instance.
    #[must_use]
    pub const fn last_position(&self) -> Option<SigningPosition> {
        self.journal.last_position()
    }
}

impl Signer for DurableSigner {
    fn validator_id(&self, handle: &KeyHandle) -> Result<ValidatorId, KeystoreError> {
        if handle.purpose != KeyPurpose::Consensus {
            return Err(KeystoreError::WrongPurpose);
        }
        if handle.id != self.handle.id {
            return Err(KeystoreError::UnknownKey);
        }
        Ok(self.validator)
    }

    fn sign_consensus(
        &mut self,
        handle: &KeyHandle,
        position: SigningPosition,
        message: Hash256,
    ) -> Result<[u8; 64], KeystoreError> {
        self.validator_id(handle)?;
        self.journal.reserve(position, message)?;
        Ok(ed25519_sign(&self.seed, &message.0))
    }
}

impl ChainSigner for DurableSigner {
    fn signing_context(&self) -> SigningContext {
        self.context
    }
}
