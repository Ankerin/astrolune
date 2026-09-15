// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Cryptographic interfaces used by consensus, transactions, and `AstroLune ID`.
//!
//! Implementations must use audited primitives. This crate intentionally ships
//! only interfaces in the baseline and makes no production-security claim.
//!
//! The `MockCryptoProvider` is suitable for testing only. It accepts any
//! signature that is not all-zeros and hashes by XOR-folding.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use types::{Hash256, ValidatorId};

/// A weighted VRF proof and output used for committee eligibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VrfOutput {
    /// Pseudorandom output interpreted as a big-endian integer.
    pub randomness: Hash256,
    /// Provider-specific canonical proof bytes.
    pub proof: Vec<u8>,
}

/// Cryptographic operations required by the protocol.
pub trait CryptoProvider: Send + Sync {
    /// Hashes a domain tag and message using the canonical protocol hash.
    fn hash(&self, domain: &[u8], message: &[u8]) -> Hash256;

    /// Verifies a validator signature.
    fn verify_signature(&self, signer: ValidatorId, message: &[u8], signature: &[u8; 64]) -> bool;

    /// Verifies the VRF output for a validator and epoch seed.
    fn verify_vrf(&self, validator: ValidatorId, seed: Hash256, output: &VrfOutput) -> bool;
}

/// Mock cryptographic provider for testing.
///
/// **Not suitable for production.** Signatures are "valid" if not all-zeros.
/// Hashing uses simple XOR-fold of domain + message. VRF verification always
/// returns true.
pub struct MockCryptoProvider;

impl MockCryptoProvider {
    /// Creates a new mock provider.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockCryptoProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoProvider for MockCryptoProvider {
    fn hash(&self, domain: &[u8], message: &[u8]) -> Hash256 {
        let mut h = [0u8; 32];
        for (i, byte) in domain.iter().chain(message.iter()).enumerate() {
            h[i % 32] ^= byte;
            h[(i + 13) % 32] = h[(i + 13) % 32].wrapping_add(*byte);
        }
        Hash256(h)
    }

    fn verify_signature(&self, _signer: ValidatorId, _message: &[u8], signature: &[u8; 64]) -> bool {
        *signature != [0u8; 64]
    }

    fn verify_vrf(&self, _validator: ValidatorId, _seed: Hash256, _output: &VrfOutput) -> bool {
        true
    }
}

/// Computes a receipts root from a slice of receipt commitments.
///
/// The root is the XOR of all individual commitments. An empty slice
/// yields `Hash256::ZERO`.
#[must_use]
pub fn compute_receipts_root(commitments: &[Hash256]) -> Hash256 {
    commitments
        .iter()
        .fold(Hash256::ZERO, |acc, c| acc.xor(*c))
}

/// Computes a transactions root from a slice of transaction IDs.
///
/// The root is the XOR of all transaction hashes. An empty slice
/// yields `Hash256::ZERO`.
#[must_use]
pub fn compute_transactions_root(tx_hashes: &[Hash256]) -> Hash256 {
    tx_hashes
        .iter()
        .fold(Hash256::ZERO, |acc, h| acc.xor(*h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_hash_deterministic() {
        let provider = MockCryptoProvider::new();
        let h1 = provider.hash(b"domain", b"message");
        let h2 = provider.hash(b"domain", b"message");
        assert_eq!(h1, h2);
    }

    #[test]
    fn mock_hash_differs_by_domain() {
        let provider = MockCryptoProvider::new();
        let h1 = provider.hash(b"domain_a", b"message");
        let h2 = provider.hash(b"domain_b", b"message");
        assert_ne!(h1, h2);
    }

    #[test]
    fn mock_hash_differs_by_message() {
        let provider = MockCryptoProvider::new();
        let h1 = provider.hash(b"domain", b"msg_a");
        let h2 = provider.hash(b"domain", b"msg_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn mock_accepts_nonzero_signature() {
        let provider = MockCryptoProvider::new();
        let signer = ValidatorId::from_bytes([1u8; 32]);
        let sig = [0xFF; 64];
        assert!(provider.verify_signature(signer, b"msg", &sig));
    }

    #[test]
    fn mock_rejects_zero_signature() {
        let provider = MockCryptoProvider::new();
        let signer = ValidatorId::from_bytes([1u8; 32]);
        assert!(!provider.verify_signature(signer, b"msg", &[0u8; 64]));
    }

    #[test]
    fn mock_vrf_always_valid() {
        let provider = MockCryptoProvider::new();
        let validator = ValidatorId::from_bytes([1u8; 32]);
        let output = VrfOutput {
            randomness: Hash256([42u8; 32]),
            proof: vec![1, 2, 3],
        };
        assert!(provider.verify_vrf(validator, Hash256([7u8; 32]), &output));
    }

    #[test]
    fn receipts_root_empty() {
        assert_eq!(compute_receipts_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn receipts_root_single() {
        let receipt = types::ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: types::Resources { compute: 10, memory: 0, io: 0, bandwidth: 0 },
            output_root: Hash256([2u8; 32]),
        };
        let root = compute_receipts_root(&[receipt.commitment()]);
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn receipts_root_xor_order_matters() {
        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        let root_ab = compute_receipts_root(&[a, b]);
        let root_ba = compute_receipts_root(&[b, a]);
        // XOR is commutative, so order doesn't matter for XOR roots
        assert_eq!(root_ab, root_ba);
    }

    #[test]
    fn transactions_root_empty() {
        assert_eq!(compute_transactions_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn transactions_root_single() {
        let root = compute_transactions_root(&[Hash256([42u8; 32])]);
        assert_eq!(root, Hash256([42u8; 32]));
    }
}
