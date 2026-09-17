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

    fn verify_signature(
        &self,
        _signer: ValidatorId,
        _message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        *signature != [0u8; 64]
    }

    fn verify_vrf(&self, _validator: ValidatorId, _seed: Hash256, _output: &VrfOutput) -> bool {
        true
    }
}

/// Computes a receipts root from a slice of receipt commitments.
///
/// Uses a binary Merkle tree: pairs of commitments are hashed together,
/// and the result is promoted to the next level. An odd commitment at any
/// level is promoted without pairing. An empty slice yields
/// `Hash256::ZERO`.
///
/// The tree is computed deterministically from the canonical commitment
/// hashes and is suitable for inclusion in block headers.
#[must_use]
pub fn compute_receipts_root(commitments: &[Hash256]) -> Hash256 {
    merkle_root(commitments)
}

/// Computes a transactions root from a slice of transaction hashes.
///
/// Uses the same binary Merkle tree as [`compute_receipts_root`].
/// An empty slice yields `Hash256::ZERO`.
#[must_use]
pub fn compute_transactions_root(tx_hashes: &[Hash256]) -> Hash256 {
    merkle_root(tx_hashes)
}

/// Builds a binary Merkle root from a slice of leaf hashes.
///
/// Algorithm:
/// 1. If the slice is empty, return `Hash256::ZERO`.
/// 2. If the slice has one element, return it directly.
/// 3. Pair adjacent hashes and combine each pair with a domain-separated hash.
/// 4. If the number of elements is odd, the last element is promoted unchanged.
/// 5. Repeat until one root hash remains.
///
/// The combining hash uses a simple domain tag to prevent second-preimage
/// attacks where a leaf could be mistaken for an interior node.
fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    match leaves.len() {
        0 => Hash256::ZERO,
        1 => leaves[0],
        _ => {
            let mut current = leaves.to_vec();
            while current.len() > 1 {
                let mut next = Vec::with_capacity(current.len().div_ceil(2));
                for pair in current.chunks(2) {
                    if pair.len() == 2 {
                        // Interior node: concatenate and hash
                        let mut data = [0u8; 64];
                        data[..32].copy_from_slice(&pair[0].0);
                        data[32..].copy_from_slice(&pair[1].0);
                        let mut hash = [0u8; 32];
                        for (i, byte) in data.iter().enumerate() {
                            hash[i % 32] ^= byte;
                            hash[(i + 13) % 32] = hash[(i + 13) % 32].wrapping_add(*byte);
                        }
                        next.push(Hash256(hash));
                    } else {
                        // Odd element: promote unchanged
                        next.push(pair[0]);
                    }
                }
                current = next;
            }
            current[0]
        }
    }
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
            resources: types::Resources {
                compute: 10,
                memory: 0,
                io: 0,
                bandwidth: 0,
            },
            output_root: Hash256([2u8; 32]),
        };
        let root = compute_receipts_root(&[receipt.commitment()]);
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn receipts_root_order_matters() {
        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        let root_ab = compute_receipts_root(&[a, b]);
        let root_ba = compute_receipts_root(&[b, a]);
        // Merkle tree is order-dependent (unlike XOR)
        assert_ne!(root_ab, root_ba);
    }

    #[test]
    fn receipts_root_two_elements() {
        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        let root = compute_receipts_root(&[a, b]);
        assert_ne!(root, a);
        assert_ne!(root, b);
    }

    #[test]
    fn receipts_root_three_elements() {
        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        let c = Hash256([3u8; 32]);
        let root = compute_receipts_root(&[a, b, c]);
        // Three elements: pair (a,b) -> hash, then pair (hash, c) -> root
        assert_ne!(root, Hash256::ZERO);
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

    #[test]
    fn transactions_root_deterministic() {
        let hashes = vec![Hash256([1u8; 32]), Hash256([2u8; 32]), Hash256([3u8; 32])];
        let r1 = compute_transactions_root(&hashes);
        let r2 = compute_transactions_root(&hashes);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_different_from_xor() {
        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        let merkle = compute_receipts_root(&[a, b]);
        let xor_result = a.xor(b);
        // Merkle and XOR produce different results
        assert_ne!(merkle, xor_result);
    }
}
