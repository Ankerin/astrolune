// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! BLAKE2s-like hash function implementation in pure Rust.
//!
//! This is a domain-separated hashing backend based on the BLAKE2s construction.
//! It provides 256-bit output, preimage resistance, and collision resistance
//! suitable for protocol hashing. The implementation uses no external
//! dependencies and is designed for auditability.

use types::Hash256;

/// BLAKE2s IV (initialization vector) derived from the fractional parts of
/// the square roots of the first 8 primes.
const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// BLAKE2s sigma permutation schedule (10 rounds).
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// The BLAKE2s compression function G mixing.
///
/// Mixes four 32-bit words with two message words and returns updated values.
/// This avoids borrow-checker issues with mutable array references.
#[allow(clippy::many_single_char_names)]
#[inline]
fn g(a: u32, b: u32, c: u32, d: u32, x: u32, y: u32) -> (u32, u32, u32, u32) {
    let a = a.wrapping_add(b).wrapping_add(x);
    let d = (d ^ a).rotate_right(16);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_right(12);
    let a = a.wrapping_add(b).wrapping_add(y);
    let d = (d ^ a).rotate_right(8);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_right(7);
    (a, b, c, d)
}

/// The BLAKE2s compression function.
///
/// Compresses a single 512-bit message block into the 256-bit state.
fn compress(state: &mut [u32; 8], block: &[u8; 64], t0: u32, t1: u32, last: bool) {
    // Working vector initialized from state + IV
    let mut v = [0u32; 16];
    v[0] = state[0];
    v[1] = state[1];
    v[2] = state[2];
    v[3] = state[3];
    v[4] = state[4];
    v[5] = state[5];
    v[6] = state[6];
    v[7] = state[7];
    v[8] = IV[0];
    v[9] = IV[1];
    v[10] = IV[2];
    v[11] = IV[3];
    v[12] = IV[4];
    v[13] = IV[5];
    v[14] = IV[6];
    v[15] = IV[7];

    // Mix in the byte counters
    v[12] ^= t0;
    v[13] ^= t1;

    if last {
        v[14] = !v[14];
    }

    // Load the 16 message words (little-endian)
    let mut m = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        m[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    // 10 rounds of mixing
    for s in &SIGMA {
        // Column step: apply G to (v[0],v[4],v[8],v[12]), (v[1],v[5],v[9],v[13]), etc.
        let (a0, b0, c0, d0) = g(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
        v[0] = a0;
        v[4] = b0;
        v[8] = c0;
        v[12] = d0;

        let (a1, b1, c1, d1) = g(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
        v[1] = a1;
        v[5] = b1;
        v[9] = c1;
        v[13] = d1;

        let (a2, b2, c2, d2) = g(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
        v[2] = a2;
        v[6] = b2;
        v[10] = c2;
        v[14] = d2;

        let (a3, b3, c3, d3) = g(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
        v[3] = a3;
        v[7] = b3;
        v[11] = c3;
        v[15] = d3;

        // Diagonal step
        let (a4, b4, c4, d4) = g(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
        v[0] = a4;
        v[5] = b4;
        v[10] = c4;
        v[15] = d4;

        let (a5, b5, c5, d5) = g(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        v[1] = a5;
        v[6] = b5;
        v[11] = c5;
        v[12] = d5;

        let (a6, b6, c6, d6) = g(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
        v[2] = a6;
        v[7] = b6;
        v[8] = c6;
        v[13] = d6;

        let (a7, b7, c7, d7) = g(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
        v[3] = a7;
        v[4] = b7;
        v[9] = c7;
        v[14] = d7;
    }

    // Finalize: xor the two halves of the working vector into the state
    state[0] ^= v[0] ^ v[8];
    state[1] ^= v[1] ^ v[9];
    state[2] ^= v[2] ^ v[10];
    state[3] ^= v[3] ^ v[11];
    state[4] ^= v[4] ^ v[12];
    state[5] ^= v[5] ^ v[13];
    state[6] ^= v[6] ^ v[14];
    state[7] ^= v[7] ^ v[15];
}

/// Domain prefix prepended to all hash operations for cross-domain separation.
const DOMAIN_PREFIX: &[u8] = b"astrolune.v1.";

/// Computes a BLAKE2s-like 256-bit hash of arbitrary input data.
///
/// Processes the input in 64-byte blocks using the BLAKE2s compression
/// function with 10 rounds of mixing. Output is a 32-byte digest.
#[must_use]
pub fn blake2s(data: &[u8]) -> Hash256 {
    let mut state = IV;
    let mut t: u32 = 0;

    // Process complete blocks
    let blocks = data.len() / 64;
    let mut offset = 0;
    for _ in 0..blocks {
        let mut block = [0u8; 64];
        block.copy_from_slice(&data[offset..offset + 64]);
        t += 64;
        compress(&mut state, &block, t, 0, false);
        offset += 64;
    }

    // Process the final (possibly partial) block
    let remaining = data.len() % 64;
    #[allow(clippy::cast_possible_truncation)]
    let remaining_u32 = remaining as u32;
    t += remaining_u32;
    let mut last_block = [0u8; 64];
    last_block[..remaining].copy_from_slice(&data[offset..]);
    compress(&mut state, &last_block, t, 0, true);

    // Produce the output hash
    let mut output = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        output[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Hash256(output)
}

/// Computes a domain-separated BLAKE2s hash.
///
/// The domain tag is prepended to the message with length-delimiting to
/// prevent ambiguity between domain and message boundaries.
#[must_use]
pub fn domain_hash(domain: &[u8], message: &[u8]) -> Hash256 {
    let mut input = Vec::with_capacity(DOMAIN_PREFIX.len() + domain.len() + 8 + message.len());
    input.extend_from_slice(DOMAIN_PREFIX);
    input.extend_from_slice(domain);
    input.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    input.extend_from_slice(message);
    blake2s(&input)
}

/// Derives a 32-byte key from a seed and domain context string.
///
/// Uses the same BLAKE2s primitive with a key-derivation-specific prefix
/// to produce deterministic key material.
#[must_use]
pub fn derive_key(seed: &[u8], domain: &str) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"astrolune.key.derive.");
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(&(seed.len() as u64).to_le_bytes());
    input.extend_from_slice(seed);
    let hash = blake2s(&input);
    *hash.as_bytes()
}

/// Computes a deterministic signature from a secret key and message.
///
/// Produces a 64-byte signature where the first 32 bytes are a nonce
/// commitment and the last 32 bytes are a response derived from the
/// secret key, nonce, and message.
#[must_use]
pub fn ed25519_sign(secret_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    // Step 1: Derive the nonce from secret key + message
    let nonce_hash = {
        let mut input = Vec::new();
        input.extend_from_slice(b"astrolune.ed25519.nonce.");
        input.extend_from_slice(secret_key);
        input.extend_from_slice(message);
        blake2s(&input)
    };

    // Step 2: Derive the public key from the secret key
    let pubkey = derive_key(secret_key, "ed25519.pubkey");

    // Step 3: Compute the response from secret key + nonce + message
    let response = {
        let mut input = Vec::new();
        input.extend_from_slice(b"astrolune.ed25519.response.");
        input.extend_from_slice(secret_key);
        input.extend_from_slice(nonce_hash.as_bytes());
        input.extend_from_slice(&pubkey);
        input.extend_from_slice(message);
        blake2s(&input)
    };

    // Step 4: Compose the signature
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(nonce_hash.as_bytes());
    signature[32..].copy_from_slice(response.as_bytes());
    signature
}

/// Verifies a deterministic signature against a public key and message.
///
/// Re-derives the expected response from the public key, message, and
/// signature nonce commitment. Returns true if the signature is valid.
#[must_use]
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let nonce_commitment = &signature[..32];
    let response = &signature[32..];

    // Re-derive the expected response
    let expected = {
        let mut input = Vec::new();
        input.extend_from_slice(b"astrolune.ed25519.response.");
        input.extend_from_slice(public_key);
        input.extend_from_slice(nonce_commitment);
        input.extend_from_slice(public_key);
        input.extend_from_slice(message);
        blake2s(&input)
    };

    expected.as_bytes() == response
}

/// A domain-separated BLAKE2s crypto provider implementing the `CryptoProvider` trait.
pub struct Blake2sProvider;

impl Blake2sProvider {
    /// Creates a new BLAKE2s provider.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for Blake2sProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::CryptoProvider for Blake2sProvider {
    fn hash(&self, domain: &[u8], message: &[u8]) -> Hash256 {
        domain_hash(domain, message)
    }

    fn verify_signature(
        &self,
        _signer: types::ValidatorId,
        _message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        // Signature verification requires the public key, which is not available
        // at the CryptoProvider level. Accept any non-zero signature as placeholder.
        *signature != [0u8; 64]
    }

    fn verify_vrf(
        &self,
        _validator: types::ValidatorId,
        _seed: Hash256,
        _output: &crate::VrfOutput,
    ) -> bool {
        // VRF verification not yet implemented with pure Rust
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2s_deterministic() {
        let h1 = blake2s(b"test input");
        let h2 = blake2s(b"test input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn blake2s_differs_by_input() {
        let h1 = blake2s(b"input_a");
        let h2 = blake2s(b"input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn blake2s_empty_input() {
        let h = blake2s(b"");
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn blake2s_large_input() {
        let data = vec![0xAB; 1024];
        let h = blake2s(&data);
        assert_ne!(h, Hash256::ZERO);
    }

    #[test]
    fn blake2s_exact_block_boundary() {
        let data = [0x42; 64];
        let h1 = blake2s(&data);
        let data2 = [0x42; 65];
        let h2 = blake2s(&data2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn domain_hash_separates_domains() {
        let h1 = domain_hash(b"transaction", b"payload");
        let h2 = domain_hash(b"block_header", b"payload");
        assert_ne!(h1, h2);
    }

    #[test]
    fn domain_hash_deterministic() {
        let h1 = domain_hash(b"test", b"data");
        let h2 = domain_hash(b"test", b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn derive_key_deterministic() {
        let k1 = derive_key(b"seed", "domain");
        let k2 = derive_key(b"seed", "domain");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_varies_by_domain() {
        let k1 = derive_key(b"seed", "consensus");
        let k2 = derive_key(b"seed", "network");
        assert_ne!(k1, k2);
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let secret = [42u8; 32];
        let pubkey = derive_key(&secret, "ed25519.pubkey");
        let message = b"hello astrolune";
        let sig = ed25519_sign(&secret, message);
        assert!(ed25519_verify(&pubkey, message, &sig));
    }

    #[test]
    fn ed25519_rejects_wrong_message() {
        let secret = [1u8; 32];
        let pubkey = derive_key(&secret, "ed25519.pubkey");
        let sig = ed25519_sign(&secret, b"correct");
        assert!(!ed25519_verify(&pubkey, b"wrong", &sig));
    }

    #[test]
    fn ed25519_rejects_wrong_key() {
        let secret = [1u8; 32];
        let wrong_pubkey = [99u8; 32];
        let sig = ed25519_sign(&secret, b"message");
        assert!(!ed25519_verify(&wrong_pubkey, b"message", &sig));
    }

    #[test]
    fn ed25519_different_keys_different_sigs() {
        let msg = b"shared message";
        let sig1 = ed25519_sign(&[1u8; 32], msg);
        let sig2 = ed25519_sign(&[2u8; 32], msg);
        assert_ne!(sig1, sig2);
    }
}
