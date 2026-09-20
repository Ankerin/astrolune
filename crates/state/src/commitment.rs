// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Count-bound Merkle commitments over lexicographically sorted state entries.

use std::collections::BTreeMap;

use crypto::blake2s::domain_hash;
use types::{Hash256, StateKey, domain};

use crate::{MAX_STATE_ENTRIES, MAX_STATE_KEY_BYTES, MAX_STATE_VALUE_BYTES};

/// Membership path for a key/value pair under a trusted state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProof {
    /// Zero-based position in lexicographic key order.
    pub index: u64,
    /// Total leaves, authenticated by the root wrapper.
    pub leaf_count: u64,
    /// Siblings from the leaf upwards; unpaired nodes are promoted unchanged.
    pub siblings: Vec<Hash256>,
}

impl StateProof {
    /// Checks the value, position, tree shape, and every sibling against `root`.
    #[must_use]
    pub fn verify(&self, root: Hash256, key: &StateKey, value: &[u8]) -> bool {
        if self.leaf_count == 0
            || self.leaf_count > MAX_STATE_ENTRIES as u64
            || self.index >= self.leaf_count
            || self.siblings.len() > 20
            || key.len() > MAX_STATE_KEY_BYTES
            || value.len() > MAX_STATE_VALUE_BYTES
        {
            return false;
        }
        let mut hash = leaf_hash(key, value);
        let mut index = self.index;
        let mut width = self.leaf_count;
        let mut siblings = self.siblings.iter();
        while width > 1 {
            if index % 2 == 1 {
                let Some(left) = siblings.next() else {
                    return false;
                };
                hash = node_hash(*left, hash);
            } else if index + 1 < width {
                let Some(right) = siblings.next() else {
                    return false;
                };
                hash = node_hash(hash, *right);
            }
            index /= 2;
            width = width.div_ceil(2);
        }
        siblings.next().is_none() && root_hash(self.leaf_count, hash) == root
    }
}

/// Commitment of the empty state; it is intentionally not the all-zero sentinel.
#[must_use]
pub fn empty_root() -> Hash256 {
    root_hash(0, Hash256::ZERO)
}

pub(crate) fn compute_root(data: &BTreeMap<StateKey, Vec<u8>>) -> Hash256 {
    let mut level: Vec<_> = data.iter().map(|(k, v)| leaf_hash(k, v)).collect();
    while level.len() > 1 {
        level = next_level(&level);
    }
    root_hash(
        data.len() as u64,
        level.first().copied().unwrap_or(Hash256::ZERO),
    )
}

pub(crate) fn prove(data: &BTreeMap<StateKey, Vec<u8>>, key: &StateKey) -> Option<StateProof> {
    let index = data.keys().position(|candidate| candidate == key)?;
    let mut proof = StateProof {
        index: index as u64,
        leaf_count: data.len() as u64,
        siblings: Vec::new(),
    };
    let mut position = index;
    let mut level: Vec<_> = data.iter().map(|(k, v)| leaf_hash(k, v)).collect();
    while level.len() > 1 {
        if let Some(sibling) = level.get(position ^ 1) {
            proof.siblings.push(*sibling);
        }
        position /= 2;
        level = next_level(&level);
    }
    Some(proof)
}

fn next_level(level: &[Hash256]) -> Vec<Hash256> {
    level
        .chunks(2)
        .map(|pair| {
            if pair.len() == 2 {
                node_hash(pair[0], pair[1])
            } else {
                pair[0]
            }
        })
        .collect()
}

fn leaf_hash(key: &StateKey, value: &[u8]) -> Hash256 {
    // Fixed-width lengths separate keys from values even when bytes share prefixes.
    let mut bytes = Vec::with_capacity(16 + key.len() + value.len());
    bytes.extend_from_slice(&(key.len() as u64).to_le_bytes());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
    domain_hash(domain::STATE_LEAF, &bytes)
}

fn node_hash(left: Hash256, right: Hash256) -> Hash256 {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(left.as_bytes());
    bytes[32..].copy_from_slice(right.as_bytes());
    domain_hash(domain::STATE_NODE, &bytes)
}

fn root_hash(count: u64, top: Hash256) -> Hash256 {
    let mut bytes = [0; 40];
    bytes[..8].copy_from_slice(&count.to_le_bytes());
    bytes[8..].copy_from_slice(top.as_bytes());
    domain_hash(domain::STATE_ROOT, &bytes)
}
