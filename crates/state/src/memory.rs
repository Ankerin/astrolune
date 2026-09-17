// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! A simple in-memory state database for testing and development.

use std::collections::BTreeMap;

use types::{Hash256, StateKey};

use crate::database::{StateDatabase, StateError, StateSnapshot};
use crate::diff::StateChange;

/// A simple in-memory state database for testing and development.
///
/// This is a reference implementation. Production nodes will use a persistent
/// database engine.
#[derive(Debug)]
pub struct InMemoryState {
    /// Current state contents.
    data: BTreeMap<StateKey, Vec<u8>>,
    /// Current state root (hash of all key-value pairs in canonical order).
    root: Hash256,
}

impl InMemoryState {
    /// Creates a new empty state database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
            root: Self::compute_root(&BTreeMap::new()),
        }
    }

    /// Returns the current state root.
    #[must_use]
    pub fn root(&self) -> Hash256 {
        self.root
    }

    /// Returns the number of key-value pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the state is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Reads a value from the state.
    #[must_use]
    pub fn get(&self, key: &StateKey) -> Option<&[u8]> {
        self.data.get(key).map(Vec::as_slice)
    }

    /// Computes a deterministic root hash from the state contents.
    ///
    /// The root is computed by XOR-ing a hash of each key-value pair in
    /// canonical (sorted) order. This is a simple reference scheme; the
    /// production implementation will use a Merkle trie.
    fn compute_root(data: &BTreeMap<StateKey, Vec<u8>>) -> Hash256 {
        let mut root = Hash256::ZERO;
        for (key, value) in data {
            let mut pair_hash = [0u8; 32];
            let key_len = u32::try_from(key.len()).unwrap_or(u32::MAX);
            let val_len = u32::try_from(value.len()).unwrap_or(u32::MAX);
            pair_hash[0..4].copy_from_slice(&key_len.to_le_bytes());
            pair_hash[4..8].copy_from_slice(&val_len.to_le_bytes());
            for (i, byte) in key.as_bytes().iter().enumerate().take(24) {
                pair_hash[8 + i] = *byte;
            }
            for (i, byte) in value.iter().enumerate().take(24) {
                pair_hash[8 + i] ^= *byte;
            }
            root = root.xor(Hash256(pair_hash));
        }
        root
    }
}

impl Default for InMemoryState {
    fn default() -> Self {
        Self::new()
    }
}

impl StateSnapshot for InMemoryState {
    fn root(&self) -> Hash256 {
        self.root
    }

    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }
}

impl StateDatabase for InMemoryState {
    fn snapshot(&self) -> Result<Box<dyn StateSnapshot>, StateError> {
        Ok(Box::new(InMemorySnapshot {
            data: self.data.clone(),
            root: self.root,
        }))
    }

    fn prefetch(&self, _keys: &[StateKey]) -> Result<(), StateError> {
        Ok(())
    }

    fn commit(&mut self, parent: Hash256, diffs: &[crate::diff::StateDiff]) -> Result<Hash256, StateError> {
        if self.root != parent {
            return Err(StateError::StaleSnapshot);
        }

        for diff in diffs {
            for change in &diff.changes {
                match change {
                    StateChange::Put(key, value) => {
                        self.data.insert(key.clone(), value.clone());
                    }
                    StateChange::Delete(key) => {
                        self.data.remove(key);
                    }
                }
            }
        }

        self.root = Self::compute_root(&self.data);
        Ok(self.root)
    }
}

/// An immutable snapshot of in-memory state.
#[derive(Debug)]
struct InMemorySnapshot {
    data: BTreeMap<StateKey, Vec<u8>>,
    root: Hash256,
}

impl StateSnapshot for InMemorySnapshot {
    fn root(&self) -> Hash256 {
        self.root
    }

    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }
}
