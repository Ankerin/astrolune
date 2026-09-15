// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Versioned state, access leasing, immutable snapshots, and deferred commits.
//!
//! This crate provides the core state management abstractions and a reference
//! in-memory implementation for testing and development.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;

use types::{Hash256, StateKey};

/// Access mode requested by a transaction lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessMode {
    /// Concurrent immutable access.
    Read,
    /// Exclusive mutable access.
    Write,
}

/// One declared state access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    /// Canonical state key.
    pub key: StateKey,
    /// Required access mode.
    pub mode: AccessMode,
}

/// A deterministic lease over state keys for one execution wave.
///
/// Keys are canonically sorted and deduplicated before scheduling. A lease
/// that omits an accessed key or uses the wrong mode triggers deterministic
/// failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateLease {
    /// Canonically sorted and deduplicated requests.
    pub requests: Vec<AccessRequest>,
}

impl StateLease {
    /// Returns `true` if the lease contains the given key in the required mode.
    #[must_use]
    pub fn covers(&self, key: &StateKey, mode: AccessMode) -> bool {
        self.requests
            .iter()
            .any(|req| req.key == *key && req.mode == mode)
    }

    /// Returns `true` if the lease has any write access.
    #[must_use]
    pub fn has_writes(&self) -> bool {
        self.requests
            .iter()
            .any(|req| req.mode == AccessMode::Write)
    }

    /// Returns the set of keys with write access.
    #[must_use]
    pub fn write_keys(&self) -> Vec<&StateKey> {
        self.requests
            .iter()
            .filter(|req| req.mode == AccessMode::Write)
            .map(|req| &req.key)
            .collect()
    }
}

/// An immutable state view at a finalized or speculative root.
pub trait StateSnapshot: Send + Sync {
    /// Root identifying this snapshot.
    fn root(&self) -> Hash256;

    /// Reads a value without mutating shared state.
    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError>;
}

/// A single canonical state mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateChange {
    /// Insert or replace a value.
    Put(StateKey, Vec<u8>),
    /// Remove a value.
    Delete(StateKey),
}

impl StateChange {
    /// Returns the key affected by this change.
    #[must_use]
    pub fn key(&self) -> &StateKey {
        match self {
            Self::Put(key, _) | Self::Delete(key) => key,
        }
    }
}

/// Deferred output of transaction or wave execution.
///
/// Diffs are accumulated during execution and applied atomically during
/// the commit stage. Changes are sorted by key before hashing to ensure
/// canonical ordering.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StateDiff {
    /// Changes sorted by key before hashing and commit.
    pub changes: Vec<StateChange>,
}

impl StateDiff {
    /// Creates an empty diff.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a put change.
    pub fn put(&mut self, key: StateKey, value: Vec<u8>) {
        self.changes.push(StateChange::Put(key, value));
    }

    /// Adds a delete change.
    pub fn delete(&mut self, key: StateKey) {
        self.changes.push(StateChange::Delete(key));
    }

    /// Returns `true` if the diff contains no changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Returns the number of changes in the diff.
    #[must_use]
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Sorts changes by key in canonical order.
    ///
    /// For duplicate keys, later operations overwrite earlier ones. Delete
    /// after Put removes the key; Put after Delete re-inserts it.
    pub fn sort_canonical(&mut self) {
        self.changes.sort_by(|a, b| a.key().cmp(b.key()));
    }

    /// Applies this diff to an in-memory state, returning the new state.
    ///
    /// Changes are applied in order. For canonical diffs, call
    /// [`sort_canonical`](Self::sort_canonical) first.
    #[must_use]
    pub fn apply_to(&self, state: &BTreeMap<StateKey, Vec<u8>>) -> BTreeMap<StateKey, Vec<u8>> {
        let mut result = state.clone();
        for change in &self.changes {
            match change {
                StateChange::Put(key, value) => {
                    result.insert(key.clone(), value.clone());
                }
                StateChange::Delete(key) => {
                    result.remove(key);
                }
            }
        }
        result
    }

    /// Merges another diff into this one.
    ///
    /// The other diff's changes are appended after this diff's changes.
    /// Later changes for the same key overwrite earlier ones when applied.
    pub fn merge(&mut self, other: Self) {
        self.changes.extend(other.changes);
    }
}

/// State database boundary for batching, snapshots, and sequential commits.
pub trait StateDatabase {
    /// Creates an immutable snapshot without a global execution lock.
    fn snapshot(&self) -> Result<Box<dyn StateSnapshot>, StateError>;

    /// Prefetches likely keys into a non-consensus cache.
    fn prefetch(&self, keys: &[StateKey]) -> Result<(), StateError>;

    /// Applies canonically ordered diffs in one sequential commit stage.
    fn commit(&mut self, parent: Hash256, diffs: &[StateDiff]) -> Result<Hash256, StateError>;
}

/// State access and commit failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    /// Persistent data is missing or malformed.
    Corrupt,
    /// A lease omitted an accessed key or used the wrong mode.
    LeaseViolation,
    /// The expected parent root changed before commit.
    StaleSnapshot,
    /// Configured state or resource limits were exceeded.
    LimitExceeded,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Corrupt => write!(f, "state data is corrupt"),
            Self::LeaseViolation => write!(f, "lease violation"),
            Self::StaleSnapshot => write!(f, "stale snapshot"),
            Self::LimitExceeded => write!(f, "state limit exceeded"),
        }
    }
}

impl std::error::Error for StateError {}

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
        // No-op for in-memory implementation
        Ok(())
    }

    fn commit(&mut self, parent: Hash256, diffs: &[StateDiff]) -> Result<Hash256, StateError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> StateKey {
        StateKey(vec![b])
    }

    fn val(b: u8) -> Vec<u8> {
        vec![b]
    }

    // -- StateLease tests --

    #[test]
    fn lease_covers_read_access() {
        let lease = StateLease {
            requests: vec![AccessRequest {
                key: key(1),
                mode: AccessMode::Read,
            }],
        };
        assert!(lease.covers(&key(1), AccessMode::Read));
        assert!(!lease.covers(&key(1), AccessMode::Write));
        assert!(!lease.covers(&key(2), AccessMode::Read));
    }

    #[test]
    fn lease_has_writes() {
        let read_only = StateLease {
            requests: vec![AccessRequest {
                key: key(1),
                mode: AccessMode::Read,
            }],
        };
        assert!(!read_only.has_writes());

        let with_write = StateLease {
            requests: vec![AccessRequest {
                key: key(1),
                mode: AccessMode::Write,
            }],
        };
        assert!(with_write.has_writes());
    }

    #[test]
    fn lease_write_keys() {
        let lease = StateLease {
            requests: vec![
                AccessRequest {
                    key: key(1),
                    mode: AccessMode::Read,
                },
                AccessRequest {
                    key: key(2),
                    mode: AccessMode::Write,
                },
                AccessRequest {
                    key: key(3),
                    mode: AccessMode::Write,
                },
            ],
        };
        let writes = lease.write_keys();
        assert_eq!(writes.len(), 2);
        assert!(writes.contains(&&key(2)));
        assert!(writes.contains(&&key(3)));
    }

    // -- StateDiff tests --

    #[test]
    fn diff_put_and_delete() {
        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));
        diff.delete(key(1));
        assert_eq!(diff.len(), 3);
        assert!(!diff.is_empty());
    }

    #[test]
    fn diff_apply_to_empty() {
        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));

        let state = BTreeMap::new();
        let result = diff.apply_to(&state);
        assert_eq!(result.len(), 2);
        assert_eq!(result[&key(1)], val(10));
        assert_eq!(result[&key(2)], val(20));
    }

    #[test]
    fn diff_apply_delete() {
        let mut state = BTreeMap::new();
        state.insert(key(1), val(10));
        state.insert(key(2), val(20));

        let mut diff = StateDiff::new();
        diff.delete(key(1));

        let result = diff.apply_to(&state);
        assert_eq!(result.len(), 1);
        assert!(!result.contains_key(&key(1)));
        assert_eq!(result[&key(2)], val(20));
    }

    #[test]
    fn diff_sort_canonical() {
        let mut diff = StateDiff::new();
        diff.put(key(3), val(30));
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));

        diff.sort_canonical();
        assert_eq!(diff.changes[0].key(), &key(1));
        assert_eq!(diff.changes[1].key(), &key(2));
        assert_eq!(diff.changes[2].key(), &key(3));
    }

    #[test]
    fn diff_merge() {
        let mut a = StateDiff::new();
        a.put(key(1), val(10));

        let mut b = StateDiff::new();
        b.put(key(2), val(20));

        a.merge(b);
        assert_eq!(a.len(), 2);
    }

    // -- InMemoryState tests --

    #[test]
    fn empty_state() {
        let state = InMemoryState::new();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        // Empty state has XOR-identity root (all zeros)
        assert!(state.root().is_zero());
    }

    #[test]
    fn state_commit_and_snapshot() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        diff.put(key(2), val(20));

        let root1 = state.commit(root0, &[diff]).unwrap();
        assert_ne!(root0, root1);
        assert_eq!(state.len(), 2);
        assert_eq!(state.get(&key(1)), Some(val(10).as_slice()));
        assert_eq!(state.get(&key(2)), Some(val(20).as_slice()));
    }

    #[test]
    fn state_commit_rejects_stale_parent() {
        let mut state = InMemoryState::new();
        let bad_root = Hash256([0xFF; 32]);

        let diff = StateDiff::new();
        assert_eq!(
            state.commit(bad_root, &[diff]),
            Err(StateError::StaleSnapshot)
        );
    }

    #[test]
    fn state_snapshot_isolation() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        state.commit(root0, &[diff]).unwrap();

        let snapshot = state.snapshot().unwrap();
        assert_eq!(snapshot.root(), state.root());
        assert_eq!(snapshot.get(&key(1)).unwrap(), Some(val(10)));

        // Mutation after snapshot doesn't affect the snapshot
        let mut diff2 = StateDiff::new();
        diff2.put(key(2), val(20));
        state.commit(state.root(), &[diff2]).unwrap();

        assert_eq!(snapshot.get(&key(2)).unwrap(), None);
    }

    #[test]
    fn state_delete_through_commit() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        let root1 = state.commit(root0, &[diff]).unwrap();

        let mut diff2 = StateDiff::new();
        diff2.delete(key(1));
        let _root2 = state.commit(root1, &[diff2]).unwrap();

        assert!(state.is_empty());
    }

    #[test]
    fn state_multiple_diffs_in_one_commit() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff1 = StateDiff::new();
        diff1.put(key(1), val(10));

        let mut diff2 = StateDiff::new();
        diff2.put(key(2), val(20));

        state.commit(root0, &[diff1, diff2]).unwrap();
        assert_eq!(state.len(), 2);
    }

    #[test]
    fn state_root_changes_on_same_data() {
        let mut state = InMemoryState::new();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), val(10));
        let root1 = state.commit(root0, &[diff]).unwrap();

        // Commit the same data again — root should be the same
        let mut diff2 = StateDiff::new();
        diff2.put(key(1), val(10));
        let root2 = state.commit(root1, &[diff2]).unwrap();
        assert_eq!(root1, root2);
    }

    #[test]
    fn state_error_display() {
        assert!(!StateError::Corrupt.to_string().is_empty());
        assert!(!StateError::LeaseViolation.to_string().is_empty());
        assert!(!StateError::StaleSnapshot.to_string().is_empty());
        assert!(!StateError::LimitExceeded.to_string().is_empty());
    }

    #[test]
    fn state_change_key() {
        let put = StateChange::Put(key(1), val(10));
        assert_eq!(put.key(), &key(1));

        let del = StateChange::Delete(key(2));
        assert_eq!(del.key(), &key(2));
    }
}
