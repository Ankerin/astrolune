// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! A simple file-backed persistent state database.
//!
//! State is stored as a flat binary file containing all key-value pairs.
//! On each commit the entire state is serialized atomically: a new temporary
//! file is written, then renamed over the old one. This guarantees that the
//! data file is always in a consistent state, even if the process crashes
//! mid-write.
//!
//! Binary format (repeated for each entry):
//! ```text
//! [4 bytes LE key_len][key_bytes][4 bytes LE val_len][val_bytes]
//! ```
//!
//! This is a reference implementation suitable for small-to-medium datasets.
//! Production nodes should use a B-tree on disk for efficient range queries
//! and partial writes.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use types::{Hash256, StateKey};

use crate::database::{StateDatabase, StateError, StateSnapshot};
use crate::diff::StateChange;

/// A file-backed persistent state database.
///
/// All key-value pairs are stored in a single binary file and loaded entirely
/// into memory on startup. Commits write the full state back to disk
/// atomically using a temporary file and rename.
#[derive(Debug)]
pub struct FileBackedState {
    /// Current state contents (kept in memory for fast reads).
    data: BTreeMap<StateKey, Vec<u8>>,
    /// Current state root hash.
    root: Hash256,
    /// Path to the persistent data file.
    path: PathBuf,
}

impl FileBackedState {
    /// Opens or creates a file-backed state database at the given path.
    ///
    /// If the file exists, it is loaded. If it does not exist, a new empty
    /// database is created and persisted.
    ///
    /// # Errors
    ///
    /// Returns `StateError::Corrupt` if the file contains malformed data.
    /// Returns `StateError::Io` on filesystem errors.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateError> {
        let path = path.as_ref().to_path_buf();

        let data = if path.exists() {
            Self::load_file(&path)?
        } else {
            BTreeMap::new()
        };

        let root = Self::compute_root(&data);

        let state = Self { data, root, path };

        // Persist the empty state if the file did not exist
        if !state.path.exists() {
            state.flush_to_disk()?;
        }

        Ok(state)
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

    /// Loads all key-value pairs from the data file.
    fn load_file(path: &Path) -> Result<BTreeMap<StateKey, Vec<u8>>, StateError> {
        let bytes = fs::read(path).map_err(|_| StateError::Corrupt)?;
        let mut data = BTreeMap::new();
        let mut cursor = 0;

        while cursor < bytes.len() {
            // Read key length
            if cursor + 4 > bytes.len() {
                return Err(StateError::Corrupt);
            }
            let key_len = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;

            // Read key bytes
            if cursor + key_len > bytes.len() {
                return Err(StateError::Corrupt);
            }
            let key_bytes = bytes[cursor..cursor + key_len].to_vec();
            cursor += key_len;

            // Read value length
            if cursor + 4 > bytes.len() {
                return Err(StateError::Corrupt);
            }
            let val_len = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            cursor += 4;

            // Read value bytes
            if cursor + val_len > bytes.len() {
                return Err(StateError::Corrupt);
            }
            let val_bytes = bytes[cursor..cursor + val_len].to_vec();
            cursor += val_len;

            data.insert(StateKey(key_bytes), val_bytes);
        }

        Ok(data)
    }

    /// Writes the entire state to disk atomically.
    ///
    /// Uses a temporary file and rename to ensure the data file is never
    /// left in a partially-written state.
    fn flush_to_disk(&self) -> Result<(), StateError> {
        let tmp_path = self.path.with_extension("tmp");

        let mut file = fs::File::create(&tmp_path).map_err(|_| StateError::Corrupt)?;

        for (key, value) in &self.data {
            let key_len = u32::try_from(key.len()).map_err(|_| StateError::LimitExceeded)?;
            let val_len = u32::try_from(value.len()).map_err(|_| StateError::LimitExceeded)?;

            file.write_all(&key_len.to_le_bytes())
                .map_err(|_| StateError::Corrupt)?;
            file.write_all(key.as_bytes())
                .map_err(|_| StateError::Corrupt)?;
            file.write_all(&val_len.to_le_bytes())
                .map_err(|_| StateError::Corrupt)?;
            file.write_all(value).map_err(|_| StateError::Corrupt)?;
        }

        file.flush().map_err(|_| StateError::Corrupt)?;

        // Atomic rename over the old data file
        fs::rename(&tmp_path, &self.path).map_err(|_| StateError::Corrupt)?;

        Ok(())
    }

    /// Computes a deterministic root hash from state contents.
    ///
    /// Uses XOR of per-entry hashes, identical to `InMemoryState`.
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

impl StateSnapshot for FileBackedState {
    fn root(&self) -> Hash256 {
        self.root
    }

    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }
}

impl StateDatabase for FileBackedState {
    fn snapshot(&self) -> Result<Box<dyn StateSnapshot>, StateError> {
        Ok(Box::new(FileBackedSnapshot {
            data: self.data.clone(),
            root: self.root,
        }))
    }

    fn prefetch(&self, _keys: &[StateKey]) -> Result<(), StateError> {
        // No-op: all data is already in memory
        Ok(())
    }

    fn commit(
        &mut self,
        parent: Hash256,
        diffs: &[crate::diff::StateDiff],
    ) -> Result<Hash256, StateError> {
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
        self.flush_to_disk()?;
        Ok(self.root)
    }
}

/// An immutable snapshot of file-backed state.
#[derive(Debug)]
struct FileBackedSnapshot {
    data: BTreeMap<StateKey, Vec<u8>>,
    root: Hash256,
}

impl StateSnapshot for FileBackedSnapshot {
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
    use crate::diff::StateDiff;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("astrolune_state_test");
        fs::create_dir_all(&dir).ok();
        dir.join(name)
    }

    fn cleanup(path: &Path) {
        fs::remove_file(path).ok();
        fs::remove_file(path.with_extension("tmp")).ok();
    }

    fn key(b: u8) -> StateKey {
        StateKey(vec![b])
    }

    #[test]
    fn open_creates_new_file() {
        let path = temp_path("test_new.dat");
        cleanup(&path);

        let state = FileBackedState::open(&path).unwrap();
        assert!(state.is_empty());
        assert!(state.root().is_zero());
        assert!(path.exists());

        cleanup(&path);
    }

    #[test]
    fn open_loads_existing_file() {
        let path = temp_path("test_load.dat");
        cleanup(&path);

        {
            let mut state = FileBackedState::open(&path).unwrap();
            let mut diff = StateDiff::new();
            diff.put(key(1), vec![10, 20]);
            state.commit(state.root(), &[diff]).unwrap();
        }

        let state = FileBackedState::open(&path).unwrap();
        assert_eq!(state.len(), 1);
        assert_eq!(state.get(&key(1)), Some(&[10, 20][..]));

        cleanup(&path);
    }

    #[test]
    fn commit_persists_to_disk() {
        let path = temp_path("test_persist.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), vec![10]);
        diff.put(key(2), vec![20]);
        let root1 = state.commit(root0, &[diff]).unwrap();

        // Reload from disk
        let state2 = FileBackedState::open(&path).unwrap();
        assert_eq!(state2.root(), root1);
        assert_eq!(state2.len(), 2);
        assert_eq!(state2.get(&key(1)), Some(&[10][..]));
        assert_eq!(state2.get(&key(2)), Some(&[20][..]));

        cleanup(&path);
    }

    #[test]
    fn commit_rejects_stale_parent() {
        let path = temp_path("test_stale.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let bad_root = Hash256([0xFF; 32]);

        let diff = StateDiff::new();
        assert_eq!(
            state.commit(bad_root, &[diff]),
            Err(StateError::StaleSnapshot)
        );

        cleanup(&path);
    }

    #[test]
    fn snapshot_isolation() {
        let path = temp_path("test_snapshot.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), vec![10]);
        state.commit(root0, &[diff]).unwrap();

        let snapshot = state.snapshot().unwrap();

        let mut diff2 = StateDiff::new();
        diff2.put(key(2), vec![20]);
        state.commit(state.root(), &[diff2]).unwrap();

        assert_eq!(snapshot.get(&key(1)).unwrap(), Some(vec![10]));
        assert_eq!(snapshot.get(&key(2)).unwrap(), None);

        cleanup(&path);
    }

    #[test]
    fn delete_through_commit() {
        let path = temp_path("test_delete.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), vec![10]);
        let root1 = state.commit(root0, &[diff]).unwrap();

        let mut diff2 = StateDiff::new();
        diff2.delete(key(1));
        state.commit(root1, &[diff2]).unwrap();

        assert!(state.is_empty());

        cleanup(&path);
    }

    #[test]
    fn root_deterministic() {
        let path = temp_path("test_deterministic.dat");
        cleanup(&path);

        let mut state = FileBackedState::open(&path).unwrap();
        let root0 = state.root();

        let mut diff = StateDiff::new();
        diff.put(key(1), vec![10]);
        let root1 = state.commit(root0, &[diff]).unwrap();

        // Reload and commit the same data
        let mut state2 = FileBackedState::open(&path).unwrap();
        let mut diff2 = StateDiff::new();
        diff2.put(key(1), vec![10]);
        let root2 = state2.commit(state2.root(), &[diff2]).unwrap();

        assert_eq!(root1, root2);

        cleanup(&path);
    }
}
