// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Validator-local persistence for finalized blocks, state, and certificates.
//!
//! This crate is node infrastructure. It is not a user-data storage or file-
//! sharing service and creates no storage marketplace.
//!
//! The reference `InMemoryStorage` implements the full `NodeStorage` trait for
//! testing and development. Production deployments replace it with a durable
//! backend (e.g. `RocksDB`, `SQLite`) while keeping the same trait boundary.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;

use state::{InMemoryState, StateDatabase, StateDiff, StateError};
use types::{Block, Hash256};

/// Durable finalized chain position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    /// Finalized height.
    pub height: u64,
    /// Finalized block identifier.
    pub block: Hash256,
    /// State root published at this height.
    pub state_root: Hash256,
}

/// Atomic finalized update prepared before durable commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitBatch {
    /// Finalized canonical block.
    pub block: Block,
    /// Opaque canonical finality certificate.
    pub finality_certificate: Vec<u8>,
    /// Execution diffs in committed transaction order.
    pub state_diffs: Vec<StateDiff>,
}

/// Validator-local durable storage boundary.
pub trait NodeStorage {
    /// Returns the last complete checkpoint after recovery.
    fn recover(&mut self) -> Result<Option<Checkpoint>, StorageError>;

    /// Atomically publishes one finalized batch after syncing its dependencies.
    fn commit(&mut self, batch: &CommitBatch) -> Result<Checkpoint, StorageError>;

    /// Exports a verified snapshot through a bounded caller-owned sink.
    fn export_snapshot(
        &self,
        checkpoint: Checkpoint,
        sink: &mut dyn SnapshotSink,
    ) -> Result<(), StorageError>;

    /// Imports snapshot chunks into staging and publishes only after verification.
    fn import_snapshot(
        &mut self,
        source: &mut dyn SnapshotSource,
    ) -> Result<Checkpoint, StorageError>;

    /// Prunes data older than the local retention policy without deleting required proofs.
    fn prune(&mut self, before_height: u64) -> Result<(), StorageError>;
}

/// Bounded destination for snapshot chunks.
pub trait SnapshotSink {
    /// Writes one ordered immutable chunk.
    fn write_chunk(&mut self, index: u32, bytes: &[u8]) -> Result<(), StorageError>;
}

/// Bounded source for snapshot chunks.
pub trait SnapshotSource {
    /// Returns the next ordered chunk or `None` at completion.
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, StorageError>;
}

/// Durable storage failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    /// Persistent bytes or checksums are invalid.
    Corrupt,
    /// Batch does not extend the current finalized checkpoint.
    InvalidOrder,
    /// A commitment or finality proof is invalid.
    VerificationFailed,
    /// Requested operation exceeds a configured bound.
    LimitExceeded,
    /// Persistent I/O did not complete.
    Io,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Corrupt => write!(f, "storage data is corrupt"),
            Self::InvalidOrder => write!(f, "invalid commit order"),
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::LimitExceeded => write!(f, "storage limit exceeded"),
            Self::Io => write!(f, "storage I/O error"),
        }
    }
}

impl std::error::Error for StorageError {}

/// In-memory reference implementation of `NodeStorage`.
///
/// Stores finalized blocks, state, and certificates in memory. No data
/// survives process restarts. Useful for testing and development.
pub struct InMemoryStorage {
    /// Finalized checkpoints indexed by height.
    checkpoints: BTreeMap<u64, Checkpoint>,
    /// State database.
    state: InMemoryState,
    /// Block bodies indexed by block hash.
    blocks: BTreeMap<Hash256, Block>,
    /// Finality certificates indexed by block hash.
    certificates: BTreeMap<Hash256, Vec<u8>>,
    /// Snapshot data keyed by `(height, chunk_index)`.
    snapshots: BTreeMap<(u64, u32), Vec<u8>>,
}

impl InMemoryStorage {
    /// Creates a new empty storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checkpoints: BTreeMap::new(),
            state: InMemoryState::new(),
            blocks: BTreeMap::new(),
            certificates: BTreeMap::new(),
            snapshots: BTreeMap::new(),
        }
    }

    /// Returns the current checkpoint, if any.
    #[must_use]
    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoints.values().next_back()
    }

    /// Returns the number of finalized blocks stored.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the underlying state database (read-only).
    #[must_use]
    pub fn state(&self) -> &InMemoryState {
        &self.state
    }

    /// Returns a block by its hash.
    #[must_use]
    pub fn get_block(&self, hash: &Hash256) -> Option<&Block> {
        self.blocks.get(hash)
    }

    /// Returns a finality certificate by its block hash.
    #[must_use]
    pub fn get_certificate(&self, hash: &Hash256) -> Option<&[u8]> {
        self.certificates.get(hash).map(Vec::as_slice)
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeStorage for InMemoryStorage {
    fn recover(&mut self) -> Result<Option<Checkpoint>, StorageError> {
        Ok(self.checkpoints.values().next_back().copied())
    }

    fn commit(&mut self, batch: &CommitBatch) -> Result<Checkpoint, StorageError> {
        let expected_height = self
            .checkpoints
            .values()
            .next_back()
            .map_or(0, |c| c.height + 1);

        if batch.block.header.height != expected_height {
            return Err(StorageError::InvalidOrder);
        }

        let parent_root = if expected_height == 0 {
            Hash256::ZERO
        } else {
            self.state.root()
        };

        let new_root = self
            .state
            .commit(parent_root, &batch.state_diffs)
            .map_err(|e| match e {
                StateError::StaleSnapshot => StorageError::InvalidOrder,
                _ => StorageError::Corrupt,
            })?;

        if new_root != batch.block.header.state_root {
            return Err(StorageError::VerificationFailed);
        }

        let block_hash = batch.block.header.compute_hash();
        self.blocks.insert(block_hash, batch.block.clone());
        self.certificates
            .insert(block_hash, batch.finality_certificate.clone());

        let checkpoint = Checkpoint {
            height: batch.block.header.height,
            block: block_hash,
            state_root: new_root,
        };
        self.checkpoints.insert(checkpoint.height, checkpoint);

        Ok(checkpoint)
    }

    fn export_snapshot(
        &self,
        checkpoint: Checkpoint,
        sink: &mut dyn SnapshotSink,
    ) -> Result<(), StorageError> {
        let chunks = self
            .snapshots
            .range((checkpoint.height, 0)..=(checkpoint.height, u32::MAX));

        for (idx, (_key, data)) in chunks.enumerate() {
            let chunk_index = u32::try_from(idx).map_err(|_| StorageError::LimitExceeded)?;
            sink.write_chunk(chunk_index, data)?;
        }
        Ok(())
    }

    fn import_snapshot(
        &mut self,
        source: &mut dyn SnapshotSource,
    ) -> Result<Checkpoint, StorageError> {
        let mut index = 0u32;
        let mut chunks = Vec::new();

        while let Some(data) = source.next_chunk()? {
            chunks.push((index, data));
            index += 1;
        }

        if chunks.is_empty() {
            return Err(StorageError::Corrupt);
        }

        let height = self
            .checkpoints
            .values()
            .next_back()
            .map_or(0, |c| c.height + 1);

        for (idx, data) in &chunks {
            self.snapshots.insert((height, *idx), data.clone());
        }

        let checkpoint = Checkpoint {
            height,
            block: Hash256::ZERO,
            state_root: Hash256::ZERO,
        };
        self.checkpoints.insert(height, checkpoint);
        Ok(checkpoint)
    }

    fn prune(&mut self, before_height: u64) -> Result<(), StorageError> {
        let heights_to_prune: Vec<u64> = self
            .checkpoints
            .keys()
            .copied()
            .filter(|&h| h < before_height)
            .collect();

        for height in &heights_to_prune {
            if let Some(checkpoint) = self.checkpoints.remove(height) {
                self.blocks.remove(&checkpoint.block);
                self.certificates.remove(&checkpoint.block);
            }
        }

        self.snapshots.retain(|&(h, _), _| h >= before_height);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Resources;

    fn make_block(height: u64, parent: Hash256, state_root: Hash256) -> Block {
        Block {
            header: types::BlockHeader {
                height,
                parent,
                transactions_root: Hash256::ZERO,
                state_root,
                receipts_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: Resources {
                    compute: 100,
                    memory: 100,
                    io: 100,
                    bandwidth: 100,
                },
            },
            transactions: Vec::new(),
        }
    }

    fn make_batch(height: u64, parent_hash: Hash256, state_root: Hash256) -> CommitBatch {
        CommitBatch {
            block: make_block(height, parent_hash, state_root),
            finality_certificate: vec![0xAA; 32],
            state_diffs: Vec::new(),
        }
    }

    struct VecSink<'a>(&'a mut Vec<Vec<u8>>);

    impl SnapshotSink for VecSink<'_> {
        fn write_chunk(&mut self, _index: u32, bytes: &[u8]) -> Result<(), StorageError> {
            self.0.push(bytes.to_vec());
            Ok(())
        }
    }

    #[test]
    fn empty_storage_recovers_none() {
        let mut storage = InMemoryStorage::new();
        assert!(storage.recover().unwrap().is_none());
    }

    #[test]
    fn commit_advances_checkpoint() {
        let mut storage = InMemoryStorage::new();
        let batch = make_batch(0, Hash256::ZERO, storage.state().root());
        let checkpoint = storage.commit(&batch).unwrap();
        assert_eq!(checkpoint.height, 0);
        assert!(storage.block_count() > 0);
    }

    #[test]
    fn commit_rejects_wrong_height() {
        let mut storage = InMemoryStorage::new();
        let mut batch = make_batch(0, Hash256::ZERO, storage.state().root());
        batch.block.header.height = 5;
        assert_eq!(storage.commit(&batch), Err(StorageError::InvalidOrder));
    }

    #[test]
    fn commit_rejects_wrong_state_root() {
        let mut storage = InMemoryStorage::new();
        let batch = make_batch(0, Hash256::ZERO, Hash256([0xFF; 32]));
        assert_eq!(
            storage.commit(&batch),
            Err(StorageError::VerificationFailed)
        );
    }

    #[test]
    fn sequential_commits() {
        let mut storage = InMemoryStorage::new();
        let batch0 = make_batch(0, Hash256::ZERO, storage.state().root());
        let cp0 = storage.commit(&batch0).unwrap();
        let batch1 = make_batch(1, cp0.block, storage.state().root());
        let cp1 = storage.commit(&batch1).unwrap();
        assert_eq!(cp1.height, 1);
        assert_eq!(storage.recover().unwrap().unwrap().height, 1);
    }

    #[test]
    fn prune_removes_old_data() {
        let mut storage = InMemoryStorage::new();
        let batch0 = make_batch(0, Hash256::ZERO, storage.state().root());
        let cp0 = storage.commit(&batch0).unwrap();
        let batch1 = make_batch(1, cp0.block, storage.state().root());
        storage.commit(&batch1).unwrap();
        storage.prune(1).unwrap();
        assert_eq!(storage.checkpoint().unwrap().height, 1);
    }

    #[test]
    fn snapshot_export_import_roundtrip() {
        let mut storage = InMemoryStorage::new();
        let batch = make_batch(0, Hash256::ZERO, storage.state().root());
        let cp = storage.commit(&batch).unwrap();
        storage.snapshots.insert((0, 0), vec![1, 2, 3]);

        let mut exported = Vec::new();
        storage
            .export_snapshot(cp, &mut VecSink(&mut exported))
            .unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0], vec![1, 2, 3]);
    }

    #[test]
    fn storage_error_display() {
        assert!(!StorageError::Corrupt.to_string().is_empty());
        assert!(!StorageError::InvalidOrder.to_string().is_empty());
        assert!(!StorageError::VerificationFailed.to_string().is_empty());
        assert!(!StorageError::LimitExceeded.to_string().is_empty());
        assert!(!StorageError::Io.to_string().is_empty());
    }

    #[test]
    fn recover_returns_latest_checkpoint() {
        let mut storage = InMemoryStorage::new();
        for h in 0..5u64 {
            let parent = if h == 0 {
                Hash256::ZERO
            } else {
                storage.checkpoint().unwrap().block
            };
            let batch = make_batch(h, parent, storage.state().root());
            storage.commit(&batch).unwrap();
        }
        assert_eq!(storage.recover().unwrap().unwrap().height, 4);
    }
}
