// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Verification-first synchronization of finalized chain data.

#![forbid(unsafe_code)]

use types::{Block, BlockHeader, Hash256};

/// Supported synchronization strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncMode {
    /// Verify every block from a trusted genesis.
    FullReplay,
    /// Import a verified snapshot and replay later blocks.
    Snapshot,
}

/// Local synchronization progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncStatus {
    /// Selected strategy.
    pub mode: SyncMode,
    /// Highest locally verified height.
    pub verified_height: u64,
    /// Current remote finalized target.
    pub target_height: u64,
}

/// Snapshot metadata verified before any state becomes canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotManifest {
    /// Snapshot block height.
    pub height: u64,
    /// Finalized block identifier.
    pub block: Hash256,
    /// Expected imported state root.
    pub state_root: Hash256,
    /// Content commitment for snapshot chunks.
    pub chunks_root: Hash256,
}

/// Verifier used by a synchronization state machine.
pub trait SyncVerifier {
    /// Verifies an ordered finalized header segment.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError`] on broken linkage, invalid finality, or bounds.
    fn verify_headers(&self, headers: &[BlockHeader]) -> Result<(), SyncError>;

    /// Verifies a complete block against its header and finalized parent.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError`] when commitments or finality do not match.
    fn verify_block(&self, block: &Block) -> Result<(), SyncError>;

    /// Verifies snapshot metadata before importing chunks into staging storage.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError`] for an unfinalized, incompatible, or malformed snapshot.
    fn verify_snapshot(&self, manifest: SnapshotManifest) -> Result<(), SyncError>;
}

/// Synchronization failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    /// Requested range or response exceeds configured limits.
    LimitExceeded,
    /// Header ancestry is discontinuous.
    InvalidAncestry,
    /// Required finality proof is invalid.
    InvalidFinality,
    /// Block or snapshot commitment does not match its content.
    CommitmentMismatch,
    /// Peer returned incompatible chain data.
    IncompatibleChain,
}
