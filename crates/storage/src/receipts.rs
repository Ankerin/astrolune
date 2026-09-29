// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Receipt publication payloads and bounded, rebuildable transaction lookup indexes.

use crate::StorageError;
use codec::{CanonicalDecode, Decoder};
use state::StateValueProof;
use std::collections::{BTreeMap, VecDeque};
use types::{Block, BlockHeader, ExecutionReceipt, Hash256};

/// Maximum receipt count in one retained block.
pub const MAX_BLOCK_RECEIPTS: usize = 16_384;
/// Maximum recent transaction IDs retained in the optional lookup index.
pub const MAX_INDEXED_TRANSACTIONS: usize = 100_000;
/// Bound on encoded receipts plus the small genesis membership witness.
pub const MAX_RECEIPTS_BYTES: usize = MAX_BLOCK_RECEIPTS * 97 + 4096;

/// Execution data published atomically alongside the finalized block and state delta.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockEffects {
    /// Receipts in exact transaction order.
    pub receipts: Vec<ExecutionReceipt>,
    /// Post-state witness binding this block to its independently trusted genesis.
    pub genesis: StateValueProof,
}
impl BlockEffects {
    /// Checks all receipt IDs, their commitment, resource totals and genesis membership.
    pub fn validate(&self, block: &Block) -> Result<(), StorageError> {
        if self.receipts.len() != block.transactions.len()
            || self.receipts.len() > MAX_BLOCK_RECEIPTS
            || self
                .receipts
                .iter()
                .zip(&block.transactions)
                .any(|(receipt, tx)| receipt.transaction != transaction::compute_tx_id(tx))
        {
            return Err(StorageError::VerificationFailed);
        }
        self.validate_header(&block.header)
    }

    /// Checks the complete receipt commitment and genesis proof without block bodies.
    pub fn validate_header(&self, header: &BlockHeader) -> Result<(), StorageError> {
        if self.receipts.len() > MAX_BLOCK_RECEIPTS {
            return Err(StorageError::LimitExceeded);
        }
        let hashes: Vec<_> = self
            .receipts
            .iter()
            .map(ExecutionReceipt::commitment)
            .collect();
        let mut resources = types::Resources::ZERO;
        for receipt in &self.receipts {
            resources = resources
                .checked_add(receipt.resources)
                .ok_or(StorageError::VerificationFailed)?;
        }
        if crypto::compute_receipts_root(&hashes) != header.receipts_root
            || !resources.fits_in(header.capacity)
            || self
                .genesis
                .verify(header.state_root, &genesis::genesis_key())
                .map_err(|_| StorageError::VerificationFailed)?
                .is_none_or(|value| value.len() != 32)
        {
            return Err(StorageError::VerificationFailed);
        }
        Ok(())
    }

    /// Encodes bounded canonical receipts and a bounded membership proof.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StorageError> {
        if self.receipts.len() > MAX_BLOCK_RECEIPTS {
            return Err(StorageError::LimitExceeded);
        }
        let proof = self
            .genesis
            .to_bytes()
            .map_err(|_| StorageError::LimitExceeded)?;
        if proof.len() > 2048 {
            return Err(StorageError::LimitExceeded);
        }
        let mut bytes = b"ALEFFECT".to_vec();
        bytes.extend_from_slice(
            &u32::try_from(self.receipts.len())
                .map_err(|_| StorageError::LimitExceeded)?
                .to_le_bytes(),
        );
        for receipt in &self.receipts {
            bytes.extend_from_slice(&receipt.canonical_bytes());
        }
        bytes.extend_from_slice(
            &u32::try_from(proof.len())
                .map_err(|_| StorageError::LimitExceeded)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&proof);
        Ok(bytes)
    }

    /// Decodes exact lengths without authenticating finality or receipt contents.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        fn decode(bytes: &[u8]) -> Result<BlockEffects, codec::DecodeError> {
            let mut decoder = Decoder::new(bytes);
            if decoder.read_exact(8)? != b"ALEFFECT" {
                return Err(codec::DecodeError::Unsupported);
            }
            let count = decoder.read_u32()? as usize;
            if count > MAX_BLOCK_RECEIPTS {
                return Err(codec::DecodeError::LimitExceeded);
            }
            let data = decoder.read_exact(count * 97)?;
            let receipts = data
                .as_chunks::<97>()
                .0
                .iter()
                .map(|chunk| ExecutionReceipt::decode(chunk))
                .collect::<Result<Vec<_>, _>>()?;
            let length = decoder.read_u32()? as usize;
            if length > 2048 {
                return Err(codec::DecodeError::LimitExceeded);
            }
            let genesis = StateValueProof::from_bytes(decoder.read_exact(length)?)
                .map_err(|_| codec::DecodeError::NonCanonical)?;
            decoder.finish()?;
            Ok(BlockEffects { receipts, genesis })
        }
        if bytes.len() > MAX_RECEIPTS_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        decode(bytes).map_err(|_| StorageError::Corrupt)
    }
}

/// Receipt data read from one immutable finalized storage record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredReceipts {
    /// Certified block header.
    pub header: BlockHeader,
    /// Canonical precommit certificate.
    pub certificate: Vec<u8>,
    /// Ordered receipts and the same-state genesis witness.
    pub effects: BlockEffects,
}

#[derive(Clone, Debug, Default)]
pub(super) struct RecentTransactions {
    by_id: BTreeMap<Hash256, (u64, usize)>,
    order: VecDeque<(Hash256, u64, usize)>,
}
impl RecentTransactions {
    pub(super) fn insert(&mut self, block: &Block) {
        for (index, tx) in block.transactions.iter().enumerate() {
            let id = transaction::compute_tx_id(tx);
            self.by_id.insert(id, (block.header.height, index));
            self.order.push_back((id, block.header.height, index));
            while self.order.len() > MAX_INDEXED_TRANSACTIONS {
                if let Some((id, height, index)) = self.order.pop_front()
                    && self.by_id.get(&id) == Some(&(height, index))
                {
                    self.by_id.remove(&id);
                }
            }
        }
    }
    pub(super) fn get(&self, id: Hash256) -> Option<(u64, usize)> {
        self.by_id.get(&id).copied()
    }
    pub(super) fn prune(&mut self, before: u64) {
        self.order.retain(|(_, height, _)| *height >= before);
        self.by_id.retain(|_, (height, _)| *height >= before);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_index_evicts_old_positions_without_erasing_a_newer_duplicate() {
        let tx = types::Transaction {
            version: 1,
            chain_id: 7,
            sender: types::Address([1; 32]),
            nonce: 0,
            expires_at: u64::MAX,
            lane: types::TransactionLane::Payments,
            resource_prices: types::Resources::ZERO,
            resource_limit: types::Resources::ZERO,
            access_list: vec![],
            payload: vec![],
            signature: [0; 64],
        };
        let first = transaction::compute_tx_id(&tx);
        let mut block = Block {
            header: BlockHeader {
                height: 0,
                parent: Hash256::ZERO,
                state_root: Hash256::ZERO,
                receipts_root: Hash256::ZERO,
                transactions_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: types::Resources::ZERO,
            },
            transactions: vec![tx],
        };
        let mut index = RecentTransactions::default();
        index.insert(&block);
        block.header.height = 1;
        index.insert(&block);
        for height in 2..=MAX_INDEXED_TRANSACTIONS as u64 {
            block.header.height = height;
            block.transactions[0].nonce = height;
            index.insert(&block);
        }
        assert_eq!(index.get(first), Some((1, 0)));
        assert_eq!(index.order.len(), MAX_INDEXED_TRANSACTIONS);
        assert_eq!(index.by_id.len(), MAX_INDEXED_TRANSACTIONS);
        block.header.height += 1;
        block.transactions[0].nonce += 1;
        let newest = transaction::compute_tx_id(&block.transactions[0]);
        index.insert(&block);
        assert_eq!(index.get(first), None);
        index.prune(block.header.height);
        assert_eq!(index.get(newest), Some((block.header.height, 0)));
        assert_eq!(index.order.len(), 1);
        assert_eq!(index.by_id.len(), 1);
    }
}
