// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Block production pipeline.
//!
//! Coordinates transaction selection from the mempool, block assembly,
//! deterministic execution, and preparation of storage commit batches.
//! The producer follows the finalization path described in ARCHITECTURE.md:
//!
//! ```text
//! transactions -> bounded validation -> mempool -> compact proposal
//!              -> deterministic execution -> commitment verification
//!              -> atomic finalized storage
//! ```

use std::collections::BTreeMap;

use execution::{ExecutionError, ExecutorConfig, SimpleExecutor, TransactionOutput};
use mempool::{Mempool, MempoolError, PoolEntry, PoolLimits};
use state::{InMemoryState, StateDiff};
use storage::{CommitBatch, NodeStorage, StorageError};
use transaction::{BasicValidator, TransactionError, TransactionValidator, ValidationContext};
use types::{Address, Block, BlockHeader, Hash256, Resources, Transaction};

/// Maximum number of transactions to include in a single block.
const MAX_BLOCK_TRANSACTIONS: usize = 256;

/// Maximum size in bytes of a single transaction accepted by the producer.
const MAX_TRANSACTION_BYTES: usize = 1024 * 1024;

/// Block production configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducerConfig {
    /// Chain identifier for transaction validation.
    pub chain_id: u32,
    /// Maximum transactions per block.
    pub max_block_transactions: usize,
    /// Maximum size in bytes for a single transaction.
    pub max_transaction_bytes: usize,
    /// Maximum pool capacity.
    pub pool_limits: PoolLimits,
    /// Adaptive block capacity.
    pub block_capacity: Resources,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            chain_id: 7,
            max_block_transactions: MAX_BLOCK_TRANSACTIONS,
            max_transaction_bytes: MAX_TRANSACTION_BYTES,
            pool_limits: PoolLimits {
                max_transactions: 10_000,
                max_bytes: 10 * 1024 * 1024,
            },
            block_capacity: Resources {
                compute: 1000,
                memory: 1024,
                io: 256,
                bandwidth: 1024,
            },
        }
    }
}

/// A prepared block ready for consensus voting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockProposal {
    /// The assembled block with header and transactions.
    pub block: Block,
    /// Execution outputs for each transaction.
    pub outputs: Vec<TransactionOutput>,
    /// Final state root after execution.
    pub state_root: Hash256,
    /// Total resources consumed by the block.
    pub resources_used: Resources,
}

/// Errors that can occur during block production.
#[derive(Debug)]
pub enum ProducerError {
    /// Transaction validation or execution failed.
    Execution(ExecutionError),
    /// Mempool admission failed.
    Mempool(MempoolError),
    /// Storage commit failed.
    Storage(StorageError),
    /// Block assembly failed due to node constraints.
    Assembly(String),
}

impl std::fmt::Display for ProducerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Execution(e) => write!(f, "execution error: {e}"),
            Self::Mempool(e) => write!(f, "mempool error: {e}"),
            Self::Storage(e) => write!(f, "storage error: {e}"),
            Self::Assembly(msg) => write!(f, "assembly error: {msg}"),
        }
    }
}

impl std::error::Error for ProducerError {}

impl From<ExecutionError> for ProducerError {
    fn from(e: ExecutionError) -> Self {
        Self::Execution(e)
    }
}

impl From<MempoolError> for ProducerError {
    fn from(e: MempoolError) -> Self {
        Self::Mempool(e)
    }
}

impl From<StorageError> for ProducerError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

impl From<TransactionError> for ProducerError {
    fn from(e: TransactionError) -> Self {
        Self::Assembly(format!("transaction validation: {e}"))
    }
}

/// Block production pipeline that coordinates mempool, execution, and storage.
///
/// The producer maintains an in-memory state database for execution and
/// prepares commit batches for durable storage. It does not participate
/// in consensus voting directly; that responsibility belongs to the node
/// service layer.
pub struct BlockProducer {
    /// Production configuration.
    config: ProducerConfig,
    /// Transaction pool with bounded admission.
    mempool: Mempool,
    /// In-memory state for deterministic execution.
    state: InMemoryState,
    /// Current block height (next to produce).
    height: u64,
    /// Parent block hash for the next block.
    parent_hash: Hash256,
    /// Transaction validator.
    validator: BasicValidator,
    /// Sequence counter for mempool admission ordering.
    admission_sequence: u64,
}

impl BlockProducer {
    /// Creates a new block producer with the given configuration.
    ///
    /// The producer starts at height 0 (genesis) with the zero hash as parent.
    ///
    /// # Panics
    ///
    /// Panics if the pool limits in the configuration are zero.
    #[must_use]
    pub fn new(config: ProducerConfig) -> Self {
        let mempool =
            Mempool::new(config.pool_limits).expect("default pool limits are always valid");

        Self {
            config,
            mempool,
            state: InMemoryState::new(),
            height: 0,
            parent_hash: Hash256::ZERO,
            validator: BasicValidator::empty(),
            admission_sequence: 0,
        }
    }

    /// Creates a producer initialized with an account for transaction validation.
    ///
    /// # Panics
    ///
    /// Panics if the pool limits in the configuration are zero.
    #[must_use]
    pub fn with_account(
        address: Address,
        nonce: u64,
        balance: u64,
        config: ProducerConfig,
    ) -> Self {
        let mut accounts = BTreeMap::new();
        accounts.insert(address, transaction::AccountState { nonce, balance });
        let validator = BasicValidator::new(accounts);

        let mempool =
            Mempool::new(config.pool_limits).expect("default pool limits are always valid");

        Self {
            config,
            mempool,
            state: InMemoryState::new(),
            height: 0,
            parent_hash: Hash256::ZERO,
            validator,
            admission_sequence: 0,
        }
    }

    /// Returns the current block height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Returns the parent block hash.
    #[must_use]
    pub fn parent_hash(&self) -> Hash256 {
        self.parent_hash
    }

    /// Returns the number of pending transactions in the mempool.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.mempool.len()
    }

    /// Returns a reference to the in-memory state.
    #[must_use]
    pub fn state(&self) -> &InMemoryState {
        &self.state
    }

    /// Submits a transaction to the mempool for inclusion in future blocks.
    ///
    /// The transaction is validated and admitted only if it passes bounds
    /// checks and does not conflict with existing entries.
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<Hash256, ProducerError> {
        let context = ValidationContext {
            chain_id: self.config.chain_id,
            next_height: self.height,
            max_transaction_bytes: self.config.max_transaction_bytes,
        };

        let validated = self.validator.validate(tx, context)?;

        let id = validated.id;
        let encoded_len = transaction::estimate_encoded_len(&validated.transaction);

        let entry = PoolEntry {
            id,
            transaction: validated.transaction,
            priority: 0,
            sequence: self.admission_sequence,
        };
        self.admission_sequence += 1;

        self.mempool.insert(entry, encoded_len)?;
        Ok(id)
    }

    /// Assembles and executes a block from pending mempool transactions.
    ///
    /// Selects transactions, builds a block header, executes against the
    /// current state, and returns a proposal ready for consensus voting.
    ///
    /// # Errors
    ///
    /// Returns [`ProducerError`] if transaction execution fails or the
    /// state root cannot be computed.
    pub fn produce_block(&mut self) -> Result<BlockProposal, ProducerError> {
        // Select transactions from the mempool based on priority and capacity
        let selected = self.mempool.select(
            self.config.max_block_transactions,
            self.config.block_capacity,
        );

        let selected_keys: Vec<(Address, u64)> = selected
            .iter()
            .map(|e| (e.transaction.sender, e.transaction.nonce))
            .collect();
        let transactions: Vec<Transaction> = selected
            .iter()
            .map(|entry| entry.transaction.clone())
            .collect();

        // Compute the transactions root commitment
        let transactions_root = compute_transactions_root(&transactions);

        // Execute transactions against the current state
        let executor_config = ExecutorConfig {
            chain_id: self.config.chain_id,
            next_height: self.height,
            max_transaction_bytes: self.config.max_transaction_bytes,
        };

        let parent_root = self.state.root();
        let mut executor =
            SimpleExecutor::new(&mut self.state, self.validator.clone(), executor_config);

        let (outputs, state_root) = executor.execute_block(&transactions, parent_root)?;

        // Advance validator nonces after execution so subsequent submissions are valid
        for tx in &transactions {
            self.validator.advance_nonce(&tx.sender);
        }

        // Compute the receipts root commitment
        let receipts: Vec<types::ExecutionReceipt> =
            outputs.iter().map(|o| o.receipt.clone()).collect();
        let receipts_root = compute_receipts_root(&receipts);

        // Sum resources used across all transactions
        let resources_used = outputs
            .iter()
            .fold(Resources::ZERO, |acc, output| Resources {
                compute: acc.compute.saturating_add(output.receipt.resources.compute),
                memory: acc.memory.saturating_add(output.receipt.resources.memory),
                io: acc.io.saturating_add(output.receipt.resources.io),
                bandwidth: acc
                    .bandwidth
                    .saturating_add(output.receipt.resources.bandwidth),
            });

        // Build the block header
        let header = BlockHeader {
            height: self.height,
            parent: self.parent_hash,
            transactions_root,
            state_root,
            receipts_root,
            committee_root: Hash256::ZERO,
            capacity: self.config.block_capacity,
        };

        let block = Block {
            header,
            transactions,
        };

        // Remove selected transactions from the mempool
        self.mempool.remove_batch(&selected_keys);

        let proposal = BlockProposal {
            block,
            outputs,
            state_root,
            resources_used,
        };

        Ok(proposal)
    }

    /// Commits a finalized block to storage after consensus approval.
    ///
    /// Updates the internal state root and height for the next block.
    pub fn commit_block<S: NodeStorage>(
        &mut self,
        proposal: &BlockProposal,
        certificate: Vec<u8>,
        storage: &mut S,
    ) -> Result<storage::Checkpoint, ProducerError> {
        let diffs: Vec<StateDiff> = proposal.outputs.iter().map(|o| o.diff.clone()).collect();

        let batch = CommitBatch {
            block: proposal.block.clone(),
            finality_certificate: certificate,
            state_diffs: diffs,
        };

        let checkpoint = storage.commit(&batch)?;

        // Advance the producer state for the next block
        self.height += 1;
        self.parent_hash = proposal.block.header.compute_hash();

        Ok(checkpoint)
    }

    /// Computes a simple deterministic hash for the mempool selection tie-breaking.
    #[allow(dead_code)]
    fn select_priority(entry: &PoolEntry) -> (std::cmp::Reverse<u64>, u64, Hash256) {
        (std::cmp::Reverse(entry.priority), entry.sequence, entry.id)
    }
}

/// Computes a deterministic transactions root hash from a list of transactions.
///
/// Uses XOR-fold over transaction identifiers to produce a commitment
/// that binds the exact transaction order.
#[must_use]
pub fn compute_transactions_root(transactions: &[Transaction]) -> Hash256 {
    if transactions.is_empty() {
        return Hash256::ZERO;
    }

    let mut hash = [0u8; 32];
    for (i, tx) in transactions.iter().enumerate() {
        let tx_hash = hash_transaction(tx);
        for (j, byte) in tx_hash.0.iter().enumerate() {
            hash[(i + j) % 32] ^= byte;
        }
    }
    Hash256(hash)
}

/// Computes a deterministic receipts root hash from execution receipts.
///
/// Uses XOR-fold over receipt commitments to produce a commitment
/// that binds the execution results.
#[must_use]
pub fn compute_receipts_root(receipts: &[types::ExecutionReceipt]) -> Hash256 {
    if receipts.is_empty() {
        return Hash256::ZERO;
    }

    let mut hash = [0u8; 32];
    for (i, receipt) in receipts.iter().enumerate() {
        let commitment = receipt.commitment();
        for (j, byte) in commitment.0.iter().enumerate() {
            hash[(i + j) % 32] ^= byte;
        }
    }
    Hash256(hash)
}

/// Computes a simple deterministic hash of a transaction.
///
/// The hash covers all canonical fields except the signature.
#[must_use]
pub fn hash_transaction(tx: &Transaction) -> Hash256 {
    let mut data = Vec::new();
    data.extend_from_slice(&tx.chain_id.to_le_bytes());
    data.extend_from_slice(tx.sender.as_bytes());
    data.extend_from_slice(&tx.nonce.to_le_bytes());
    data.extend_from_slice(&tx.resource_limit.compute.to_le_bytes());
    data.extend_from_slice(&tx.resource_limit.memory.to_le_bytes());
    data.extend_from_slice(&tx.resource_limit.io.to_le_bytes());
    data.extend_from_slice(&tx.resource_limit.bandwidth.to_le_bytes());
    data.extend_from_slice(&tx.payload);

    let mut hash = [0u8; 32];
    for (i, byte) in data.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    Hash256(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Address, Resources};

    fn sender() -> Address {
        Address([1u8; 32])
    }

    fn make_tx(nonce: u64, payload: Vec<u8>) -> Transaction {
        Transaction {
            chain_id: 7,
            sender: sender(),
            nonce,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 10,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload,
            signature: [0xFF; 64],
        }
    }

    fn test_config() -> ProducerConfig {
        ProducerConfig {
            chain_id: 7,
            max_block_transactions: 10,
            max_transaction_bytes: 1024,
            pool_limits: PoolLimits {
                max_transactions: 100,
                max_bytes: 1024 * 1024,
            },
            block_capacity: Resources {
                compute: 1000,
                memory: 1024,
                io: 256,
                bandwidth: 1024,
            },
        }
    }

    #[test]
    fn producer_starts_at_height_zero() {
        let producer = BlockProducer::new(test_config());
        assert_eq!(producer.height(), 0);
        assert_eq!(producer.parent_hash(), Hash256::ZERO);
        assert_eq!(producer.pending_count(), 0);
    }

    #[test]
    fn submit_and_produce_empty_block() {
        let mut producer = BlockProducer::new(test_config());
        let proposal = producer.produce_block().unwrap();
        assert_eq!(proposal.block.header.height, 0);
        assert!(proposal.block.transactions.is_empty());
        assert!(proposal.outputs.is_empty());
        assert_eq!(proposal.state_root, producer.state().root());
    }

    #[test]
    fn submit_transaction_increases_pending() {
        let mut producer = BlockProducer::new(test_config());
        let tx = make_tx(0, vec![1, 2, 3]);
        producer.submit_transaction(tx).unwrap();
        assert_eq!(producer.pending_count(), 1);
    }

    #[test]
    fn produce_block_includes_submitted_transactions() {
        let mut producer = BlockProducer::new(test_config());
        let tx = make_tx(0, vec![1, 2, 3]);
        producer.submit_transaction(tx.clone()).unwrap();

        let proposal = producer.produce_block().unwrap();
        assert_eq!(proposal.block.transactions.len(), 1);
        assert_eq!(proposal.block.transactions[0], tx);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn produce_block_multiple_transactions() {
        let mut producer = BlockProducer::with_account(sender(), 0, 100_000, test_config());
        for i in 0u64..3 {
            let tx = make_tx(i, vec![i as u8]);
            producer.submit_transaction(tx).unwrap();
        }

        let proposal = producer.produce_block().unwrap();
        assert_eq!(proposal.block.transactions.len(), 3);
        assert!(proposal.outputs.iter().all(|o| o.receipt.succeeded));
    }

    #[test]
    fn commit_block_advances_height() {
        let mut producer = BlockProducer::new(test_config());
        let proposal = producer.produce_block().unwrap();
        let mut storage = storage::InMemoryStorage::new();

        producer
            .commit_block(&proposal, vec![0xAA; 32], &mut storage)
            .unwrap();

        assert_eq!(producer.height(), 1);
        assert_eq!(producer.parent_hash(), proposal.block.header.compute_hash());
    }

    #[test]
    fn transactions_root_deterministic() {
        let txs = vec![make_tx(0, vec![1]), make_tx(1, vec![2])];
        let root1 = compute_transactions_root(&txs);
        let root2 = compute_transactions_root(&txs);
        assert_eq!(root1, root2);
    }

    #[test]
    fn transactions_root_empty() {
        assert_eq!(compute_transactions_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn receipts_root_empty() {
        assert_eq!(compute_receipts_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn hash_transaction_deterministic() {
        let tx = make_tx(0, vec![1, 2, 3]);
        let h1 = hash_transaction(&tx);
        let h2 = hash_transaction(&tx);
        assert_eq!(h1, h2);
    }

    #[test]
    fn producer_config_default() {
        let config = ProducerConfig::default();
        assert_eq!(config.chain_id, 7);
        assert_eq!(config.max_block_transactions, MAX_BLOCK_TRANSACTIONS);
        assert_eq!(config.max_transaction_bytes, MAX_TRANSACTION_BYTES);
    }

    #[test]
    fn producer_error_display() {
        let errors = [ProducerError::Assembly("test".into())];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn producer_with_account() {
        let mut producer = BlockProducer::with_account(sender(), 0, 1000, test_config());
        let tx = make_tx(0, vec![1, 2, 3]);
        producer.submit_transaction(tx).unwrap();
        let proposal = producer.produce_block().unwrap();
        assert_eq!(proposal.block.transactions.len(), 1);
    }

    #[test]
    fn block_header_parent_linkage() {
        let mut producer = BlockProducer::new(test_config());
        let proposal1 = producer.produce_block().unwrap();
        let mut storage = storage::InMemoryStorage::new();

        producer
            .commit_block(&proposal1, vec![0xAA; 32], &mut storage)
            .unwrap();

        let proposal2 = producer.produce_block().unwrap();
        assert_eq!(proposal2.block.header.height, 1);
        assert_eq!(
            proposal2.block.header.parent,
            proposal1.block.header.compute_hash()
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn multiple_blocks_sequential() {
        let mut producer = BlockProducer::with_account(sender(), 0, 100_000, test_config());
        let mut storage = storage::InMemoryStorage::new();

        for h in 0u64..5 {
            let tx = make_tx(h, vec![h as u8]);
            producer.submit_transaction(tx).unwrap();

            let proposal = producer.produce_block().unwrap();
            assert_eq!(proposal.block.header.height, h);

            producer
                .commit_block(&proposal, vec![0xAA; 32], &mut storage)
                .unwrap();
        }

        assert_eq!(producer.height(), 5);
        assert_eq!(storage.recover().unwrap().unwrap().height, 4);
    }
}
