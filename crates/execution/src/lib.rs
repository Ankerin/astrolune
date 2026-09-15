// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic parallel transaction scheduling and execution.
//!
//! This crate provides:
//! - An `ExecutionScheduler` for building canonical execution plans
//! - A `SimpleExecutor` that validates, executes, and commits transactions
//! - The `TransactionOutput` type linking execution results to state diffs

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use state::{StateDatabase, StateDiff, StateError, StateLease};
use transaction::{BasicValidator, TransactionLane, TransactionValidator, ValidationContext};
use types::{ExecutionReceipt, Hash256, Transaction};

/// A conflict-free set of transactions that may execute concurrently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionWave {
    /// Original transaction indexes in deterministic order.
    pub transaction_indexes: Vec<usize>,
}

/// A deterministic execution plan containing one or more lanes and waves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPlan {
    /// Waves execute sequentially; transactions inside a wave may run in parallel.
    pub waves: Vec<ExecutionWave>,
}

/// Workload lane used for admission and resource isolation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExecutionLane {
    /// Ordinary account transfers.
    Payments,
    /// Rust smart-contract calls.
    Contracts,
    /// Consensus-governed system operations.
    System,
}

impl From<TransactionLane> for ExecutionLane {
    fn from(lane: TransactionLane) -> Self {
        match lane {
            TransactionLane::Payments => Self::Payments,
            TransactionLane::Contracts => Self::Contracts,
            TransactionLane::System => Self::System,
        }
    }
}

/// Schedules declared and predicted state accesses.
pub trait ExecutionScheduler {
    /// Builds a canonical plan. Predictions may improve placement, but validators
    /// must derive the same fallback ordering when predictions are absent or wrong.
    fn plan(&self, transactions: &[Transaction]) -> ExecutionPlan;

    /// Reserves declared keys for a transaction during its execution wave.
    fn lease(&self, transaction: &Transaction) -> StateLease;
}

/// Default scheduler that places each transaction in its own wave (serial execution).
pub struct SerialScheduler;

impl ExecutionScheduler for SerialScheduler {
    fn plan(&self, transactions: &[Transaction]) -> ExecutionPlan {
        let waves = (0..transactions.len())
            .map(|i| ExecutionWave {
                transaction_indexes: vec![i],
            })
            .collect();
        ExecutionPlan { waves }
    }

    fn lease(&self, transaction: &Transaction) -> StateLease {
        use state::AccessMode;
        let requests = transaction
            .access_list
            .iter()
            .map(|key| state::AccessRequest {
                key: key.clone(),
                mode: AccessMode::Write,
            })
            .collect();
        StateLease { requests }
    }
}

/// Result of one transaction before deferred state commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionOutput {
    /// State updates generated against an immutable snapshot.
    pub diff: StateDiff,
    /// Canonical receipt.
    pub receipt: ExecutionReceipt,
    /// Actual keys read and written, used to validate optimistic execution.
    pub observed_lease: StateLease,
}

/// Execution and scheduling failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// Contract code or its artifact is invalid.
    InvalidContract,
    /// Actual access exceeded the declared lease.
    UndeclaredStateAccess,
    /// Resource metering stopped execution.
    ResourceLimit,
    /// Optimistic outputs conflict and require canonical replay.
    Conflict,
    /// Arithmetic, memory, or host behavior trapped deterministically.
    Trap,
    /// Transaction validation failed.
    TransactionValidation(transaction::TransactionError),
    /// State database error.
    State(StateError),
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContract => write!(f, "invalid contract"),
            Self::UndeclaredStateAccess => write!(f, "undeclared state access"),
            Self::ResourceLimit => write!(f, "resource limit exceeded"),
            Self::Conflict => write!(f, "execution conflict"),
            Self::Trap => write!(f, "deterministic trap"),
            Self::TransactionValidation(e) => write!(f, "transaction validation: {e}"),
            Self::State(e) => write!(f, "state error: {e}"),
        }
    }
}

impl std::error::Error for ExecutionError {}

impl From<transaction::TransactionError> for ExecutionError {
    fn from(e: transaction::TransactionError) -> Self {
        Self::TransactionValidation(e)
    }
}

impl From<StateError> for ExecutionError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}

/// Configuration for the simple executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorConfig {
    /// Expected chain identifier for transaction validation.
    pub chain_id: u32,
    /// Current block height for expiry checks.
    pub next_height: u64,
    /// Maximum transaction size in bytes.
    pub max_transaction_bytes: usize,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            chain_id: 7,
            next_height: 1,
            max_transaction_bytes: 1024 * 1024, // 1 MiB
        }
    }
}

/// A simple single-threaded executor that validates and executes transactions
/// sequentially, committing state diffs after each transaction.
pub struct SimpleExecutor<'a, DB: StateDatabase> {
    database: &'a mut DB,
    validator: BasicValidator,
    config: ExecutorConfig,
}

impl<'a, DB: StateDatabase> SimpleExecutor<'a, DB> {
    /// Creates a new executor with the given database, validator, and config.
    pub fn new(database: &'a mut DB, validator: BasicValidator, config: ExecutorConfig) -> Self {
        Self {
            database,
            validator,
            config,
        }
    }

    /// Executes a block of transactions against the current state.
    ///
    /// Returns the transaction outputs in order and the new state root.
    pub fn execute_block(
        &mut self,
        transactions: &[Transaction],
        parent_root: Hash256,
    ) -> Result<(Vec<TransactionOutput>, Hash256), ExecutionError> {
        let context = ValidationContext {
            chain_id: self.config.chain_id,
            next_height: self.config.next_height,
            max_transaction_bytes: self.config.max_transaction_bytes,
        };

        let mut outputs = Vec::with_capacity(transactions.len());

        for tx in transactions {
            // Validate
            let validated = self.validator.validate(tx.clone(), context)?;

            // Take a snapshot at the current root (used for read access in real execution)
            let _snapshot = self.database.snapshot()?;

            // Build a simple diff: put the payload under a key derived from tx id
            let mut diff = StateDiff::new();
            let key = types::StateKey::new(format!("tx:{}", validated.id).into_bytes())
                .ok_or(ExecutionError::InvalidContract)?;

            // For payments, the diff is a simple record; for contracts, execution
            // would produce a more complex diff. Here we record the transaction.
            diff.put(key, validated.transaction.payload.clone());

            // Record actual resources used (equal to limit for this baseline)
            let resources = validated.transaction.resource_limit;

            let receipt = ExecutionReceipt {
                transaction: validated.id,
                succeeded: true,
                resources,
                output_root: diff.compute_hash(),
            };

            let observed_lease = StateLease {
                requests: validated
                    .transaction
                    .access_list
                    .iter()
                    .map(|k| state::AccessRequest {
                        key: k.clone(),
                        mode: state::AccessMode::Write,
                    })
                    .collect(),
            };

            outputs.push(TransactionOutput {
                diff,
                receipt,
                observed_lease,
            });
        }

        // Commit all diffs in one batch
        let diffs: Vec<StateDiff> = outputs.iter().map(|o| o.diff.clone()).collect();
        let new_root = self.database.commit(parent_root, &diffs)?;

        Ok((outputs, new_root))
    }
}

/// Extension trait for computing a simple hash of a diff.
trait DiffHash {
    /// Computes a deterministic hash of this diff.
    fn compute_hash(&self) -> Hash256;
}

impl DiffHash for StateDiff {
    fn compute_hash(&self) -> Hash256 {
        let mut hash = Hash256::ZERO;
        for change in &self.changes {
            match change {
                state::StateChange::Put(key, value) => {
                    let mut data = Vec::with_capacity(1 + key.len() + value.len());
                    data.push(0x01); // put tag
                    data.extend_from_slice(key.as_bytes());
                    data.extend_from_slice(value);
                    let mut h = [0u8; 32];
                    for (i, byte) in data.iter().enumerate() {
                        h[i % 32] ^= byte;
                    }
                    hash = hash.xor(Hash256(h));
                }
                state::StateChange::Delete(key) => {
                    let mut data = Vec::with_capacity(1 + key.len());
                    data.push(0x00); // delete tag
                    data.extend_from_slice(key.as_bytes());
                    let mut h = [0u8; 32];
                    for (i, byte) in data.iter().enumerate() {
                        h[i % 32] ^= byte;
                    }
                    hash = hash.xor(Hash256(h));
                }
            }
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use state::InMemoryState;
    use transaction::{AccountState, BasicValidator};
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

    fn config() -> ExecutorConfig {
        ExecutorConfig {
            chain_id: 7,
            next_height: 1,
            max_transaction_bytes: 1024,
        }
    }

    // -- SerialScheduler tests --

    #[test]
    fn serial_scheduler_plan_one_per_wave() {
        let scheduler = SerialScheduler;
        let txs = vec![make_tx(0, vec![]), make_tx(0, vec![]), make_tx(0, vec![])];
        let plan = scheduler.plan(&txs);
        assert_eq!(plan.waves.len(), 3);
        assert_eq!(plan.waves[0].transaction_indexes, vec![0]);
        assert_eq!(plan.waves[1].transaction_indexes, vec![1]);
        assert_eq!(plan.waves[2].transaction_indexes, vec![2]);
    }

    #[test]
    fn serial_scheduler_lease_from_access_list() {
        use state::AccessMode;
        let scheduler = SerialScheduler;
        let mut tx = make_tx(0, vec![]);
        tx.access_list = vec![types::StateKey(vec![1, 2]), types::StateKey(vec![3, 4])];
        let lease = scheduler.lease(&tx);
        assert_eq!(lease.requests.len(), 2);
        assert!(lease.covers(&types::StateKey(vec![1, 2]), AccessMode::Write));
        assert!(lease.covers(&types::StateKey(vec![3, 4]), AccessMode::Write));
    }

    // -- ExecutionLane conversion --

    #[test]
    fn lane_conversion() {
        assert_eq!(
            ExecutionLane::from(TransactionLane::Payments),
            ExecutionLane::Payments
        );
        assert_eq!(
            ExecutionLane::from(TransactionLane::Contracts),
            ExecutionLane::Contracts
        );
        assert_eq!(
            ExecutionLane::from(TransactionLane::System),
            ExecutionLane::System
        );
    }

    // -- SimpleExecutor tests --

    #[test]
    fn executor_empty_block() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        let (outputs, root1) = executor.execute_block(&[], root0).unwrap();
        assert!(outputs.is_empty());
        assert_eq!(root0, root1);
    }

    #[test]
    fn executor_single_transaction() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        let txs = vec![make_tx(0, vec![1, 2, 3])];
        let (outputs, root1) = executor.execute_block(&txs, root0).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_ne!(root0, root1);
        assert!(outputs[0].receipt.succeeded);
    }

    #[test]
    fn executor_multiple_transactions_sequential() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 10_000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        let txs = vec![
            make_tx(0, vec![1]),
            make_tx(0, vec![2]),
            make_tx(0, vec![3]),
        ];
        let (outputs, _root) = executor.execute_block(&txs, root0).unwrap();
        assert_eq!(outputs.len(), 3);
        for output in &outputs {
            assert!(output.receipt.succeeded);
        }
    }

    #[test]
    fn executor_rejects_invalid_transaction() {
        let validator = BasicValidator::empty(); // no accounts
        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        // Nonce 1 fails for unknown account
        let txs = vec![make_tx(1, vec![])];
        let result = executor.execute_block(&txs, root0);
        assert!(result.is_err());
    }

    #[test]
    fn executor_rejects_wrong_chain() {
        let validator = BasicValidator::empty();
        let mut state = InMemoryState::new();
        let root0 = state.root();
        let config = ExecutorConfig {
            chain_id: 7,
            ..config()
        };
        let mut executor = SimpleExecutor::new(&mut state, validator, config);

        let mut tx = make_tx(0, vec![]);
        tx.chain_id = 99;
        tx.signature = [0xFF; 64];
        let txs = vec![tx];
        let result = executor.execute_block(&txs, root0);
        assert!(result.is_err());
    }

    #[test]
    fn executor_receipt_commitment_deterministic() {
        let mut accounts = std::collections::BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

        let txs = vec![make_tx(0, vec![1, 2, 3])];
        let (outputs, _) = executor.execute_block(&txs, root0).unwrap();
        let c1 = outputs[0].receipt.commitment();
        let c2 = outputs[0].receipt.commitment();
        assert_eq!(c1, c2);
    }

    // -- Error display tests --

    #[test]
    fn execution_error_display() {
        let errors = [
            ExecutionError::InvalidContract,
            ExecutionError::UndeclaredStateAccess,
            ExecutionError::ResourceLimit,
            ExecutionError::Conflict,
            ExecutionError::Trap,
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn execution_error_from_transaction_error() {
        let e = ExecutionError::from(transaction::TransactionError::WrongChain);
        assert!(matches!(e, ExecutionError::TransactionValidation(_)));
    }

    #[test]
    fn execution_error_from_state_error() {
        let e = ExecutionError::from(StateError::StaleSnapshot);
        assert!(matches!(e, ExecutionError::State(_)));
    }
}
