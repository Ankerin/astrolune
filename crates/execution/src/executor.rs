// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Transaction executor, configuration, and output types.

use state::{StateDatabase, StateDiff, StateLease};
use transaction::{BasicValidator, TransactionValidator, ValidationContext};
use types::{ExecutionReceipt, Hash256, Transaction};

use crate::error::ExecutionError;

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
            max_transaction_bytes: 1024 * 1024,
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
            let validated = self.validator.validate(tx.clone(), context)?;

            let _snapshot = self.database.snapshot()?;

            let mut diff = StateDiff::new();
            let key = types::StateKey::new(format!("tx:{}", validated.id).into_bytes())
                .ok_or(ExecutionError::InvalidContract)?;

            diff.put(key, validated.transaction.payload.clone());

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
                    data.push(0x01);
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
                    data.push(0x00);
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
        let validator = BasicValidator::empty();
        let mut state = InMemoryState::new();
        let root0 = state.root();
        let mut executor = SimpleExecutor::new(&mut state, validator, config());

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
}
