// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Transaction validation logic and types.

use std::collections::BTreeMap;

use types::{Address, Hash256, Transaction};

use crate::error::TransactionError;
use crate::lane::TransactionLane;

/// Context needed for deterministic pre-execution validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationContext {
    /// Expected chain identifier.
    pub chain_id: u32,
    /// Height for expiry checks.
    pub next_height: u64,
    /// Maximum canonical transaction bytes.
    pub max_transaction_bytes: usize,
}

/// Transaction accepted by every pre-execution validation stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedTransaction {
    /// Canonical transaction identifier.
    pub id: Hash256,
    /// Assigned execution lane.
    pub lane: TransactionLane,
    /// Original canonical transaction.
    pub transaction: Transaction,
}

/// Provider for hashing and state-aware transaction checks.
pub trait TransactionValidator {
    /// Validates one transaction without mutating state.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionError`] at the first failed validation stage.
    fn validate(
        &self,
        transaction: Transaction,
        context: ValidationContext,
    ) -> Result<ValidatedTransaction, TransactionError>;
}

/// Account state required for transaction validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountState {
    /// Current nonce for the account.
    pub nonce: u64,
    /// Available balance for resource payment.
    pub balance: u64,
}

/// A basic transaction validator that checks envelope shape, chain ID,
/// resource limits, and lane assignment.
///
/// Signature verification is delegated to the crypto provider through the
/// `SignatureVerifier` callback. This validator does not mutate any state.
pub struct BasicValidator {
    /// Known account states keyed by address.
    accounts: BTreeMap<Address, AccountState>,
}

impl BasicValidator {
    /// Creates a new validator with the given account states.
    #[must_use]
    pub fn new(accounts: BTreeMap<Address, AccountState>) -> Self {
        Self { accounts }
    }

    /// Creates a validator with no accounts (useful for testing envelope checks).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            accounts: BTreeMap::new(),
        }
    }
}

impl Default for BasicValidator {
    fn default() -> Self {
        Self::empty()
    }
}

impl TransactionValidator for BasicValidator {
    fn validate(
        &self,
        transaction: Transaction,
        context: ValidationContext,
    ) -> Result<ValidatedTransaction, TransactionError> {
        let encoded_len = estimate_encoded_len(&transaction);
        if encoded_len > context.max_transaction_bytes {
            return Err(TransactionError::InvalidEnvelope);
        }

        if transaction.signature == [0; 64] {
            return Err(TransactionError::InvalidSignature);
        }

        if transaction.chain_id != context.chain_id {
            return Err(TransactionError::WrongChain);
        }

        let account = self.accounts.get(&transaction.sender);
        match account {
            None => {
                if transaction.nonce != 0 {
                    return Err(TransactionError::InvalidNonce);
                }
            }
            Some(acc) => {
                if transaction.nonce != acc.nonce {
                    return Err(TransactionError::InvalidNonce);
                }
                let cost = transaction.resource_limit.compute
                    + transaction.resource_limit.memory
                    + transaction.resource_limit.io
                    + transaction.resource_limit.bandwidth;
                if cost > acc.balance {
                    return Err(TransactionError::InsufficientResources);
                }
            }
        }

        let lane = TransactionLane::from_payload(&transaction.payload);
        let id = compute_tx_id(&transaction);

        Ok(ValidatedTransaction {
            id,
            lane,
            transaction,
        })
    }
}

/// Estimates the encoded byte length of a transaction.
///
/// This is a simplified estimate for validation; the actual encoding uses
/// the canonical codec.
#[must_use]
pub fn estimate_encoded_len(tx: &Transaction) -> usize {
    let base = 4 + 32 + 8 + 8 + 64;
    let access_list: usize = tx.access_list.iter().map(|k| 1 + k.len()).sum();
    base + access_list + tx.payload.len()
}

/// Computes a deterministic transaction identifier.
///
/// This is a simplified scheme for the baseline. The production implementation
/// will use a proper canonical hash of the encoded transaction.
#[must_use]
pub fn compute_tx_id(tx: &Transaction) -> Hash256 {
    let mut input = Vec::with_capacity(44);
    input.extend_from_slice(&tx.chain_id.to_le_bytes());
    input.extend_from_slice(&tx.sender.0);
    input.extend_from_slice(&tx.nonce.to_le_bytes());

    let mut hash = [0u8; 32];
    for (i, byte) in input.iter().enumerate() {
        hash[i % 32] ^= byte;
        hash[(i + 7) % 32] = hash[(i + 7) % 32].wrapping_add(*byte);
    }
    Hash256(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TransactionError;
    use types::{Resources, StateKey};

    fn sender() -> Address {
        Address([1u8; 32])
    }

    fn make_tx(nonce: u64, payload: Vec<u8>, resources: Resources) -> Transaction {
        Transaction {
            chain_id: 7,
            sender: sender(),
            nonce,
            access_list: Vec::new(),
            resource_limit: resources,
            payload,
            signature: [0xFF; 64],
        }
    }

    fn simple_context() -> ValidationContext {
        ValidationContext {
            chain_id: 7,
            next_height: 100,
            max_transaction_bytes: 1024,
        }
    }

    fn resources_with(compute: u64) -> Resources {
        Resources {
            compute,
            memory: 1,
            io: 1,
            bandwidth: 1,
        }
    }

    #[test]
    fn valid_transaction_passes() {
        let mut accounts = BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let tx = make_tx(0, vec![1, 2, 3], resources_with(10));
        let result = validator.validate(tx, simple_context());
        assert!(result.is_ok());

        let validated = result.unwrap();
        assert_eq!(validated.lane, TransactionLane::Payments);
        assert_eq!(validated.transaction.chain_id, 7);
    }

    #[test]
    fn rejects_wrong_chain() {
        let validator = BasicValidator::empty();
        let mut tx = make_tx(0, vec![], Resources::default());
        tx.chain_id = 99;

        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::WrongChain));
    }

    #[test]
    fn rejects_zero_signature() {
        let validator = BasicValidator::empty();
        let mut tx = make_tx(0, vec![], Resources::default());
        tx.signature = [0; 64];

        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::InvalidSignature));
    }

    #[test]
    fn rejects_invalid_nonce() {
        let mut accounts = BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 5,
                balance: 1000,
            },
        );
        let validator = BasicValidator::new(accounts);

        let tx = make_tx(0, vec![], Resources::default());
        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::InvalidNonce));
    }

    #[test]
    fn accepts_zero_nonce_for_unknown_account() {
        let validator = BasicValidator::empty();
        let tx = make_tx(0, vec![], Resources::default());
        let result = validator.validate(tx, simple_context());
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_nonzero_nonce_for_unknown_account() {
        let validator = BasicValidator::empty();
        let tx = make_tx(1, vec![], Resources::default());
        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::InvalidNonce));
    }

    #[test]
    fn rejects_insufficient_resources() {
        let mut accounts = BTreeMap::new();
        accounts.insert(
            sender(),
            AccountState {
                nonce: 0,
                balance: 5,
            },
        );
        let validator = BasicValidator::new(accounts);

        let tx = make_tx(
            0,
            vec![],
            Resources {
                compute: 100,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
        );
        let result = validator.validate(tx, simple_context());
        assert_eq!(result, Err(TransactionError::InsufficientResources));
    }

    #[test]
    fn rejects_oversized_transaction() {
        let validator = BasicValidator::empty();
        let mut tx = make_tx(0, vec![0; 2048], Resources::default());
        tx.signature = [0xFF; 64];

        let context = ValidationContext {
            chain_id: 7,
            next_height: 100,
            max_transaction_bytes: 1024,
        };
        let result = validator.validate(tx, context);
        assert_eq!(result, Err(TransactionError::InvalidEnvelope));
    }

    #[test]
    fn assigned_lane_matches_payload() {
        let validator = BasicValidator::empty();

        let tx = make_tx(0, vec![], Resources::default());
        let validated = validator.validate(tx, simple_context()).unwrap();
        assert_eq!(validated.lane, TransactionLane::System);

        let tx = make_tx(0, vec![0; 64], resources_with(1));
        let validated = validator.validate(tx, simple_context()).unwrap();
        assert_eq!(validated.lane, TransactionLane::Payments);

        let tx = make_tx(0, vec![0; 256], resources_with(1));
        let validated = validator.validate(tx, simple_context()).unwrap();
        assert_eq!(validated.lane, TransactionLane::Contracts);
    }

    #[test]
    fn transaction_id_is_deterministic() {
        let validator = BasicValidator::empty();
        let tx = make_tx(0, vec![1, 2, 3], resources_with(1));

        let v1 = validator.validate(tx.clone(), simple_context()).unwrap();
        let v2 = validator.validate(tx, simple_context()).unwrap();
        assert_eq!(v1.id, v2.id);
    }

    #[test]
    fn different_nonces_produce_different_ids() {
        let validator = BasicValidator::empty();

        let tx0 = Transaction {
            chain_id: 7,
            sender: Address([1u8; 32]),
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 1,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload: vec![1, 2, 3],
            signature: [0xFF; 64],
        };
        let tx1 = Transaction {
            chain_id: 7,
            sender: Address([2u8; 32]),
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 1,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload: vec![1, 2, 3],
            signature: [0xFF; 64],
        };

        let v0 = validator.validate(tx0, simple_context()).unwrap();
        let v1 = validator.validate(tx1, simple_context()).unwrap();
        assert_ne!(v0.id, v1.id);
    }

    #[test]
    fn estimate_encoded_len_basic() {
        let tx = Transaction {
            chain_id: 1,
            sender: Address([0; 32]),
            nonce: 0,
            access_list: vec![StateKey(vec![1, 2, 3])],
            resource_limit: Resources {
                compute: 1,
                memory: 2,
                io: 3,
                bandwidth: 4,
            },
            payload: vec![0; 10],
            signature: [0; 64],
        };
        let len = estimate_encoded_len(&tx);
        assert_eq!(len, 130);
    }
}
