// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic, privately staged genesis state.

use codec::CanonicalEncode;
use state::{InMemoryState, StateDiff, account_key};
use types::{AccountState, StateKey, ValidatorId};

use crate::{Genesis, GenesisError};

/// State key containing the full canonical genesis commitment.
#[must_use]
pub fn genesis_key() -> StateKey {
    StateKey(b"astrolune/genesis/v1".to_vec())
}

/// State key containing the initial validator weight as a little-endian `u128`.
#[must_use]
pub fn validator_key(id: ValidatorId) -> StateKey {
    let mut bytes = b"astrolune/validator/v1/".to_vec();
    bytes.extend_from_slice(id.as_bytes());
    StateKey(bytes)
}

impl Genesis {
    /// Builds the initial account/validator state without publishing or modifying a database.
    ///
    /// Every allocation creates a nonce-zero account, including zero balances.
    /// The metadata commitment binds chain parameters even when balances are identical.
    /// Persist the returned snapshot only after checking the expected genesis commitment.
    pub fn materialize(&self) -> Result<InMemoryState, GenesisError> {
        let hash = self.commitment()?;
        let mut diff = StateDiff::new();
        diff.put(genesis_key(), hash.as_bytes().to_vec());
        for validator in &self.validators {
            diff.put(
                validator_key(validator.id),
                validator.weight.to_le_bytes().to_vec(),
            );
        }
        for allocation in &self.allocations {
            diff.put(
                account_key(allocation.address),
                AccountState {
                    nonce: 0,
                    balance: allocation.amount,
                }
                .to_bytes(),
            );
        }
        diff.sort_canonical();
        let empty = InMemoryState::new();
        empty
            .prepare(empty.root(), &[diff])
            .map_err(GenesisError::State)
    }
}
