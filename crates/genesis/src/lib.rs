// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Validated chain genesis parameters.

#![forbid(unsafe_code)]

use types::{Address, Hash256, Resources, ValidatorId};

/// Initial account allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Allocation {
    /// Account receiving the allocation.
    pub address: Address,
    /// Initial smallest-unit balance.
    pub amount: u64,
}

/// Initial validator identity and fixed-point `PoTB` weight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisValidator {
    /// Validator identity key.
    pub id: ValidatorId,
    /// Non-zero initial fixed-point weight.
    pub weight: u128,
}

/// Complete consensus-controlled chain configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Genesis {
    /// Encoding version.
    pub version: u16,
    /// Replay-protection identifier.
    pub chain_id: u32,
    /// Initial aggregate block capacity.
    pub capacity: Resources,
    /// Nominal active committee size.
    pub committee_size: usize,
    /// Number of committee seats replaced per block.
    pub rotation_count: usize,
    /// Contract runtime semantics version.
    pub runtime_version: u32,
    /// Canonically ordered validator set.
    pub validators: Vec<GenesisValidator>,
    /// Canonically ordered initial account balances.
    pub allocations: Vec<Allocation>,
}

impl Genesis {
    /// Checks structural invariants before hashing or materialization.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisError`] when identifiers, capacity, committee parameters,
    /// validators, or allocations violate canonical genesis rules.
    pub fn validate(&self) -> Result<(), GenesisError> {
        if self.version == 0 || self.chain_id == 0 {
            return Err(GenesisError::InvalidIdentity);
        }
        if self.capacity.compute == 0
            || self.capacity.memory == 0
            || self.capacity.io == 0
            || self.capacity.bandwidth == 0
        {
            return Err(GenesisError::InvalidCapacity);
        }
        if self.committee_size == 0
            || self.rotation_count == 0
            || self.rotation_count > self.committee_size
            || self.committee_size > self.validators.len()
        {
            return Err(GenesisError::InvalidCommittee);
        }
        if self.validators.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || self.validators.iter().any(|validator| validator.weight == 0)
        {
            return Err(GenesisError::InvalidValidators);
        }
        if self
            .allocations
            .windows(2)
            .any(|pair| pair[0].address >= pair[1].address)
        {
            return Err(GenesisError::InvalidAllocations);
        }
        Ok(())
    }
}

/// Hashing boundary for canonical genesis bytes.
pub trait GenesisCommitment {
    /// Returns the chain-binding genesis hash.
    fn hash(&self, genesis: &Genesis) -> Hash256;
}

/// Genesis validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenesisError {
    /// Version or chain identifier is zero.
    InvalidIdentity,
    /// One or more resource dimensions are zero.
    InvalidCapacity,
    /// Committee size or rotation is inconsistent.
    InvalidCommittee,
    /// Validators are empty, duplicated, unsorted, or have zero weight.
    InvalidValidators,
    /// Allocations contain duplicate or unsorted addresses.
    InvalidAllocations,
}
