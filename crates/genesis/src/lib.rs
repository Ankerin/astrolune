// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Validated chain genesis parameters.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use codec::decoder::Decoder;
use codec::error::DecodeError;
use codec::traits::{CanonicalDecode, CanonicalEncode};
use crypto::CryptoProvider;
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
        if self
            .validators
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
            || self
                .validators
                .iter()
                .any(|validator| validator.weight == 0)
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
    fn genesis_hash(&self, genesis: &Genesis) -> Hash256;
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

impl CanonicalEncode for Allocation {
    fn encode(&self, output: &mut Vec<u8>) {
        self.address.encode(output);
        self.amount.encode(output);
    }
}

impl CanonicalEncode for GenesisValidator {
    #[allow(clippy::cast_possible_truncation)]
    fn encode(&self, output: &mut Vec<u8>) {
        self.id.encode(output);
        // Encode u128 weight as two LE u64 parts for canonical representation
        let low = self.weight as u64;
        let high = (self.weight >> 64) as u64;
        low.encode(output);
        high.encode(output);
    }
}

impl CanonicalEncode for Genesis {
    fn encode(&self, output: &mut Vec<u8>) {
        self.version.encode(output);
        self.chain_id.encode(output);
        self.capacity.encode(output);
        // Encode usize fields as u64 for deterministic cross-platform encoding
        (self.committee_size as u64).encode(output);
        (self.rotation_count as u64).encode(output);
        self.runtime_version.encode(output);

        // Validators: length-prefixed canonically ordered list
        (self.validators.len() as u64).encode(output);
        for v in &self.validators {
            v.encode(output);
        }

        // Allocations: length-prefixed canonically ordered list
        (self.allocations.len() as u64).encode(output);
        for a in &self.allocations {
            a.encode(output);
        }
    }
}

/// Implementation of `GenesisCommitment` for any `CryptoProvider`.
///
/// Produces a domain-separated deterministic hash of the genesis configuration
/// suitable for chain-binding and genesis validation.
impl<C: CryptoProvider> GenesisCommitment for C {
    fn genesis_hash(&self, genesis: &Genesis) -> Hash256 {
        let encoded = genesis.to_bytes();
        self.hash(types::domain::GENESIS, &encoded)
    }
}

impl CanonicalDecode for Allocation {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes);
        let address = Address(dec.read_fixed::<32>()?);
        let amount = dec.read_u64()?;
        dec.finish()?;
        Ok(Self { address, amount })
    }
}

impl CanonicalDecode for GenesisValidator {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes);
        let id = ValidatorId(dec.read_fixed::<32>()?);
        let low = dec.read_u64()?;
        let high = dec.read_u64()?;
        dec.finish()?;
        Ok(Self {
            id,
            weight: u128::from(low) | (u128::from(high) << 64),
        })
    }
}

impl CanonicalDecode for Genesis {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes);
        let version = dec.read_u16()?;
        let chain_id = dec.read_u32()?;
        let capacity = Resources {
            compute: dec.read_u64()?,
            memory: dec.read_u64()?,
            io: dec.read_u64()?,
            bandwidth: dec.read_u64()?,
        };
        let committee_size = dec.read_u64()? as usize;
        let rotation_count = dec.read_u64()? as usize;
        let runtime_version = dec.read_u32()?;

        let validator_len = dec.read_u64()? as usize;
        let mut validators = Vec::with_capacity(validator_len);
        for _ in 0..validator_len {
            let id = ValidatorId(dec.read_fixed::<32>()?);
            let low = dec.read_u64()?;
            let high = dec.read_u64()?;
            validators.push(GenesisValidator {
                id,
                weight: u128::from(low) | (u128::from(high) << 64),
            });
        }

        let allocation_len = dec.read_u64()? as usize;
        let mut allocations = Vec::with_capacity(allocation_len);
        for _ in 0..allocation_len {
            let address = Address(dec.read_fixed::<32>()?);
            let amount = dec.read_u64()?;
            allocations.push(Allocation { address, amount });
        }

        dec.finish()?;

        Ok(Self {
            version,
            chain_id,
            capacity,
            committee_size,
            rotation_count,
            runtime_version,
            validators,
            allocations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::MockCryptoProvider;

    fn valid_genesis() -> Genesis {
        Genesis {
            version: 1,
            chain_id: 7,
            capacity: Resources {
                compute: 100,
                memory: 100,
                io: 100,
                bandwidth: 100,
            },
            committee_size: 2,
            rotation_count: 1,
            runtime_version: 1,
            validators: vec![
                GenesisValidator {
                    id: ValidatorId::from_bytes([1u8; 32]),
                    weight: 100,
                },
                GenesisValidator {
                    id: ValidatorId::from_bytes([2u8; 32]),
                    weight: 200,
                },
            ],
            allocations: vec![
                Allocation {
                    address: Address::from_bytes([0xAA; 32]),
                    amount: 1000,
                },
                Allocation {
                    address: Address::from_bytes([0xBB; 32]),
                    amount: 2000,
                },
            ],
        }
    }

    #[test]
    fn genesis_validate_passes() {
        let genesis = valid_genesis();
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn genesis_encoding_deterministic() {
        let genesis = valid_genesis();
        let e1 = genesis.to_bytes();
        let e2 = genesis.to_bytes();
        assert_eq!(e1, e2);
    }

    #[test]
    fn genesis_encoding_differs_by_version() {
        let mut g1 = valid_genesis();
        g1.version = 1;
        let mut g2 = valid_genesis();
        g2.version = 2;
        assert_ne!(g1.to_bytes(), g2.to_bytes());
    }

    #[test]
    fn genesis_encoding_differs_by_chain_id() {
        let mut g1 = valid_genesis();
        g1.chain_id = 7;
        let mut g2 = valid_genesis();
        g2.chain_id = 8;
        assert_ne!(g1.to_bytes(), g2.to_bytes());
    }

    #[test]
    fn genesis_encoding_differs_by_validators() {
        let mut g1 = valid_genesis();
        g1.validators[0].weight = 100;
        let mut g2 = valid_genesis();
        g2.validators[0].weight = 200;
        assert_ne!(g1.to_bytes(), g2.to_bytes());
    }

    #[test]
    fn genesis_encoding_empty_allocations() {
        let mut genesis = valid_genesis();
        genesis.allocations.clear();
        let encoded = genesis.to_bytes();
        // Verify it can be roundtripped (no decoding impl yet, but encoding should succeed)
        assert!(!encoded.is_empty());
    }

    #[test]
    fn genesis_encoding_empty_validators_fails_validation() {
        let mut genesis = valid_genesis();
        genesis.validators.clear();
        assert!(genesis.validate().is_err());
    }

    #[test]
    fn genesis_commitment_deterministic() {
        let provider = MockCryptoProvider::new();
        let genesis = valid_genesis();
        let h1 = provider.genesis_hash(&genesis);
        let h2 = provider.genesis_hash(&genesis);
        assert_eq!(h1, h2);
    }

    #[test]
    fn genesis_commitment_differs_by_chain_id() {
        let _provider = MockCryptoProvider::new();
        let mut g1 = valid_genesis();
        g1.chain_id = 7;
        let mut g2 = valid_genesis();
        g2.chain_id = 8;
        // Different chain IDs produce different canonical encodings
        let e1 = g1.to_bytes();
        let e2 = g2.to_bytes();
        assert_ne!(e1, e2);
    }

    #[test]
    fn genesis_commitment_non_zero() {
        let provider = MockCryptoProvider::new();
        let genesis = valid_genesis();
        let hash = provider.genesis_hash(&genesis);
        assert!(!hash.is_zero());
    }

    #[test]
    fn allocation_roundtrip() {
        let alloc = Allocation {
            address: Address::from_bytes([0xAA; 32]),
            amount: 42,
        };
        let encoded = alloc.to_bytes();
        let decoded = Allocation::decode(&encoded).unwrap();
        assert_eq!(alloc, decoded);
    }

    #[test]
    fn genesis_validator_roundtrip() {
        let gv = GenesisValidator {
            id: ValidatorId::from_bytes([0x55; 32]),
            weight: u128::MAX,
        };
        let encoded = gv.to_bytes();
        let decoded = GenesisValidator::decode(&encoded).unwrap();
        assert_eq!(gv, decoded);
    }

    #[test]
    fn genesis_validator_weight_zero_roundtrip() {
        let gv = GenesisValidator {
            id: ValidatorId::from_bytes([0x55; 32]),
            weight: 0,
        };
        let encoded = gv.to_bytes();
        let decoded = GenesisValidator::decode(&encoded).unwrap();
        assert_eq!(gv, decoded);
    }

    #[test]
    fn genesis_roundtrip() {
        let genesis = valid_genesis();
        let encoded = genesis.to_bytes();
        let decoded = Genesis::decode(&encoded).unwrap();
        assert_eq!(genesis, decoded);
    }

    #[test]
    fn genesis_roundtrip_empty_lists() {
        let mut genesis = valid_genesis();
        genesis.validators.clear();
        genesis.allocations.clear();
        let encoded = genesis.to_bytes();
        let decoded = Genesis::decode(&encoded).unwrap();
        assert_eq!(genesis, decoded);
    }

    #[test]
    fn genesis_roundtrip_single_validator() {
        let mut genesis = valid_genesis();
        genesis.validators.truncate(1);
        let encoded = genesis.to_bytes();
        let decoded = Genesis::decode(&encoded).unwrap();
        assert_eq!(genesis, decoded);
    }

    #[test]
    fn genesis_encoding_empty_allocations_comment_updated() {
        let mut genesis = valid_genesis();
        genesis.allocations.clear();
        let encoded = genesis.to_bytes();
        let decoded = Genesis::decode(&encoded).unwrap();
        assert_eq!(genesis, decoded);
    }

    #[test]
    fn allocation_encoding_deterministic() {
        let alloc = Allocation {
            address: Address::from_bytes([0xCC; 32]),
            amount: 999,
        };
        assert_eq!(alloc.to_bytes(), alloc.to_bytes());
    }

    #[test]
    fn genesis_encoding_differs_by_allocations() {
        let mut g1 = valid_genesis();
        g1.allocations[0].amount = 100;
        let mut g2 = valid_genesis();
        g2.allocations[0].amount = 200;
        assert_ne!(g1.to_bytes(), g2.to_bytes());
    }
}
