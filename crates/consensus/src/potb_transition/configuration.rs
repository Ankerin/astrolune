// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! A separately committed opt-in configuration; never an implicit genesis upgrade.

use super::encoding::read_field;
use crate::{ConsensusError, potb::PotbPolicy, rotation::MAX_ROTATION_VALIDATORS};
use codec::{CanonicalDecode, CanonicalEncode, DecodeError, Decoder};
use genesis::Genesis;
use types::{Hash256, hash::domain_hash};

/// Explicit genesis parameters plus immutable `PoTB` policy, in a new namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PotbConfiguration {
    genesis: Genesis,
    policy: PotbPolicy,
}

impl PotbConfiguration {
    /// Maximum configuration size, including bounded genesis allocations.
    pub const MAX_BYTES: usize = 12 + genesis::MAX_GENESIS_BYTES + 56;

    /// Requires rotating base parameters and uniform policy starting weights.
    /// Maximum weight must be safe for every possible bounded roster, not just
    /// the initial committee. Existing genesis APIs never accept this envelope.
    pub fn new(genesis: Genesis, policy: PotbPolicy) -> Result<Self, ConsensusError> {
        genesis
            .validate()
            .map_err(|_| ConsensusError::InvalidCommittee)?;
        validate_policy(policy)?;
        if genesis.version != genesis::ROTATING_GENESIS_VERSION
            || genesis.validators.len() > MAX_ROTATION_VALIDATORS
            || genesis
                .validators
                .iter()
                .any(|v| v.weight != policy.initial_weight)
        {
            return Err(ConsensusError::InvalidCommittee);
        }
        Ok(Self { genesis, policy })
    }

    /// Base allocations, capacity and runtime. Its legacy hash is not this profile's anchor.
    #[must_use]
    pub const fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    /// Immutable integer policy.
    #[must_use]
    pub const fn policy(&self) -> PotbPolicy {
        self.policy
    }

    /// Independent namespace for parent linkage, VRF, admission and committee history.
    #[must_use]
    pub fn commitment(&self) -> Hash256 {
        domain_hash(b"astrolune.potb.configuration.v1", &self.to_bytes())
    }

    /// Materializes allocations and the explicit initial policy authority together.
    /// The legacy rotating marker is replaced by the complete `PoTB` state. Initial
    /// validator keys retain their genesis meaning; current power lives in that state.
    pub fn materialize(&self, keys: &[[u8; 32]]) -> Result<state::InMemoryState, ConsensusError> {
        let authority = super::PotbState::from_configuration(self, keys)?;
        let initial = self
            .genesis
            .materialize()
            .map_err(|_| ConsensusError::InvalidTransition)?;
        let mut diff = state::StateDiff::new();
        diff.delete(types::StateKey(
            types::domain::ROTATING_PROFILE_KEY.to_vec(),
        ));
        diff.put(genesis::genesis_key(), self.commitment().0.to_vec());
        diff.put(
            super::potb_state_key(),
            authority
                .to_bytes()
                .map_err(|_| ConsensusError::InvalidTransition)?,
        );
        diff.sort_canonical();
        initial
            .prepare(initial.root(), &[diff])
            .map_err(|_| ConsensusError::InvalidTransition)
    }

    /// Canonical bounded configuration bytes.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Private validated genesis is bounded below u32::MAX.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = b"ALPTCF01".to_vec();
        let genesis = self.genesis.to_bytes();
        bytes.extend_from_slice(&(genesis.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&genesis);
        write_policy(&mut bytes, self.policy);
        bytes
    }

    /// Decodes exact structure and validates policy; caller must still trust the configuration.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.read_exact(8)? != b"ALPTCF01" {
            return Err(DecodeError::Unsupported);
        }
        let genesis = read_field(&mut decoder, genesis::MAX_GENESIS_BYTES)?;
        let policy = read_policy(&mut decoder)?;
        decoder.finish()?;
        Self::new(Genesis::decode(genesis)?, policy).map_err(|_| DecodeError::NonCanonical)
    }
}

pub(super) fn validate_policy(policy: PotbPolicy) -> Result<(), ConsensusError> {
    policy.validate()?;
    if policy.maximum_weight > u128::MAX / MAX_ROTATION_VALIDATORS as u128 {
        return Err(ConsensusError::InvalidTransition);
    }
    Ok(())
}

pub(super) fn write_policy(bytes: &mut Vec<u8>, policy: PotbPolicy) {
    bytes.extend_from_slice(&policy.epoch_blocks.to_le_bytes());
    bytes.extend_from_slice(&policy.initial_weight.to_le_bytes());
    bytes.extend_from_slice(&policy.age_increment.to_le_bytes());
    bytes.extend_from_slice(&policy.maximum_weight.to_le_bytes());
}

pub(super) fn read_policy(decoder: &mut Decoder<'_>) -> Result<PotbPolicy, DecodeError> {
    let policy = PotbPolicy {
        epoch_blocks: decoder.read_u64()?,
        initial_weight: u128::from_le_bytes(decoder.read_fixed()?),
        age_increment: u128::from_le_bytes(decoder.read_fixed()?),
        maximum_weight: u128::from_le_bytes(decoder.read_fixed()?),
    };
    validate_policy(policy).map_err(|_| DecodeError::NonCanonical)?;
    Ok(policy)
}
