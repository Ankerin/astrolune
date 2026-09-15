// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Proof of Trusted Behavior committee selection and fast `BFT` finality.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use crypto::VrfOutput;
use types::{Hash256, ValidatorId};

/// Consensus weight derived from finalized `PoTB` state.
///
/// Fixed-point arithmetic is mandatory; floating point must never influence
/// committee selection or quorum calculations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PotbWeight(pub u128);

/// A validator eligible for committee selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Stable validator identity.
    pub id: ValidatorId,
    /// Effective `PoTB` weight after protocol caps and penalties.
    pub weight: PotbWeight,
    /// `VRF` result for the target height.
    pub vrf: VrfOutput,
}

/// A selected committee member and their voting power.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitteeMember {
    /// Validator identity.
    pub id: ValidatorId,
    /// Voting power used for quorum accounting.
    pub power: PotbWeight,
}

/// Ordered committee for one consensus height.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Committee {
    /// Height at which this membership becomes active.
    pub height: u64,
    /// Ordered unique membership.
    pub members: Vec<CommitteeMember>,
}

/// Selects committee replacements with probability proportional to `PoTB` weight.
pub trait CommitteeSelector {
    /// Builds the next committee while retaining the configured fraction of
    /// current members. Implementations must be deterministic after `VRF` proof
    /// verification and canonical tie-breaking by validator identity.
    fn rotate(
        &self,
        current: &Committee,
        candidates: &[Candidate],
        replacement_count: usize,
    ) -> Committee;
}

/// The two voting phases used by fast `BFT` finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VotePhase {
    /// A validator considers the proposal valid for the round.
    Prevote,
    /// A validator locks and commits after observing a prevote quorum.
    Precommit,
}

/// A signed `BFT` vote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vote {
    /// Target height.
    pub height: u64,
    /// Round within the height.
    pub round: u32,
    /// Voting phase.
    pub phase: VotePhase,
    /// Proposed block, or `None` for a nil vote.
    pub block: Option<Hash256>,
    /// Committee member that produced the vote.
    pub voter: ValidatorId,
    /// Canonical signature bytes.
    pub signature: [u8; 64],
}

/// Returns the minimum power that is strictly greater than two thirds.
#[must_use]
pub const fn quorum_power(total_power: u128) -> u128 {
    total_power.saturating_mul(2) / 3 + 1
}

/// Fast-finality state machine boundary.
pub trait FinalityEngine {
    /// Validates and records a vote without executing transactions.
    fn receive_vote(&mut self, vote: Vote) -> Result<(), ConsensusError>;

    /// Returns a block only after a valid precommit quorum exists.
    fn finalized_block(&self) -> Option<Hash256>;
}

/// Consensus-level validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusError {
    /// The signer is not in the active committee.
    UnknownVoter,
    /// A validator voted more than once in one phase and round.
    DuplicateVote,
    /// A signature or `VRF` proof is invalid.
    InvalidProof,
    /// Height, round, phase, or lock rules were violated.
    InvalidTransition,
}

#[cfg(test)]
mod tests {
    use super::quorum_power;

    #[test]
    fn quorum_is_strictly_greater_than_two_thirds() {
        assert_eq!(quorum_power(100), 67);
        assert_eq!(quorum_power(3), 3);
        assert_eq!(quorum_power(0), 1);
    }
}
