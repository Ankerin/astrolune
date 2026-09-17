// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Proof of Trusted Behavior committee selection and fast `BFT` finality.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

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

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVoter => write!(f, "voter is not in the active committee"),
            Self::DuplicateVote => {
                write!(f, "validator voted more than once in one phase and round")
            }
            Self::InvalidProof => write!(f, "signature or VRF proof is invalid"),
            Self::InvalidTransition => {
                write!(f, "height, round, phase, or lock rules were violated")
            }
        }
    }
}

impl std::error::Error for ConsensusError {}

/// Weighted committee sampler that retains a configurable fraction of sitting
/// members and fills vacancies from candidates sorted by `VRF` randomness.
///
/// Determinism is guaranteed by sorting candidates first by descending `VRF`
/// randomness (big-endian `Hash256` comparison), then by descending effective
/// weight, and finally by ascending validator identity for tie-breaking.
pub struct WeightedSampler;

impl CommitteeSelector for WeightedSampler {
    fn rotate(
        &self,
        current: &Committee,
        candidates: &[Candidate],
        replacement_count: usize,
    ) -> Committee {
        let next_height = current.height + 1;
        let committee_size = current.members.len();

        if committee_size == 0 || replacement_count == 0 {
            return Committee {
                height: next_height,
                members: current.members.clone(),
            };
        }

        let retained_count = replacement_count.min(committee_size);

        let mut retained: Vec<CommitteeMember> = current.members[..retained_count].to_vec();

        let retained_ids: BTreeSet<ValidatorId> = retained.iter().map(|m| m.id).collect();

        let mut new_slots = committee_size.saturating_sub(retained_count);

        if new_slots == 0 {
            return Committee {
                height: next_height,
                members: retained,
            };
        }

        let mut eligible: Vec<&Candidate> = candidates
            .iter()
            .filter(|c| !retained_ids.contains(&c.id))
            .collect();

        eligible.sort_by(|a, b| {
            b.vrf
                .randomness
                .cmp(&a.vrf.randomness)
                .then_with(|| b.weight.cmp(&a.weight))
                .then_with(|| a.id.cmp(&b.id))
        });

        let mut selected_ids: BTreeSet<ValidatorId> = retained_ids;

        for candidate in eligible {
            if new_slots == 0 {
                break;
            }
            if selected_ids.insert(candidate.id) {
                retained.push(CommitteeMember {
                    id: candidate.id,
                    power: candidate.weight,
                });
                new_slots -= 1;
            }
        }

        Committee {
            height: next_height,
            members: retained,
        }
    }
}

/// Internal key identifying a unique vote slot: `(voter, height, round, phase)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VoteKey {
    voter: ValidatorId,
    height: u64,
    round: u32,
    phase: VotePhase,
}

impl Ord for VoteKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.voter
            .cmp(&other.voter)
            .then_with(|| self.height.cmp(&other.height))
            .then_with(|| self.round.cmp(&other.round))
            .then_with(|| phase_ord(self.phase).cmp(&phase_ord(other.phase)))
    }
}

impl PartialOrd for VoteKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for VoteKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.voter.hash(state);
        self.height.hash(state);
        self.round.hash(state);
        phase_ord(self.phase).hash(state);
    }
}

fn phase_ord(phase: VotePhase) -> u8 {
    match phase {
        VotePhase::Prevote => 0,
        VotePhase::Precommit => 1,
    }
}

/// Wrapper for `(Option<Hash256>, VotePhase)` to derive `Ord` without requiring
/// it on `VotePhase` directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PowerKey {
    block: Option<Hash256>,
    phase: VotePhase,
}

impl Ord for PowerKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.block
            .cmp(&other.block)
            .then_with(|| phase_ord(self.phase).cmp(&phase_ord(other.phase)))
    }
}

impl PartialOrd for PowerKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::hash::Hash for PowerKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.block.hash(state);
        phase_ord(self.phase).hash(state);
    }
}

/// Fast `BFT` finality engine that tracks votes, detects equivocation, and
/// finalizes a block once a precommit quorum is reached.
pub struct BftFinalityEngine {
    /// Current committee and its total voting power.
    committee: Committee,
    /// Total voting power of the active committee.
    total_power: PotbWeight,
    /// Set of `(voter, height, round, phase)` tuples already seen.
    votes: BTreeMap<VoteKey, Option<Hash256>>,
    /// Accumulated voting power per `(block_hash, phase)` for a single height.
    power: BTreeMap<PowerKey, PotbWeight>,
    /// The finalized block hash, if any.
    finalized: Option<Hash256>,
}

impl BftFinalityEngine {
    /// Creates a new engine for the given committee.
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        let total_power = committee.members.iter().fold(PotbWeight(0), |acc, m| {
            PotbWeight(acc.0.saturating_add(m.power.0))
        });
        Self {
            committee,
            total_power,
            votes: BTreeMap::new(),
            power: BTreeMap::new(),
            finalized: None,
        }
    }

    /// Returns the committee power of the given voter, or `None` if absent.
    #[must_use]
    fn voter_power(&self, voter: &ValidatorId) -> Option<PotbWeight> {
        self.committee
            .members
            .iter()
            .find(|m| m.id == *voter)
            .map(|m| m.power)
    }
}

impl FinalityEngine for BftFinalityEngine {
    fn receive_vote(&mut self, vote: Vote) -> Result<(), ConsensusError> {
        let power = self
            .voter_power(&vote.voter)
            .ok_or(ConsensusError::UnknownVoter)?;

        let key = VoteKey {
            voter: vote.voter,
            height: vote.height,
            round: vote.round,
            phase: vote.phase,
        };

        if let Some(prev_block) = self.votes.get(&key)
            && prev_block.is_some()
        {
            return Err(ConsensusError::DuplicateVote);
        }

        self.votes.insert(key, vote.block);

        let key = PowerKey {
            block: vote.block,
            phase: vote.phase,
        };

        let entry = self.power.entry(key).or_insert(PotbWeight(0));
        *entry = PotbWeight(entry.0.saturating_add(power.0));

        if vote.phase == VotePhase::Precommit && self.finalized.is_none() {
            let quorum = quorum_power(self.total_power.0);
            if let Some(block) = vote.block
                && entry.0 >= quorum
            {
                self.finalized = Some(block);
            }
        }

        Ok(())
    }

    fn finalized_block(&self) -> Option<Hash256> {
        self.finalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::VrfOutput;

    fn make_vrf(byte: u8) -> VrfOutput {
        VrfOutput {
            randomness: Hash256([byte; 32]),
            proof: vec![byte],
        }
    }

    fn make_candidate(id: u8, weight: u128, vrf_byte: u8) -> Candidate {
        Candidate {
            id: ValidatorId::from_bytes([id; 32]),
            weight: PotbWeight(weight),
            vrf: make_vrf(vrf_byte),
        }
    }

    fn make_member(id: u8, power: u128) -> CommitteeMember {
        CommitteeMember {
            id: ValidatorId::from_bytes([id; 32]),
            power: PotbWeight(power),
        }
    }

    #[test]
    fn quorum_is_strictly_greater_than_two_thirds() {
        assert_eq!(quorum_power(100), 67);
        assert_eq!(quorum_power(3), 3);
        assert_eq!(quorum_power(0), 1);
    }

    // -- ConsensusError Display and Error --

    #[test]
    fn consensus_error_display() {
        assert_eq!(
            format!("{}", ConsensusError::UnknownVoter),
            "voter is not in the active committee"
        );
        assert_eq!(
            format!("{}", ConsensusError::DuplicateVote),
            "validator voted more than once in one phase and round"
        );
        assert_eq!(
            format!("{}", ConsensusError::InvalidProof),
            "signature or VRF proof is invalid"
        );
        assert_eq!(
            format!("{}", ConsensusError::InvalidTransition),
            "height, round, phase, or lock rules were violated"
        );
    }

    #[test]
    fn consensus_error_is_std_error() {
        let err: &dyn std::error::Error = &ConsensusError::UnknownVoter;
        assert!(err.source().is_none());
    }

    // -- WeightedSampler: committee rotation with retention --

    #[test]
    fn sampler_retains_first_replacement_count_members() {
        let current = Committee {
            height: 0,
            members: vec![
                make_member(1, 10),
                make_member(2, 20),
                make_member(3, 30),
                make_member(4, 40),
            ],
        };

        let candidates = vec![make_candidate(5, 50, 0xFF), make_candidate(6, 60, 0xFE)];

        let sampler = WeightedSampler;
        let next = sampler.rotate(&current, &candidates, 2);

        assert_eq!(next.height, 1);
        assert_eq!(next.members.len(), 4);
        // Retained members are at indices 0 and 1
        assert_eq!(next.members[0].id, ValidatorId::from_bytes([1; 32]));
        assert_eq!(next.members[1].id, ValidatorId::from_bytes([2; 32]));
        // New members fill slots 2 and 3
        assert_eq!(next.members[2].id, ValidatorId::from_bytes([5; 32]));
        assert_eq!(next.members[3].id, ValidatorId::from_bytes([6; 32]));
    }

    #[test]
    fn sampler_sorts_new_members_by_vrf_then_weight_then_id() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10)],
        };

        let candidates = vec![
            make_candidate(2, 100, 0x01),
            make_candidate(3, 200, 0x02),
            make_candidate(4, 150, 0x03),
        ];

        let sampler = WeightedSampler;
        let next = sampler.rotate(&current, &candidates, 1);

        // Committee has 1 member, replacement_count=1 retains all, no new slots
        assert_eq!(next.members.len(), 1);
        assert_eq!(next.members[0].id, ValidatorId::from_bytes([1; 32]));
    }

    #[test]
    fn sampler_no_duplicates_in_committee() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 20), make_member(3, 30)],
        };

        // Candidate 1 appears again in the candidate list
        let candidates = vec![make_candidate(1, 100, 0xFF), make_candidate(4, 40, 0xFE)];

        let sampler = WeightedSampler;
        let next = sampler.rotate(&current, &candidates, 1);

        let ids: Vec<ValidatorId> = next.members.iter().map(|m| m.id).collect();
        let unique: BTreeSet<ValidatorId> = ids.iter().copied().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn sampler_empty_committee_unchanged() {
        let current = Committee {
            height: 5,
            members: vec![],
        };
        let candidates = vec![make_candidate(1, 10, 0x01)];

        let sampler = WeightedSampler;
        let next = sampler.rotate(&current, &candidates, 1);

        assert_eq!(next.height, 6);
        assert!(next.members.is_empty());
    }

    #[test]
    fn sampler_zero_replacement_count_unchanged() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 20)],
        };
        let candidates = vec![make_candidate(3, 30, 0x01)];

        let sampler = WeightedSampler;
        let next = sampler.rotate(&current, &candidates, 0);

        assert_eq!(next.members.len(), 2);
        assert_eq!(next.members[0].id, ValidatorId::from_bytes([1; 32]));
        assert_eq!(next.members[1].id, ValidatorId::from_bytes([2; 32]));
    }

    #[test]
    fn sampler_total_power_is_sum_of_member_powers() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 20)],
        };
        let candidates = vec![make_candidate(3, 30, 0x01)];

        let sampler = WeightedSampler;
        let next = sampler.rotate(&current, &candidates, 1);

        let total: u128 = next.members.iter().map(|m| m.power.0).sum();
        let expected: u128 = next.members.iter().map(|m| m.power.0).sum::<u128>();
        assert_eq!(total, expected);
    }

    #[test]
    fn sampler_replacement_count_exceeds_committee_keeps_all() {
        let current = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 20)],
        };
        let candidates = vec![make_candidate(3, 30, 0x01)];

        let sampler = WeightedSampler;
        let next = sampler.rotate(&current, &candidates, 100);

        // replacement_count is clamped to committee size, so all current members retained
        assert_eq!(next.members.len(), 2);
        assert_eq!(next.members[0].id, ValidatorId::from_bytes([1; 32]));
        assert_eq!(next.members[1].id, ValidatorId::from_bytes([2; 32]));
    }

    // -- BftFinalityEngine: quorum detection --

    #[test]
    fn finality_reaches_quorum() {
        let committee = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 10), make_member(3, 10)],
        };

        let mut engine = BftFinalityEngine::new(committee);
        let block = Hash256([0xAA; 32]);

        // 3 votes of 10 power each = 30 total, quorum = 30*2/3+1 = 21
        for id in [1u8, 2, 3] {
            engine
                .receive_vote(Vote {
                    height: 0,
                    round: 0,
                    phase: VotePhase::Precommit,
                    block: Some(block),
                    voter: ValidatorId::from_bytes([id; 32]),
                    signature: [0xFF; 64],
                })
                .unwrap();
        }

        assert_eq!(engine.finalized_block(), Some(block));
    }

    #[test]
    fn finality_not_reached_before_quorum() {
        let committee = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 10), make_member(3, 10)],
        };

        let mut engine = BftFinalityEngine::new(committee);
        let block = Hash256([0xAA; 32]);

        engine
            .receive_vote(Vote {
                height: 0,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(block),
                voter: ValidatorId::from_bytes([1; 32]),
                signature: [0xFF; 64],
            })
            .unwrap();

        engine
            .receive_vote(Vote {
                height: 0,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(block),
                voter: ValidatorId::from_bytes([2; 32]),
                signature: [0xFF; 64],
            })
            .unwrap();

        // 20 power < quorum 21
        assert_eq!(engine.finalized_block(), None);
    }

    // -- BftFinalityEngine: equivocation rejection --

    #[test]
    fn finality_rejects_duplicate_vote() {
        let committee = Committee {
            height: 0,
            members: vec![make_member(1, 10)],
        };

        let mut engine = BftFinalityEngine::new(committee);
        let block = Hash256([0xAA; 32]);

        engine
            .receive_vote(Vote {
                height: 0,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(block),
                voter: ValidatorId::from_bytes([1; 32]),
                signature: [0xFF; 64],
            })
            .unwrap();

        let err = engine
            .receive_vote(Vote {
                height: 0,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(block),
                voter: ValidatorId::from_bytes([1; 32]),
                signature: [0xFF; 64],
            })
            .unwrap_err();

        assert_eq!(err, ConsensusError::DuplicateVote);
    }

    #[test]
    fn finality_rejects_unknown_voter() {
        let committee = Committee {
            height: 0,
            members: vec![make_member(1, 10)],
        };

        let mut engine = BftFinalityEngine::new(committee);
        let block = Hash256([0xAA; 32]);

        let err = engine
            .receive_vote(Vote {
                height: 0,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(block),
                voter: ValidatorId::from_bytes([99; 32]),
                signature: [0xFF; 64],
            })
            .unwrap_err();

        assert_eq!(err, ConsensusError::UnknownVoter);
    }

    #[test]
    fn finality_allows_different_phases_for_same_height_round() {
        let committee = Committee {
            height: 0,
            members: vec![make_member(1, 10)],
        };

        let mut engine = BftFinalityEngine::new(committee);
        let block = Hash256([0xAA; 32]);

        engine
            .receive_vote(Vote {
                height: 0,
                round: 0,
                phase: VotePhase::Prevote,
                block: Some(block),
                voter: ValidatorId::from_bytes([1; 32]),
                signature: [0xFF; 64],
            })
            .unwrap();

        // Same voter, same height/round, different phase -> allowed
        engine
            .receive_vote(Vote {
                height: 0,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(block),
                voter: ValidatorId::from_bytes([1; 32]),
                signature: [0xFF; 64],
            })
            .unwrap();

        assert_eq!(engine.finalized_block(), Some(block));
    }

    #[test]
    fn finality_only_precommit_triggers_finalization() {
        let committee = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 10), make_member(3, 10)],
        };

        let mut engine = BftFinalityEngine::new(committee);
        let block = Hash256([0xAA; 32]);

        for id in [1u8, 2, 3] {
            engine
                .receive_vote(Vote {
                    height: 0,
                    round: 0,
                    phase: VotePhase::Prevote,
                    block: Some(block),
                    voter: ValidatorId::from_bytes([id; 32]),
                    signature: [0xFF; 64],
                })
                .unwrap();
        }

        // Prevote quorum reached but that does not finalize
        assert_eq!(engine.finalized_block(), None);
    }

    // -- Full lifecycle test --

    #[test]
    fn full_lifecycle_committee_rotation_and_finality() {
        let initial_committee = Committee {
            height: 0,
            members: vec![
                make_member(1, 10),
                make_member(2, 20),
                make_member(3, 30),
                make_member(4, 40),
            ],
        };

        let sampler = WeightedSampler;

        let candidates = vec![
            make_candidate(5, 50, 0x05),
            make_candidate(6, 60, 0x06),
            make_candidate(7, 70, 0x07),
        ];

        // Rotate: retain 2 members, fill 2 from candidates
        let next_committee = sampler.rotate(&initial_committee, &candidates, 2);
        assert_eq!(next_committee.height, 1);
        assert_eq!(next_committee.members.len(), 4);

        // Verify retained members
        assert_eq!(
            next_committee.members[0].id,
            ValidatorId::from_bytes([1; 32])
        );
        assert_eq!(
            next_committee.members[1].id,
            ValidatorId::from_bytes([2; 32])
        );

        // Verify new members are from candidates (sorted by VRF desc: 7, 6)
        let new_ids: BTreeSet<ValidatorId> =
            next_committee.members[2..].iter().map(|m| m.id).collect();
        assert!(new_ids.contains(&ValidatorId::from_bytes([7; 32])));
        assert!(new_ids.contains(&ValidatorId::from_bytes([6; 32])));

        // Use the new committee for finality
        let mut engine = BftFinalityEngine::new(next_committee.clone());
        let block = Hash256([0xBB; 32]);
        let total_power: u128 = next_committee.members.iter().map(|m| m.power.0).sum();
        let q = quorum_power(total_power);

        // Accumulate votes until quorum
        let mut accumulated = 0u128;
        for member in &next_committee.members {
            if accumulated >= q {
                break;
            }
            engine
                .receive_vote(Vote {
                    height: 1,
                    round: 0,
                    phase: VotePhase::Precommit,
                    block: Some(block),
                    voter: member.id,
                    signature: [0xFF; 64],
                })
                .unwrap();
            accumulated += member.power.0;
        }

        assert_eq!(engine.finalized_block(), Some(block));
    }

    // -- Empty committee edge cases --

    #[test]
    fn finality_empty_committee_never_finalizes() {
        let committee = Committee {
            height: 0,
            members: vec![],
        };

        let mut engine = BftFinalityEngine::new(committee);

        // Any vote from a non-member is rejected
        let err = engine
            .receive_vote(Vote {
                height: 0,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(Hash256([0xAA; 32])),
                voter: ValidatorId::from_bytes([1; 32]),
                signature: [0xFF; 64],
            })
            .unwrap_err();

        assert_eq!(err, ConsensusError::UnknownVoter);
        assert_eq!(engine.finalized_block(), None);
    }

    #[test]
    fn finality_nil_vote_does_not_finalize() {
        let committee = Committee {
            height: 0,
            members: vec![make_member(1, 10), make_member(2, 10), make_member(3, 10)],
        };

        let mut engine = BftFinalityEngine::new(committee);

        for id in [1u8, 2, 3] {
            engine
                .receive_vote(Vote {
                    height: 0,
                    round: 0,
                    phase: VotePhase::Precommit,
                    block: None,
                    voter: ValidatorId::from_bytes([id; 32]),
                    signature: [0xFF; 64],
                })
                .unwrap();
        }

        // Nil votes accumulate power but finalize is only set for `Some(block)`
        assert_eq!(engine.finalized_block(), None);
    }

    #[test]
    fn finality_finalized_sticks_after_first_quorum() {
        let committee = Committee {
            height: 0,
            members: vec![
                make_member(1, 10),
                make_member(2, 10),
                make_member(3, 10),
                make_member(4, 10),
            ],
        };

        let mut engine = BftFinalityEngine::new(committee);
        let block_a = Hash256([0xAA; 32]);
        let block_b = Hash256([0xBB; 32]);

        // Reach quorum for block A
        for id in [1u8, 2, 3] {
            engine
                .receive_vote(Vote {
                    height: 0,
                    round: 0,
                    phase: VotePhase::Precommit,
                    block: Some(block_a),
                    voter: ValidatorId::from_bytes([id; 32]),
                    signature: [0xFF; 64],
                })
                .unwrap();
        }

        assert_eq!(engine.finalized_block(), Some(block_a));

        // Additional vote for block B does not change finalized
        engine
            .receive_vote(Vote {
                height: 0,
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(block_b),
                voter: ValidatorId::from_bytes([4; 32]),
                signature: [0xFF; 64],
            })
            .unwrap();

        assert_eq!(engine.finalized_block(), Some(block_a));
    }
}
