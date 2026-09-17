// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fast BFT finality engine.

use std::collections::BTreeMap;

use crate::committee::Committee;
use crate::error::ConsensusError;
use crate::vote::{Vote, VotePhase};
use crate::weight::{PotbWeight, quorum_power};
use types::{Hash256, ValidatorId};

/// Fast-finality state machine boundary.
pub trait FinalityEngine {
    /// Validates and records a vote without executing transactions.
    fn receive_vote(&mut self, vote: Vote) -> Result<(), ConsensusError>;

    /// Returns a block only after a valid precommit quorum exists.
    fn finalized_block(&self) -> Option<Hash256>;
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

/// Wrapper for `(Option<Hash256>, VotePhase)` to derive `Ord`.
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
    committee: Committee,
    total_power: PotbWeight,
    votes: BTreeMap<VoteKey, Option<Hash256>>,
    power: BTreeMap<PowerKey, PotbWeight>,
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
    use crate::committee::{Committee, CommitteeMember};
    use crate::weight::PotbWeight;
    use types::ValidatorId;

    fn make_member(id: u8, power: u128) -> CommitteeMember {
        CommitteeMember {
            id: ValidatorId::from_bytes([id; 32]),
            power: PotbWeight(power),
        }
    }

    #[test]
    fn reaches_quorum() {
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
    fn not_reached_before_quorum() {
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

        assert_eq!(engine.finalized_block(), None);
    }

    #[test]
    fn rejects_duplicate_vote() {
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
    fn rejects_unknown_voter() {
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
    fn allows_different_phases_for_same_height_round() {
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
    fn only_precommit_triggers_finalization() {
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

        assert_eq!(engine.finalized_block(), None);
    }

    #[test]
    fn empty_committee_never_finalizes() {
        let committee = Committee {
            height: 0,
            members: vec![],
        };

        let mut engine = BftFinalityEngine::new(committee);

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
    fn nil_vote_does_not_finalize() {
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

        assert_eq!(engine.finalized_block(), None);
    }

    #[test]
    fn finalized_sticks_after_first_quorum() {
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
