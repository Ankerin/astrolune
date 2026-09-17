// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Proof of Trusted Behavior committee selection and fast `BFT` finality.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

pub mod committee;
pub mod error;
pub mod finality;
pub mod sampler;
pub mod vote;
pub mod weight;

pub use committee::{Candidate, Committee, CommitteeMember, CommitteeSelector};
pub use error::ConsensusError;
pub use finality::{BftFinalityEngine, FinalityEngine};
pub use sampler::WeightedSampler;
pub use vote::{Vote, VotePhase};
pub use weight::{quorum_power, PotbWeight};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::{Candidate, Committee, CommitteeMember};
    use crate::weight::PotbWeight;
    use crypto::VrfOutput;
    use std::collections::BTreeSet;
    use types::{Hash256, ValidatorId};

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

        let next_committee = sampler.rotate(&initial_committee, &candidates, 2);
        assert_eq!(next_committee.height, 1);
        assert_eq!(next_committee.members.len(), 4);

        assert_eq!(
            next_committee.members[0].id,
            ValidatorId::from_bytes([1; 32])
        );
        assert_eq!(
            next_committee.members[1].id,
            ValidatorId::from_bytes([2; 32])
        );

        let new_ids: BTreeSet<ValidatorId> =
            next_committee.members[2..].iter().map(|m| m.id).collect();
        assert!(new_ids.contains(&ValidatorId::from_bytes([7; 32])));
        assert!(new_ids.contains(&ValidatorId::from_bytes([6; 32])));

        let mut engine = BftFinalityEngine::new(next_committee.clone());
        let block = Hash256([0xBB; 32]);
        let total_power: u128 = next_committee.members.iter().map(|m| m.power.0).sum();
        let q = quorum_power(total_power);

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
}
