// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Local voting, proof validation, durable lock recovery, and adversarial schedules.

use consensus::{
    AuthenticatedCommittee, BftFinalityEngine, Committee, CommitteeMember, ConsensusError,
    FinalityEngine, LocalBft, LocalBftError, PotbWeight, PrevoteCertificate, Vote, VotePhase,
    VotingStep,
};
use keystore::{DurableSigner, KeystoreError, SigningContext, SigningPosition, SigningSafety};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use types::{BlockHeader, Hash256, Resources, ValidatorId};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-local-bft-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, seed: u8) -> PathBuf {
        self.0.join(format!("validator-{seed}.bin"))
    }
    fn create(&self, seed: u8) -> LocalBft {
        let signer =
            DurableSigner::create_protected(self.path(seed), namespace(), [seed; 32]).unwrap();
        LocalBft::new(context(), signer, namespace().genesis).unwrap()
    }
    fn reopen(&self, seed: u8) -> LocalBft {
        LocalBft::new(
            context(),
            DurableSigner::open(self.path(seed), namespace(), [seed; 32]).unwrap(),
            namespace().genesis,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn namespace() -> SigningContext {
    SigningContext {
        chain_id: 7,
        genesis: Hash256([8; 32]),
    }
}
fn public(seed: u8) -> [u8; 32] {
    crypto::blake2s::ed25519_public_key(&[seed; 32])
}
fn identity(seed: u8) -> ValidatorId {
    ValidatorId(crypto::blake2s_hash(&public(seed)).0)
}
fn context_at(chain: u32, height: u64, weight: u128) -> AuthenticatedCommittee {
    let members = (1..=4)
        .map(|seed| CommitteeMember {
            id: identity(seed),
            power: PotbWeight(weight),
        })
        .collect();
    AuthenticatedCommittee::new(
        chain,
        &Committee { height, members },
        &[public(1), public(2), public(3), public(4)],
    )
    .unwrap()
}
fn context() -> AuthenticatedCommittee {
    context_at(7, 42, 1)
}
fn header(tag: u8) -> BlockHeader {
    BlockHeader {
        height: 42,
        parent: Hash256([1; 32]),
        transactions_root: Hash256([2; 32]),
        state_root: Hash256([tag; 32]),
        receipts_root: Hash256([4; 32]),
        committee_root: context().root(),
        capacity: Resources::ZERO,
    }
}
fn votes(
    context: &AuthenticatedCommittee,
    block: Option<Hash256>,
    round: u32,
    phase: VotePhase,
) -> Vec<Vote> {
    let mut votes: Vec<_> = (1..=3)
        .map(|seed| {
            let mut vote = Vote {
                chain_id: context.chain_id(),
                height: context.height(),
                committee_root: context.root(),
                round,
                phase,
                block,
                voter: identity(seed),
                signature: [0; 64],
            };
            vote.signature = crypto::blake2s::ed25519_sign(&[seed; 32], &vote.signing_hash().0);
            vote
        })
        .collect();
    votes.sort_by_key(|vote| vote.voter);
    votes
}
fn proof(header: &BlockHeader, round: u32) -> PrevoteCertificate {
    PrevoteCertificate::from_votes(
        &context(),
        votes(
            &context(),
            Some(header.compute_hash()),
            round,
            VotePhase::Prevote,
        ),
    )
    .unwrap()
}
fn lock(local: &mut LocalBft, header: &BlockHeader) {
    assert_eq!(
        local.prevote(Some(header), None, |_| true).unwrap().block,
        Some(header.compute_hash())
    );
    local
        .precommit(header, &proof(header, local.round()), |_| true)
        .unwrap();
}

#[test]
fn local_votes_survive_restart_and_form_finality_with_execution_validation() {
    let fixture = Fixture::new();
    let header = header(3);
    let mut collector = BftFinalityEngine::new(context());
    for seed in 1..=3 {
        let mut local = fixture.create(seed);
        collector
            .receive_vote(local.prevote(Some(&header), None, |_| true).unwrap())
            .unwrap();
    }
    assert_eq!(collector.finalized_block(), None);
    let proof = collector
        .prevote_certificate(header.compute_hash())
        .unwrap();
    for seed in 1..=3 {
        let mut local = fixture.reopen(seed);
        assert_eq!(local.step(), VotingStep::Prevoted);
        assert!(local.precommit(&header, &proof, |_| false).is_err());
        assert_eq!(local.locked(), None);
        let vote = local.precommit(&header, &proof, |_| true).unwrap();
        collector.receive_vote(vote.clone()).unwrap();
        drop(local);
        let mut restored = fixture.reopen(seed);
        assert_eq!(restored.precommit(&header, &proof, |_| true).unwrap(), vote);
        assert_eq!(restored.locked().unwrap().block, header.compute_hash());
        assert!(restored.timeout_prevote(0).is_err());
    }
    let certificate = collector.certificate().unwrap();
    let mut observer = fixture.create(4);
    assert!(observer.finalize(&header, certificate, |_| false).is_err());
    assert_eq!(observer.step(), VotingStep::AwaitingProposal);
    observer.finalize(&header, certificate, |_| true).unwrap();
    assert_eq!(observer.finalized_block(), Some(header.compute_hash()));
    assert!(observer.prevote(Some(&header), None, |_| true).is_err());
    assert!(observer.timeout_proposal(0).is_err());
}

#[test]
fn timeout_and_nil_votes_retain_lock_until_a_newer_proof_authorizes_change() {
    let fixture = Fixture::new();
    let a = header(3);
    let b = header(5);
    let mut local = fixture.create(1);
    lock(&mut local, &a);
    local.timeout_precommit(0).unwrap();
    assert_eq!(local.prevote(Some(&b), None, |_| true).unwrap().block, None);
    assert_eq!(local.timeout_prevote(1).unwrap().block, None);
    assert_eq!(local.locked().unwrap().block, a.compute_hash());
    drop(local);
    let mut local = fixture.reopen(1);
    assert_eq!(local.round(), 1);
    local.timeout_precommit(1).unwrap();
    // Equal/older proof cannot release a lock, even when independently authenticated.
    assert_eq!(
        local
            .prevote(Some(&b), Some(&proof(&b, 0)), |_| true)
            .unwrap()
            .block,
        None
    );
    local.timeout_prevote(2).unwrap();
    local.timeout_precommit(2).unwrap();
    assert_eq!(
        local
            .prevote(Some(&b), Some(&proof(&b, 2)), |_| true)
            .unwrap()
            .block,
        Some(b.compute_hash())
    );
    assert_eq!(local.locked().unwrap().block, a.compute_hash());
    local.precommit(&b, &proof(&b, 3), |_| true).unwrap();
    assert_eq!(local.locked().unwrap().round, 3);
    drop(local);
    assert_eq!(fixture.reopen(1).locked().unwrap().block, b.compute_hash());
}

#[test]
fn invalid_proofs_stale_timers_and_conflicting_slot_retries_cannot_change_decisions() {
    let fixture = Fixture::new();
    let a = header(3);
    let b = header(5);
    let mut local = fixture.create(1);
    assert!(local.precommit(&a, &proof(&a, 0), |_| true).is_err());
    assert!(local.timeout_precommit(0).is_err());
    assert!(
        local
            .prevote(Some(&a), Some(&proof(&a, 0)), |_| true)
            .is_err()
    );
    assert_eq!(local.step(), VotingStep::AwaitingProposal);
    let first = local.prevote(Some(&a), None, |_| true).unwrap();
    assert_eq!(local.prevote(Some(&a), None, |_| true).unwrap(), first);
    assert_eq!(
        local.prevote(Some(&b), None, |_| true),
        Err(LocalBftError::Signing(KeystoreError::ConflictingSign))
    );
    assert!(local.timeout_proposal(0).is_err());
    assert!(local.precommit(&a, &proof(&a, 1), |_| true).is_err());
    local.timeout_prevote(0).unwrap();
    local.timeout_precommit(0).unwrap();
    assert!(local.timeout_proposal(0).is_err());
    assert!(
        local
            .prevote(Some(&a), Some(&proof(&b, 0)), |_| true)
            .is_err()
    );
    let other = context_at(8, 42, 1);
    let other_proof = PrevoteCertificate::from_votes(
        &other,
        votes(&other, Some(a.compute_hash()), 0, VotePhase::Prevote),
    )
    .unwrap();
    assert!(
        local
            .prevote(Some(&a), Some(&other_proof), |_| true)
            .is_err()
    );
    assert_eq!(local.step(), VotingStep::AwaitingProposal);
    assert_eq!(local.timeout_proposal(1).unwrap().block, None);
}

#[test]
fn invalid_proposal_validation_always_yields_nil_without_locking() {
    let fixture = Fixture::new();
    let mut local = fixture.create(1);
    let mut invalid = header(3);
    invalid.height += 1;
    assert_eq!(
        local.prevote(Some(&invalid), None, |_| true).unwrap().block,
        None
    );
    invalid = header(3);
    invalid.committee_root = Hash256::ZERO;
    assert_eq!(
        local.prevote(Some(&invalid), None, |_| true).unwrap().block,
        None
    );
    assert_eq!(
        local
            .prevote(Some(&header(3)), None, |_| false)
            .unwrap()
            .block,
        None
    );
    assert_eq!(local.locked(), None);
}

#[test]
fn restart_cannot_erase_quorum_locks_to_create_a_conflicting_prevote_quorum() {
    let fixture = Fixture::new();
    let a = header(3);
    let b = header(5);
    for seed in 1..=4 {
        let mut local = fixture.create(seed);
        if seed <= 3 {
            lock(&mut local, &a);
        } else {
            local.timeout_proposal(0).unwrap();
            local.timeout_prevote(0).unwrap();
        }
    }
    for round in 1..=3 {
        let mut alternate = Vec::new();
        for seed in 1..=4 {
            let mut local = fixture.reopen(seed);
            local.timeout_precommit(round - 1).unwrap();
            let vote = local.prevote(Some(&b), None, |_| true).unwrap();
            if seed <= 3 {
                assert_eq!(vote.block, None);
            }
            if vote.block.is_some() {
                alternate.push(vote);
            }
            local.timeout_prevote(round).unwrap();
        }
        alternate.sort_by_key(|vote| vote.voter);
        assert_eq!(
            PrevoteCertificate::from_votes(&context(), alternate),
            Err(ConsensusError::InvalidCertificate)
        );
    }
}

#[test]
fn resume_rejects_wrong_context_and_raw_journals_and_round_exhaustion_is_checked() {
    let fixture = Fixture::new();
    let raw = DurableSigner::create(fixture.path(1), namespace(), [1; 32]).unwrap();
    assert!(LocalBft::new(context(), raw, namespace().genesis).is_err());
    let signer = DurableSigner::create_protected(fixture.path(2), namespace(), [2; 32]).unwrap();
    assert!(LocalBft::new(context(), signer, Hash256([9; 32])).is_err());
    let mut signer = DurableSigner::open(fixture.path(2), namespace(), [2; 32]).unwrap();
    let safety = SigningSafety {
        committee_root: context().root(),
        locked: None,
    };
    signer
        .sign_protected(
            &signer.key_handle(),
            SigningPosition {
                height: 42,
                round: u32::MAX,
                phase: 2,
            },
            Hash256([6; 32]),
            safety,
        )
        .unwrap();
    let mut local = LocalBft::new(context(), signer, namespace().genesis).unwrap();
    assert!(local.timeout_precommit(u32::MAX).is_err());
    assert_eq!(local.round(), u32::MAX);
    drop(local);
    for alternate in [context_at(7, 41, 1), context_at(7, 42, 2)] {
        let signer = DurableSigner::open(fixture.path(2), namespace(), [2; 32]).unwrap();
        assert!(LocalBft::new(alternate, signer, namespace().genesis).is_err());
    }
    let signer = DurableSigner::open(fixture.path(2), namespace(), [2; 32]).unwrap();
    let next = LocalBft::new(context_at(7, 43, 1), signer, namespace().genesis).unwrap();
    assert_eq!(
        (next.round(), next.step(), next.locked()),
        (0, VotingStep::AwaitingProposal, None)
    );
}

#[test]
fn prevote_proofs_reject_duplicates_mixed_contexts_phase_changes_and_tampering() {
    let context = context();
    let block = Some(header(3).compute_hash());
    let original = votes(&context, block, 0, VotePhase::Prevote);
    for kind in 0..6 {
        let mut changed = original.clone();
        match kind {
            0 => {
                changed.pop();
            }
            1 => changed[1] = changed[0].clone(),
            2 => changed.reverse(),
            3 => changed[0].round += 1,
            4 => changed[0].signature[0] ^= 1,
            _ => changed[0].phase = VotePhase::Precommit,
        }
        assert!(PrevoteCertificate::from_votes(&context, changed).is_err());
    }
    for phase in [VotePhase::Prevote, VotePhase::Precommit] {
        assert!(PrevoteCertificate::from_votes(&context, votes(&context, None, 0, phase)).is_err());
    }
    let certificate = PrevoteCertificate::from_votes(&context, original).unwrap();
    let bytes = certificate.encode();
    assert_eq!(
        PrevoteCertificate::decode(&context, &bytes).unwrap(),
        certificate
    );
    for length in 0..bytes.len() {
        assert!(PrevoteCertificate::decode(&context, &bytes[..length]).is_err());
    }
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(PrevoteCertificate::decode(&context, &changed).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(PrevoteCertificate::decode(&context, &trailing).is_err());
}
