// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Signed account execution, durable local BFT voting, finality, and archive recovery.

use consensus::{
    AuthenticatedCommittee, BftFinalityEngine, Committee, CommitteeMember, FinalityCertificate,
    FinalityEngine, LocalBft, PotbWeight, VotingStep,
};
use genesis::{Allocation, Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use node::{BlockProducer, ProducerConfig};
use state::{StateDatabase, read_account};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use storage::FileBackedStorage;
use types::{AccountState, Address, Hash256, Resources, Transaction, TransactionLane, ValidatorId};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "astrolune-bft-pipeline-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn journal(&self, seed: u8) -> PathBuf {
        self.0.join(format!("signer-{seed}.bin"))
    }
    fn archive(&self) -> PathBuf {
        self.0.join("chain.bin")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn public(seed: u8) -> [u8; 32] {
    crypto::blake2s::ed25519_public_key(&[seed; 32])
}
fn address(seed: u8) -> Address {
    transaction::address_from_public_key(&public(seed))
}
fn genesis() -> Genesis {
    let mut validators: Vec<_> = (1..=4)
        .map(|seed| GenesisValidator {
            id: ValidatorId(crypto::blake2s_hash(&public(seed)).0),
            weight: 1,
        })
        .collect();
    validators.sort_by_key(|validator| validator.id);
    Genesis {
        version: 1,
        chain_id: 7,
        capacity: ProducerConfig::default().block_capacity,
        committee_size: 4,
        rotation_count: 1,
        runtime_version: 1,
        validators,
        allocations: vec![Allocation {
            address: address(9),
            amount: 1000,
        }],
    }
}
fn context(genesis: &Genesis, height: u64) -> AuthenticatedCommittee {
    let members = genesis
        .validators
        .iter()
        .map(|validator| CommitteeMember {
            id: validator.id,
            power: PotbWeight(validator.weight),
        })
        .collect();
    AuthenticatedCommittee::new(
        genesis.chain_id,
        &Committee { height, members },
        &[public(1), public(2), public(3), public(4)],
    )
    .unwrap()
}
fn payment() -> Transaction {
    let mut access_list = vec![
        state::account_key(address(9)),
        state::account_key(address(10)),
    ];
    access_list.sort();
    let mut tx = Transaction {
        version: types::TRANSACTION_VERSION,
        chain_id: 7,
        nonce: 0,
        expires_at: 1,
        sender: address(9),
        lane: TransactionLane::Payments,
        access_list,
        resource_limit: Resources::ZERO,
        resource_prices: execution::PAYMENT_PRICES,
        payload: transaction::Payment {
            public_key: public(9),
            recipient: address(10),
            amount: 10,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature = crypto::blake2s::ed25519_sign(&[9; 32], &transaction::signing_hash(&tx).0);
    tx
}

#[test]
fn payment_is_committed_only_after_validated_local_votes_and_durable_certificate() {
    let fixture = Fixture::new();
    let genesis = genesis();
    let genesis_hash = genesis.commitment().unwrap();
    let namespace = SigningContext {
        chain_id: 7,
        genesis: genesis_hash,
    };
    let mut storage = FileBackedStorage::open(fixture.archive()).unwrap();
    let anchor = storage
        .initialize_genesis(genesis_hash, genesis.materialize().unwrap())
        .unwrap();
    let mut producer = BlockProducer::from_checkpoint(
        ProducerConfig::default(),
        Some(anchor),
        storage.state().clone(),
    )
    .unwrap();
    producer.submit_transaction(payment()).unwrap();
    let committee = context(&genesis, 1);
    let proposal = producer.produce_block_for_committee(&committee).unwrap();
    let before = producer.state().root();
    producer.validate_proposal(&proposal).unwrap();
    assert_eq!(producer.state().root(), before);
    assert_eq!(producer.pending_count(), 1);
    let mut invalid = proposal.clone();
    invalid.block.header.state_root = Hash256::ZERO;
    assert!(producer.validate_proposal(&invalid).is_err());
    let mut collector = BftFinalityEngine::new(context(&genesis, 1));
    for seed in 1..=4 {
        let signer =
            DurableSigner::create_protected(fixture.journal(seed), namespace, [seed; 32]).unwrap();
        let mut local = LocalBft::new(context(&genesis, 1), signer, genesis_hash).unwrap();
        // This in-process fixture supplies the authorized proposal; execution is rechecked.
        let vote = local
            .prevote(Some(&proposal.block.header), None, |header| {
                *header == proposal.block.header && producer.validate_proposal(&proposal).is_ok()
            })
            .unwrap();
        collector.receive_vote(vote).unwrap();
    }
    let proof = collector
        .prevote_certificate(proposal.block.header.compute_hash())
        .unwrap();
    for seed in 1..=3 {
        let signer = DurableSigner::open(fixture.journal(seed), namespace, [seed; 32]).unwrap();
        let mut local = LocalBft::new(context(&genesis, 1), signer, genesis_hash).unwrap();
        assert_eq!(local.step(), VotingStep::Prevoted);
        let vote = local
            .precommit(&proposal.block.header, &proof, |_| {
                producer.validate_proposal(&proposal).is_ok()
            })
            .unwrap();
        collector.receive_vote(vote).unwrap();
    }
    let certificate = collector.certificate().unwrap().clone();
    let signer = DurableSigner::open(fixture.journal(4), namespace, [4; 32]).unwrap();
    let mut observer = LocalBft::new(context(&genesis, 1), signer, genesis_hash).unwrap();
    observer
        .finalize(&proposal.block.header, &certificate, |_| {
            producer.validate_proposal(&proposal).is_ok()
        })
        .unwrap();
    let pending = fixture.0.join("chain.bin.pending");
    fs::create_dir(&pending).unwrap();
    assert!(
        producer
            .commit_certified_block(&proposal, &certificate, &committee, &mut storage)
            .is_err()
    );
    fs::remove_dir(&pending).unwrap();
    assert_eq!(producer.state().root(), before);
    assert_eq!(producer.pending_count(), 1);
    let checkpoint = producer
        .commit_certified_block(&proposal, &certificate, &committee, &mut storage)
        .unwrap();
    assert_eq!(producer.pending_count(), 0);
    drop(storage);
    let storage = FileBackedStorage::open(fixture.archive()).unwrap();
    let recovered =
        FinalityCertificate::decode(storage.get_certificate(&checkpoint.block).unwrap()).unwrap();
    context(&genesis, 1)
        .verify_certificate(
            &recovered,
            &storage.get_block(&checkpoint.block).unwrap().header,
        )
        .unwrap();
    let state = storage.state().snapshot().unwrap();
    assert_eq!(
        read_account(state.as_ref(), address(9)).unwrap(),
        Some(AccountState {
            nonce: 1,
            balance: 989
        })
    );
    assert_eq!(
        read_account(state.as_ref(), address(10)).unwrap(),
        Some(AccountState {
            nonce: 0,
            balance: 10
        })
    );
}
