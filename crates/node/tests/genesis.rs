// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Genesis activation, durable identity checks, and restart equivalence.

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use genesis::{Allocation, Genesis, GenesisValidator};
use node::{FullNodeService, NodeService, ProducerConfig};
use state::{StateDatabase, read_account};
use storage::{FileBackedStorage, NodeStorage, StorageError};
use types::{AccountState, Address, Hash256, Resources, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-genesis-node-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> PathBuf {
        self.0.join("chain.bin")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn genesis() -> Genesis {
    Genesis {
        version: 1,
        chain_id: 42,
        capacity: Resources {
            compute: 20,
            memory: 30,
            io: 40,
            bandwidth: 50,
        },
        committee_size: 2,
        rotation_count: 1,
        runtime_version: 1,
        validators: (1..=3)
            .map(|n| GenesisValidator {
                id: ValidatorId([n; 32]),
                weight: u128::from(n) << 80,
            })
            .collect(),
        allocations: vec![Allocation {
            address: Address([7; 32]),
            amount: 1234,
        }],
    }
}

fn config(genesis: &Genesis) -> ProducerConfig {
    ProducerConfig {
        chain_id: genesis.chain_id,
        block_capacity: genesis.capacity,
        ..ProducerConfig::default()
    }
}

fn advance(service: &mut FullNodeService<FileBackedStorage>, blocks: usize) {
    for _ in 0..blocks * 5 {
        service.advance().unwrap();
    }
}

#[test]
fn genesis_survives_restart_and_matches_uninterrupted_production() {
    let fixture = Fixture::new();
    let uninterrupted = Fixture::new();
    let genesis = genesis();
    let mut service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    assert_eq!(service.height(), 1);
    assert_eq!(service.storage().block_count(), 0);
    assert_eq!(
        service.finalized_block(),
        Some(genesis.commitment().unwrap())
    );
    assert_eq!(
        service.storage().state().root(),
        genesis.materialize().unwrap().root()
    );
    let committee = service.committee().unwrap();
    assert_eq!(committee.members.len(), genesis.committee_size);
    assert_eq!(committee.members[1].power.0, genesis.validators[1].weight);
    advance(&mut service, 1);
    let first = service.storage().checkpoint().unwrap();
    let block = service.storage().get_block(&first.block).unwrap();
    assert_eq!(block.header.height, 1);
    assert_eq!(block.header.parent, genesis.commitment().unwrap());
    assert_eq!(block.header.capacity, genesis.capacity);
    drop(service);
    let mut service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    assert_eq!(service.height(), 2);
    assert_eq!(service.committee().unwrap().height, 2);
    advance(&mut service, 2);
    let snapshot = service.storage().state().snapshot().unwrap();
    assert_eq!(
        read_account(snapshot.as_ref(), Address([7; 32])).unwrap(),
        Some(AccountState {
            nonce: 0,
            balance: 1234
        })
    );
    let mut reference =
        FullNodeService::open_with_genesis(config(&genesis), uninterrupted.path(), &genesis)
            .unwrap();
    advance(&mut reference, 3);
    assert_eq!(
        service.storage().checkpoint(),
        reference.storage().checkpoint()
    );
    assert_eq!(
        fs::read(fixture.path()).unwrap(),
        fs::read(uninterrupted.path()).unwrap()
    );
}

#[test]
fn mismatches_missing_genesis_and_reinitialization_preserve_archive() {
    let fixture = Fixture::new();
    let genesis = genesis();
    let mut service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    for blocks in [0, 2] {
        advance(&mut service, blocks);
        drop(service);
        let before = fs::read(fixture.path()).unwrap();
        assert!(FullNodeService::open(config(&genesis), fixture.path()).is_err());
        for changed in [
            Genesis {
                chain_id: 43,
                ..genesis.clone()
            },
            Genesis {
                runtime_version: 2,
                ..genesis.clone()
            },
            Genesis {
                allocations: vec![],
                ..genesis.clone()
            },
        ] {
            assert!(
                FullNodeService::open_with_genesis(config(&changed), fixture.path(), &changed)
                    .is_err()
            );
        }
        let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
        assert_eq!(
            storage.initialize_genesis(
                genesis.commitment().unwrap(),
                genesis.materialize().unwrap()
            ),
            Err(StorageError::InvalidOrder)
        );
        drop(storage);
        assert_eq!(before, fs::read(fixture.path()).unwrap());
        service =
            FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
        assert_eq!(before, fs::read(fixture.path()).unwrap());
    }
}

#[test]
fn existing_legacy_chain_is_not_converted() {
    let fixture = Fixture::new();
    let genesis = genesis();
    let mut service = FullNodeService::open(config(&genesis), fixture.path()).unwrap();
    advance(&mut service, 1);
    drop(service);
    let before = fs::read(fixture.path()).unwrap();
    assert!(
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).is_err()
    );
    assert_eq!(before, fs::read(fixture.path()).unwrap());
}

#[test]
fn invalid_genesis_and_producer_config_fail_before_archive_creation() {
    let fixture = Fixture::new();
    let genesis = genesis();
    assert!(
        FullNodeService::open_with_genesis(ProducerConfig::default(), fixture.path(), &genesis)
            .is_err()
    );
    let invalid = Genesis {
        version: 2,
        ..genesis
    };
    assert!(
        FullNodeService::open_with_genesis(config(&invalid), fixture.path(), &invalid).is_err()
    );
    assert!(!fixture.path().exists());
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 0);
}

#[test]
fn failed_genesis_publication_can_be_retried_without_partial_state() {
    let fixture = Fixture::new();
    let genesis = genesis();
    let mut storage = FileBackedStorage::open(fixture.path()).unwrap();
    let before = fs::read(fixture.path()).unwrap();
    assert_eq!(
        storage.initialize_genesis(Hash256::ZERO, genesis.materialize().unwrap()),
        Err(StorageError::VerificationFailed)
    );
    let pending = fixture.0.join("chain.bin.pending");
    fs::create_dir(&pending).unwrap();
    assert_eq!(
        storage.initialize_genesis(
            genesis.commitment().unwrap(),
            genesis.materialize().unwrap()
        ),
        Err(StorageError::Io)
    );
    assert!(storage.recover().unwrap().is_none());
    assert!(storage.state().is_empty());
    assert_eq!(before, fs::read(fixture.path()).unwrap());
    fs::remove_dir(pending).unwrap();
    storage
        .initialize_genesis(
            genesis.commitment().unwrap(),
            genesis.materialize().unwrap(),
        )
        .unwrap();
    drop(storage);
    let service =
        FullNodeService::open_with_genesis(config(&genesis), fixture.path(), &genesis).unwrap();
    assert_eq!(service.height(), 1);
}
