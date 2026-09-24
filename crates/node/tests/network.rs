// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Distributed message delivery, durable recovery, and adversarial reference-network checks.

use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use node::{
    network::{NetworkNode, StaticNetwork},
    network_wire::{NetworkMessage, SyncRequest, decode_exchange, encode_exchange},
    observer::ObserverNode,
};
use state::StateDatabase;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use transaction::{Payment, address_from_public_key, signing_hash};
use types::{AccountState, Address, Hash256, Resources, Transaction, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
    network: StaticNetwork,
    genesis: Genesis,
}
impl Fixture {
    fn new(count: u8) -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-network-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let keys: Vec<_> = (1..=count)
            .map(|index| ed25519_public_key(&[index; 32]))
            .collect();
        let mut validators: Vec<_> = keys
            .iter()
            .map(|key| GenesisValidator {
                id: ValidatorId(blake2s(key).0),
                weight: 1,
            })
            .collect();
        validators.sort_by_key(|validator| validator.id);
        let genesis = Genesis {
            version: 1,
            chain_id: 42,
            committee_size: usize::from(count),
            rotation_count: 1,
            runtime_version: 1,
            capacity: Resources {
                compute: 1_000_000,
                memory: 1_000_000,
                io: 1_000_000,
                bandwidth: 1_000_000,
            },
            validators,
            allocations: vec![Allocation {
                address: address_from_public_key(&ed25519_public_key(&[99; 32])),
                amount: 1_000_000,
            }],
        };
        let network = StaticNetwork::new(genesis.clone(), keys).unwrap();
        for index in 1..=count {
            let directory = path.join(index.to_string());
            std::fs::create_dir(&directory).unwrap();
            drop(
                DurableSigner::create_protected(
                    directory.join("signing.journal"),
                    SigningContext {
                        chain_id: 42,
                        genesis: network.genesis_hash(),
                    },
                    [index; 32],
                )
                .unwrap(),
            );
        }
        Self {
            path,
            network,
            genesis,
        }
    }
    fn open(&self, index: u8) -> NetworkNode {
        let directory = self.path.join(index.to_string());
        let signer = DurableSigner::open(
            directory.join("signing.journal"),
            SigningContext {
                chain_id: 42,
                genesis: self.network.genesis_hash(),
            },
            [index; 32],
        )
        .unwrap();
        NetworkNode::open(
            self.network.clone(),
            &directory,
            signer,
            Duration::from_millis(100),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn exchange(nodes: &mut [NetworkNode], now: Instant) {
    for index in 0..nodes.len() {
        let request = nodes[index].request();
        let responses: Vec<_> = nodes
            .iter()
            .map(|node| node.respond(request).unwrap())
            .collect();
        for response in responses {
            nodes[index].receive(&response).unwrap();
        }
        nodes[index].tick(now).unwrap();
    }
}

fn transfer() -> Transaction {
    let key = ed25519_public_key(&[99; 32]);
    let sender = address_from_public_key(&key);
    let recipient = Address([77; 32]);
    let mut access_list = vec![state::account_key(sender), state::account_key(recipient)];
    access_list.sort();
    let mut tx = Transaction {
        version: 1,
        chain_id: 42,
        sender,
        nonce: 0,
        expires_at: 100,
        lane: types::TransactionLane::Payments,
        resource_prices: Resources {
            compute: 1,
            ..Resources::ZERO
        },
        access_list,
        resource_limit: Resources::ZERO,
        payload: Payment {
            public_key: key,
            recipient,
            amount: 123,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature = ed25519_sign(&[99; 32], signing_hash(&tx).as_bytes());
    tx
}

#[test]
fn payment_gossip_three_of_four_commit_and_late_node_catches_up_after_restart() {
    let fixture = Fixture::new(4);
    let mut nodes: Vec<_> = (1..=3).map(|index| fixture.open(index)).collect();
    let tx = transfer();
    nodes[0].submit_transaction(tx.clone()).unwrap();
    let started = Instant::now();
    for step in 0..400 {
        exchange(&mut nodes, started + Duration::from_millis(step * 20));
        if nodes.iter().all(|node| node.request().height >= 5) {
            break;
        }
    }
    assert!(
        nodes.iter().all(|node| node.request().height >= 5),
        "one offline validator must not prevent quorum progress"
    );
    // Stop producing and catch every node up to the same certified head.
    let highest = nodes
        .iter()
        .map(|node| node.request().height)
        .max()
        .unwrap();
    let source = nodes
        .iter()
        .position(|node| node.request().height == highest)
        .unwrap();
    for index in 0..nodes.len() {
        while nodes[index].request().height < highest {
            let bytes = nodes[source].respond(nodes[index].request()).unwrap();
            nodes[index].receive(&bytes).unwrap();
        }
    }
    let checkpoint = *nodes[0].storage().checkpoint().unwrap();
    assert!(
        nodes
            .iter()
            .all(|node| node.storage().checkpoint() == Some(&checkpoint))
    );
    let state = nodes[0].storage().state().snapshot().unwrap();
    assert_eq!(
        state::read_account(state.as_ref(), Address([77; 32])).unwrap(),
        Some(AccountState {
            nonce: 0,
            balance: 123
        })
    );
    drop(nodes);
    let source = fixture.open(1);
    let mut late = fixture.open(4);
    while late.request().height < source.request().height {
        late.receive(&source.respond(late.request()).unwrap())
            .unwrap();
    }
    assert_eq!(late.storage().checkpoint(), source.storage().checkpoint());
    assert_eq!(
        late.storage().state().root(),
        source.storage().state().root()
    );
    assert!(
        late.submit_transaction(tx).is_err(),
        "finalized nonce must reject replay"
    );
}

#[test]
fn two_of_four_never_finalize_and_forged_input_cannot_advance_state() {
    let fixture = Fixture::new(4);
    let mut nodes = vec![fixture.open(1), fixture.open(2)];
    let started = Instant::now();
    for step in 0..100 {
        exchange(&mut nodes, started + Duration::from_millis(step * 30));
    }
    assert!(nodes.iter().all(|node| node.request().height == 1));
    assert!(nodes.iter().all(|node| node.round() > 0));
    let before = *nodes[0].storage().checkpoint().unwrap();
    let messages = vec![NetworkMessage::Vote(consensus::Vote {
        chain_id: 42,
        height: 1,
        round: nodes[0].round(),
        committee_root: fixture.network.committee(1).unwrap().root(),
        voter: fixture.genesis.validators[0].id,
        phase: consensus::VotePhase::Precommit,
        block: Some(Hash256([255; 32])),
        signature: [0; 64],
    })];
    let rejected = nodes[0]
        .receive(&encode_exchange(fixture.network.genesis_hash(), &messages).unwrap())
        .unwrap();
    assert_eq!(
        rejected, 1,
        "forged signature from a registered member must be rejected"
    );
    assert_eq!(nodes[0].storage().checkpoint(), Some(&before));
    assert!(
        nodes[0]
            .respond(SyncRequest {
                genesis: Hash256([1; 32]),
                height: 1
            })
            .is_err()
    );
    assert!(
        nodes[0]
            .receive(&encode_exchange(Hash256([1; 32]), &[]).unwrap())
            .is_err()
    );
}

#[test]
fn all_nodes_restart_after_precommit_and_recover_the_payment_body() {
    let fixture = Fixture::new(4);
    let mut nodes: Vec<_> = (1..=4).map(|index| fixture.open(index)).collect();
    for node in &mut nodes {
        node.submit_transaction(transfer()).unwrap();
    }
    let now = Instant::now();
    // Propose, distribute proposals/prevotes, then lock without delivering precommits.
    for node in &mut nodes {
        node.tick(now).unwrap();
    }
    let request = nodes[0].request();
    for _ in 0..2 {
        let responses: Vec<_> = nodes
            .iter()
            .map(|node| node.respond(request).unwrap())
            .collect();
        for node in &mut nodes {
            for bytes in &responses {
                node.receive(bytes).unwrap();
            }
        }
    }
    for node in &mut nodes {
        node.tick(now).unwrap();
    }
    assert!(nodes.iter().all(|node| node.request().height == 1));
    drop(nodes);
    let mut nodes: Vec<_> = (1..=4).map(|index| fixture.open(index)).collect();
    for step in 0..40 {
        exchange(&mut nodes, now + Duration::from_millis(step * 10));
        if nodes.iter().all(|node| node.request().height > 1) {
            break;
        }
    }
    assert!(nodes.iter().all(|node| node.request().height > 1));
    for node in &nodes {
        let snapshot = node.storage().state().snapshot().unwrap();
        assert_eq!(
            state::read_account(snapshot.as_ref(), Address([77; 32]))
                .unwrap()
                .unwrap()
                .balance,
            123
        );
    }
}

#[test]
fn registry_and_envelopes_fail_closed() {
    let fixture = Fixture::new(1);
    assert!(
        StaticNetwork::new(fixture.genesis.clone(), vec![ed25519_public_key(&[2; 32])]).is_err()
    );
    let bytes = encode_exchange(
        fixture.network.genesis_hash(),
        &[NetworkMessage::Transaction(transfer())],
    )
    .unwrap();
    for length in 0..bytes.len() {
        assert!(decode_exchange(fixture.network.genesis_hash(), &bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_exchange(fixture.network.genesis_hash(), &trailing).is_err());
    let mut oversized = bytes.clone();
    oversized[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decode_exchange(fixture.network.genesis_hash(), &oversized).is_err());
    let decoded = decode_exchange(fixture.network.genesis_hash(), &bytes).unwrap();
    assert_eq!(
        encode_exchange(fixture.network.genesis_hash(), &decoded).unwrap(),
        bytes
    );
}

#[test]
fn locked_value_survives_round_change_when_precommits_are_lost() {
    let fixture = Fixture::new(4);
    let mut nodes: Vec<_> = (1..=4).map(|index| fixture.open(index)).collect();
    for node in &mut nodes {
        node.submit_transaction(transfer()).unwrap();
    }
    let now = Instant::now();
    for node in &mut nodes {
        node.tick(now).unwrap();
    }
    let request = nodes[0].request();
    for _ in 0..2 {
        let responses: Vec<_> = nodes
            .iter()
            .map(|node| node.respond(request).unwrap())
            .collect();
        for node in &mut nodes {
            for bytes in &responses {
                node.receive(bytes).unwrap();
            }
        }
    }
    for node in &mut nodes {
        node.tick(now).unwrap();
    }
    // Every node locked the available payment, but no precommit was delivered.
    for node in &mut nodes {
        node.tick(now + Duration::from_millis(101)).unwrap();
    }
    assert!(nodes.iter().all(|node| node.round() == 1));
    for step in 0..40 {
        exchange(&mut nodes, now + Duration::from_millis(102 + step));
        if nodes.iter().all(|node| node.request().height > 1) {
            break;
        }
    }
    assert!(nodes.iter().all(|node| node.request().height > 1));
    for node in &nodes {
        let snapshot = node.storage().state().snapshot().unwrap();
        assert_eq!(
            state::read_account(snapshot.as_ref(), Address([77; 32]))
                .unwrap()
                .unwrap()
                .balance,
            123
        );
    }
}

#[test]
fn demonstration_history_is_rejected_before_network_signing() {
    use node::{FullNodeService, NodeService, ProducerConfig};
    let fixture = Fixture::new(1);
    let path = fixture.path.join("1");
    let mut demo = FullNodeService::open_with_genesis(
        ProducerConfig {
            chain_id: 42,
            block_capacity: fixture.genesis.capacity,
            ..ProducerConfig::default()
        },
        path.join("chain.bin"),
        &fixture.genesis,
    )
    .unwrap();
    for _ in 0..5 {
        demo.advance().unwrap();
    }
    drop(demo);
    let signer = DurableSigner::open(
        path.join("signing.journal"),
        SigningContext {
            chain_id: 42,
            genesis: fixture.network.genesis_hash(),
        },
        [1; 32],
    )
    .unwrap();
    assert!(
        NetworkNode::open(
            fixture.network.clone(),
            &path,
            signer,
            Duration::from_millis(100)
        )
        .is_err()
    );
}

#[test]
fn certified_history_cannot_be_downgraded_to_demonstration_finality() {
    let fixture = Fixture::new(1);
    let mut node = fixture.open(1);
    let now = Instant::now();
    for step in 0..4 {
        node.tick(now + Duration::from_millis(step)).unwrap();
        if node.request().height > 1 {
            break;
        }
    }
    assert_eq!(node.request().height, 2);
    drop(node);
    let archive = fixture.path.join("1/chain.bin");
    let bytes = std::fs::read(&archive).unwrap();
    let config = node::ProducerConfig {
        chain_id: 42,
        block_capacity: fixture.genesis.capacity,
        ..node::ProducerConfig::default()
    };
    assert!(node::FullNodeService::open_with_genesis(config, &archive, &fixture.genesis).is_err());
    assert_eq!(std::fs::read(&archive).unwrap(), bytes);
}

#[test]
fn every_network_message_has_canonical_mutation_and_truncation_behavior() {
    let fixture = Fixture::new(1);
    let mut node = fixture.open(1);
    node.submit_transaction(transfer()).unwrap();
    let request = node.request();
    let now = Instant::now();
    node.tick(now).unwrap();
    let mut messages = decode_exchange(request.genesis, &node.respond(request).unwrap()).unwrap();
    node.tick(now + Duration::from_millis(1)).unwrap();
    messages.extend(decode_exchange(request.genesis, &node.respond(request).unwrap()).unwrap());
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::Proposal { .. }))
    );
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::Vote(_)))
    );
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::Finalized { .. }))
    );
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::ValidValue { .. }))
    );
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, NetworkMessage::Transaction(_)))
    );
    let bytes = encode_exchange(request.genesis, &messages).unwrap();
    for offset in 0..bytes.len() {
        assert!(decode_exchange(request.genesis, &bytes[..offset]).is_err());
        let mut mutated = bytes.clone();
        mutated[offset] ^= 0x80;
        if let Ok(decoded) = decode_exchange(request.genesis, &mutated) {
            assert_eq!(encode_exchange(request.genesis, &decoded).unwrap(), mutated);
        }
    }
    let mut expected_request = b"ALRQ\x01\0\0\0".to_vec();
    expected_request.extend_from_slice(&request.genesis.0);
    expected_request.extend_from_slice(&1u64.to_le_bytes());
    assert_eq!(request.encode(), expected_request);
}

#[test]
fn observer_gossips_payments_syncs_relays_and_recovers_without_signing_authority() {
    let fixture = Fixture::new(1);
    let path = fixture.path.join("observer");
    let mut observer = ObserverNode::open(fixture.network.clone(), &path).unwrap();
    let mut validator = fixture.open(1);
    let tx = transfer();
    observer.submit_transaction(tx.clone()).unwrap();
    let pending = observer.respond(validator.request()).unwrap();
    assert!(
        decode_exchange(fixture.network.genesis_hash(), &pending)
            .unwrap()
            .iter()
            .all(|message| matches!(message, NetworkMessage::Transaction(_)))
    );
    validator.receive(&pending).unwrap();
    let now = Instant::now();
    for step in 0..20 {
        validator.tick(now + Duration::from_millis(step)).unwrap();
        if validator.request().height >= 4 {
            break;
        }
    }
    assert_eq!(validator.request().height, 4);
    while observer.request().height < validator.request().height {
        assert_eq!(
            observer
                .receive(&validator.respond(observer.request()).unwrap())
                .unwrap(),
            0
        );
    }
    assert_eq!(
        observer.storage().checkpoint(),
        validator.storage().checkpoint()
    );
    assert_eq!(
        observer.storage().state().root(),
        validator.storage().state().root()
    );
    assert!(observer.submit_transaction(tx.clone()).is_err());
    assert!(
        decode_exchange(
            fixture.network.genesis_hash(),
            &observer.respond(observer.request()).unwrap()
        )
        .unwrap()
        .is_empty()
    );
    let checkpoint = *observer.storage().checkpoint().unwrap();
    drop(observer);
    let observer = ObserverNode::open(fixture.network.clone(), &path).unwrap();
    assert_eq!(observer.storage().checkpoint(), Some(&checkpoint));
    let mut late =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("late-observer")).unwrap();
    while late.request().height < observer.request().height {
        assert_eq!(
            late.receive(&observer.respond(late.request()).unwrap())
                .unwrap(),
            0
        );
    }
    assert_eq!(
        late.storage().state().root(),
        observer.storage().state().root()
    );
    assert!(late.submit_transaction(tx).is_err());
    for directory in [path, fixture.path.join("late-observer")] {
        assert!(!directory.join("signing.journal").exists());
        assert!(!directory.join("validator.seed").exists());
        assert!(!directory.join("consensus-cache.bin").exists());
        assert_eq!(
            std::fs::read(directory.join(node::observer::OBSERVER_MARKER))
                .unwrap()
                .len(),
            36
        );
    }
}

#[test]
fn observer_rejects_forged_finality_body_mutations_gaps_and_truncated_batches() {
    let fixture = Fixture::new(1);
    let mut validator = fixture.open(1);
    validator.submit_transaction(transfer()).unwrap();
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    let initial = *observer.storage().checkpoint().unwrap();
    let now = Instant::now();
    for step in 0..8 {
        validator.tick(now + Duration::from_millis(step)).unwrap();
        if validator.request().height >= 3 {
            break;
        }
    }
    let original = validator.respond(observer.request()).unwrap();
    let message = decode_exchange(fixture.network.genesis_hash(), &original)
        .unwrap()
        .remove(0);
    for defect in 0..2 {
        let mut mutated = message.clone();
        let NetworkMessage::Finalized { block, certificate } = &mut mutated else {
            panic!("finalized block expected")
        };
        if defect == 0 {
            certificate.signatures[0].signature[0] ^= 1;
        } else {
            block.transactions[0].payload[0] ^= 1;
        }
        let bytes = encode_exchange(fixture.network.genesis_hash(), &[mutated]).unwrap();
        assert_eq!(observer.receive(&bytes).unwrap(), 1);
        assert_eq!(observer.storage().checkpoint(), Some(&initial));
    }
    let gap = validator
        .respond(SyncRequest {
            height: 2,
            ..observer.request()
        })
        .unwrap();
    assert_eq!(observer.receive(&gap).unwrap(), 1);
    let mut truncated = original.clone();
    truncated.pop();
    assert!(observer.receive(&truncated).is_err());
    assert_eq!(observer.storage().checkpoint(), Some(&initial));
    assert!(
        observer
            .respond(SyncRequest {
                genesis: Hash256([0x42; 32]),
                height: 1
            })
            .is_err()
    );
    assert_eq!(observer.receive(&original).unwrap(), 0);
    assert_eq!(observer.receive(&original).unwrap(), 1);
    assert_eq!(observer.request().height, 2);
}

#[test]
fn observer_cannot_replace_missing_quorum_or_relay_live_consensus_messages() {
    let fixture = Fixture::new(4);
    let mut validators = vec![fixture.open(1), fixture.open(2)];
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    let now = Instant::now();
    for step in 0..60 {
        exchange(&mut validators, now + Duration::from_millis(step * 20));
        for validator in &mut validators {
            observer
                .receive(&validator.respond(observer.request()).unwrap())
                .unwrap();
            let bytes = observer.respond(validator.request()).unwrap();
            assert!(
                decode_exchange(fixture.network.genesis_hash(), &bytes)
                    .unwrap()
                    .is_empty()
            );
            validator.receive(&bytes).unwrap();
        }
    }
    assert_eq!(observer.request().height, 1);
    assert!(
        validators
            .iter()
            .all(|validator| validator.request().height == 1)
    );
}

#[test]
fn observer_role_validation_preserves_validator_data_and_rejects_corrupt_markers() {
    let fixture = Fixture::new(1);
    let directory = fixture.path.join("1");
    let journal = std::fs::read(directory.join("signing.journal")).unwrap();
    assert!(ObserverNode::open(fixture.network.clone(), &directory).is_err());
    assert_eq!(
        std::fs::read(directory.join("signing.journal")).unwrap(),
        journal
    );
    assert!(!directory.join("chain.bin").exists());
    let path = fixture.path.join("observer");
    drop(ObserverNode::open(fixture.network.clone(), &path).unwrap());
    let archive = std::fs::read(path.join("chain.bin")).unwrap();
    std::fs::write(path.join(node::observer::OBSERVER_MARKER), b"ALOB").unwrap();
    assert!(ObserverNode::open(fixture.network.clone(), &path).is_err());
    assert_eq!(std::fs::read(path.join("chain.bin")).unwrap(), archive);
}

#[test]
fn observer_recovery_rejects_demonstration_history() {
    use node::{FullNodeService, NodeService, ProducerConfig};
    let fixture = Fixture::new(1);
    let path = fixture.path.join("observer");
    std::fs::create_dir(&path).unwrap();
    let mut demo = FullNodeService::open_with_genesis(
        ProducerConfig {
            chain_id: 42,
            block_capacity: fixture.genesis.capacity,
            ..ProducerConfig::default()
        },
        path.join("chain.bin"),
        &fixture.genesis,
    )
    .unwrap();
    for _ in 0..5 {
        demo.advance().unwrap();
    }
    drop(demo);
    let archive = std::fs::read(path.join("chain.bin")).unwrap();
    assert!(ObserverNode::open(fixture.network.clone(), &path).is_err());
    assert_eq!(std::fs::read(path.join("chain.bin")).unwrap(), archive);
    assert!(!path.join(node::observer::OBSERVER_MARKER).exists());
}

#[test]
fn observer_storage_failure_is_fatal_and_does_not_publish_or_consume_pending_payment() {
    let fixture = Fixture::new(1);
    let path = fixture.path.join("observer");
    let mut observer = ObserverNode::open(fixture.network.clone(), &path).unwrap();
    observer.submit_transaction(transfer()).unwrap();
    let mut validator = fixture.open(1);
    validator
        .receive(&observer.respond(validator.request()).unwrap())
        .unwrap();
    let initial = *observer.storage().checkpoint().unwrap();
    let now = Instant::now();
    for step in 0..4 {
        validator.tick(now + Duration::from_millis(step)).unwrap();
        if validator.request().height > 1 {
            break;
        }
    }
    let bytes = validator.respond(observer.request()).unwrap();
    let blocked = path.join("chain.bin.pending");
    std::fs::create_dir(&blocked).unwrap();
    assert!(matches!(
        observer.receive(&bytes),
        Err(node::network::NetworkNodeError::Local(_))
    ));
    assert_eq!(observer.storage().checkpoint(), Some(&initial));
    assert_eq!(
        decode_exchange(
            fixture.network.genesis_hash(),
            &observer.respond(observer.request()).unwrap()
        )
        .unwrap()
        .len(),
        1
    );
    drop(observer);
    std::fs::remove_dir(&blocked).unwrap();
    let mut recovered = ObserverNode::open(fixture.network.clone(), &path).unwrap();
    assert_eq!(recovered.storage().checkpoint(), Some(&initial));
    assert_eq!(recovered.receive(&bytes).unwrap(), 0);
    assert_eq!(
        recovered.storage().checkpoint(),
        validator.storage().checkpoint()
    );
}

#[test]
fn legacy_validator_and_log_observer_exchange_certified_payments_and_recover() {
    let fixture = Fixture::new(1);
    let path = fixture.path.join("1/chain.bin");
    let mut archive = storage::FileBackedStorage::open(&path).unwrap();
    archive
        .initialize_genesis(
            fixture.network.genesis_hash(),
            fixture.genesis.materialize().unwrap(),
        )
        .unwrap();
    drop(archive);
    let mut validator = fixture.open(1);
    assert!(validator.storage().is_legacy_archive());
    let directory = fixture.path.join("observer");
    let mut observer = ObserverNode::open(fixture.network.clone(), &directory).unwrap();
    assert!(!observer.storage().is_legacy_archive());
    validator.submit_transaction(transfer()).unwrap();
    let now = Instant::now();
    for step in 0..4 {
        validator.tick(now + Duration::from_millis(step)).unwrap();
        if validator.request().height > 1 {
            break;
        }
    }
    observer
        .receive(&validator.respond(observer.request()).unwrap())
        .unwrap();
    assert_eq!(
        observer.storage().checkpoint(),
        validator.storage().checkpoint()
    );
    drop(observer);
    drop(validator);
    let validator = fixture.open(1);
    let observer = ObserverNode::open(fixture.network.clone(), &directory).unwrap();
    assert_eq!(
        observer.storage().state().root(),
        validator.storage().state().root()
    );
    assert!(validator.storage().is_legacy_archive());
    assert_eq!(&std::fs::read(path).unwrap()[..8], b"ASTSTORE");
}

#[test]
fn network_crosses_full_signing_journal_recovers_and_finalizes_payments() {
    use consensus::{Vote, VotePhase};
    use types::hash::domain_hash;
    let fixture = Fixture::new(1);
    let path = fixture.path.join("1/signing.journal");
    // Build the documented full v2 prefix: 100,000 reserved nil prevotes during
    // an extended outage. No test-only reduction of the production limit.
    let mut prefix = std::fs::read(&path).unwrap();
    let mut tip = Hash256(prefix[76..108].try_into().unwrap());
    let committee = fixture.network.committee(1).unwrap();
    let voter = ValidatorId(blake2s(&ed25519_public_key(&[1; 32])).0);
    for sequence in 1..=keystore::MAX_JOURNAL_RECORDS {
        let round = u32::try_from(sequence - 1).unwrap();
        let vote = Vote {
            chain_id: 42,
            height: 1,
            committee_root: committee.root(),
            round,
            phase: VotePhase::Prevote,
            block: None,
            voter,
            signature: [0; 64],
        };
        let mut record = sequence.to_le_bytes().to_vec();
        record.extend_from_slice(&1u64.to_le_bytes());
        record.extend_from_slice(&round.to_le_bytes());
        record.push(keystore::PREVOTE_PHASE);
        record.extend_from_slice(vote.signing_hash().as_bytes());
        record.extend_from_slice(committee.root().as_bytes());
        record.extend_from_slice(&[0; 37]); // No BFT lock.
        let mut input = tip.0.to_vec();
        input.extend_from_slice(&record);
        tip = domain_hash(b"astrolune.signing.decision.v1", &input);
        record.extend_from_slice(tip.as_bytes());
        prefix.extend_from_slice(&record);
    }
    std::fs::write(&path, &prefix).unwrap();
    assert_eq!(prefix.len() as u64, keystore::MAX_PROTECTED_JOURNAL_BYTES);
    let mut node = fixture.open(1);
    assert_eq!(node.round(), 99_999);
    let now = Instant::now();
    node.tick(now).unwrap();
    node.tick(now + Duration::from_secs(20_000)).unwrap(); // Nil precommit activates rollover.
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        keystore::MAX_ROLLOVER_JOURNAL_BYTES
    );
    drop(node);
    let mut node = fixture.open(1);
    node.submit_transaction(transfer()).unwrap();
    for step in 0..16 {
        node.tick(now + Duration::from_secs(step * 20_000)).unwrap();
        if node.request().height >= 2 {
            break;
        }
    }
    assert_eq!(node.request().height, 2);
    let mut observer =
        ObserverNode::open(fixture.network.clone(), &fixture.path.join("observer")).unwrap();
    observer
        .receive(&node.respond(observer.request()).unwrap())
        .unwrap();
    assert_eq!(observer.storage().checkpoint(), node.storage().checkpoint());
    let checkpoint = *node.storage().checkpoint().unwrap();
    drop(node);
    assert_eq!(&std::fs::read(&path).unwrap()[..prefix.len()], prefix);
    let mut recovered = fixture.open(1);
    assert_eq!(recovered.storage().checkpoint(), Some(&checkpoint));
    for step in 0..4 {
        recovered.tick(now + Duration::from_millis(step)).unwrap();
    }
    assert!(recovered.request().height > 2);
    assert_eq!(
        std::fs::metadata(path).unwrap().len(),
        keystore::MAX_ROLLOVER_JOURNAL_BYTES
    );
}
