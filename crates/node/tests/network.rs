// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Distributed message delivery, durable recovery, and adversarial reference-network checks.

use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use node::{
    network::{NetworkNode, StaticNetwork},
    network_wire::{NetworkMessage, SyncRequest, decode_exchange, encode_exchange},
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
