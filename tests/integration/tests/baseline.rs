// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use codec::{DecodeError, Decoder, PROTOCOL_VERSION};
use config::{NetworkConfig, NodeConfig, SecretRef};
use consensus::{
    Committee, CommitteeMember, CommitteeSelector, FinalityEngine, PotbWeight, WeightedSampler,
    quorum_power,
};
use crypto::MockCryptoProvider;
use dns::{InMemoryResolver, Record, Resolver};
use execution::{ExecutorConfig, SimpleExecutor};
use genesis::{Genesis, GenesisValidator};
use id::{AuthorizationChallenge, AuthorizationVerifier, InMemoryVerifier, Scope};
use keystore::{KeyHandle, KeyPurpose, MockKeystore, Signer};
use mempool::{Mempool, PoolEntry, PoolLimits};
use p2p::{BoundedFrameDecoder, FrameDecoder, FrameEncoder, MAX_FRAME_SIZE, MessageKind};
use pages::{InMemoryPageSource, PageManifest, PageSource};
use proxy::{EchoHandler, InMemoryProxyGateway, ProxyGateway, ProxyRequest};
use rpc::{InMemoryRpcService, RpcRequest, RpcResponse, RpcService};
use state::{InMemoryState, StateDatabase, StateDiff};
use storage::{CommitBatch, InMemoryStorage, NodeStorage};
use sync::{ChainVerifier, SyncVerifier};
use testkit::{hash, resources, transaction, validator};
use transaction::{AccountState, BasicValidator};
use types::{Address, Block, BlockHeader, Hash256, Resources, StateKey, ValidatorId};

// ---------------------------------------------------------------------------
// Original baseline tests
// ---------------------------------------------------------------------------

#[test]
fn protocol_baseline_invariants_hold() {
    assert_eq!(PROTOCOL_VERSION, 1);
    assert_eq!(quorum_power(100), 67);

    let mut decoder = Decoder::new(&[1]);
    assert_eq!(decoder.read_u16(), Err(DecodeError::Truncated));
    assert_eq!(Decoder::new(&[1]).finish(), Err(DecodeError::TrailingBytes));
}

#[test]
fn configuration_validates_and_redacts_key_reference() {
    let key = SecretRef::new("hardware-slot-7").expect("valid key reference");
    let config = NodeConfig {
        chain_id: 7,
        data_dir: PathBuf::from("node-data"),
        validator_key: Some(key),
        network: NetworkConfig {
            p2p_listen: "127.0.0.1:17330".into(),
            rpc_listen: "127.0.0.1:17331".into(),
            max_peers: 32,
        },
    };

    config.validate().expect("valid node configuration");
    let debug = format!("{config:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("hardware-slot-7"));
}

#[test]
fn genesis_and_mempool_form_a_deterministic_baseline() {
    let genesis = Genesis {
        version: 1,
        chain_id: 7,
        capacity: resources(10),
        committee_size: 2,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![
            GenesisValidator {
                id: validator(1),
                weight: 10,
            },
            GenesisValidator {
                id: validator(2),
                weight: 10,
            },
        ],
        allocations: Vec::new(),
    };
    genesis.validate().expect("valid genesis");

    let mut pool = Mempool::new(PoolLimits {
        max_transactions: 2,
        max_bytes: 128,
    })
    .expect("valid limits");
    pool.insert(
        PoolEntry {
            id: hash(1),
            transaction: transaction(1, 0),
            priority: 1,
            sequence: 1,
        },
        32,
    )
    .expect("first transaction");
    pool.insert(
        PoolEntry {
            id: hash(2),
            transaction: transaction(2, 0),
            priority: 2,
            sequence: 2,
        },
        32,
    )
    .expect("second transaction");

    let selected = pool.select(2, resources(2));
    assert_eq!(selected[0].id, hash(2));
    assert_eq!(selected[1].id, hash(1));
}

// ---------------------------------------------------------------------------
// Keystore + consensus signing integration
// ---------------------------------------------------------------------------

#[test]
fn keystore_signs_consensus_votes() {
    let mut ks = MockKeystore::new();
    ks.insert(
        "validator-1",
        ValidatorId::from_bytes([1; 32]),
        KeyPurpose::Consensus,
    );

    let handle = KeyHandle {
        id: "validator-1".into(),
        purpose: KeyPurpose::Consensus,
    };

    let vid = ks.validator_id(&handle).expect("key exists");
    assert_eq!(vid, ValidatorId::from_bytes([1; 32]));

    let msg = hash(42);
    let pos = keystore::SigningPosition {
        height: 1,
        round: 0,
        phase: 0,
    };
    let sig = ks.sign_consensus(&handle, pos, msg).expect("signs");
    assert_ne!(sig, [0u8; 64]);

    let sig2 = ks
        .sign_consensus(&handle, pos, msg)
        .expect("re-signs same msg");
    assert_eq!(sig, sig2);

    let err = ks.sign_consensus(&handle, pos, hash(99));
    assert_eq!(err, Err(keystore::KeystoreError::ConflictingSign));
}

// ---------------------------------------------------------------------------
// Committee rotation + finality integration
// ---------------------------------------------------------------------------

#[test]
fn committee_rotation_feeds_finality() {
    let committee = Committee {
        height: 0,
        members: vec![
            CommitteeMember {
                id: validator(1),
                power: PotbWeight(10),
            },
            CommitteeMember {
                id: validator(2),
                power: PotbWeight(10),
            },
            CommitteeMember {
                id: validator(3),
                power: PotbWeight(10),
            },
        ],
    };

    let candidates = vec![
        consensus::Candidate {
            id: validator(4),
            weight: PotbWeight(50),
            vrf: crypto::VrfOutput {
                randomness: Hash256([0xFF; 32]),
                proof: vec![1],
            },
        },
        consensus::Candidate {
            id: validator(5),
            weight: PotbWeight(30),
            vrf: crypto::VrfOutput {
                randomness: Hash256([0xFE; 32]),
                proof: vec![2],
            },
        },
    ];

    let sampler = WeightedSampler;
    let next = sampler.rotate(&committee, &candidates, 1);
    assert_eq!(next.height, 1);
    assert_eq!(next.members.len(), 3);
    assert_eq!(next.members[0].id, validator(1));

    let mut engine = consensus::BftFinalityEngine::new(next.clone());
    let block = hash(100);

    for member in next.members.iter().take(2) {
        let vote = consensus::Vote {
            height: 1,
            round: 0,
            phase: consensus::VotePhase::Precommit,
            block: Some(block),
            voter: member.id,
            signature: [0xFF; 64],
        };
        engine.receive_vote(vote).expect("valid vote");
    }

    assert_eq!(engine.finalized_block(), Some(block));
}

// ---------------------------------------------------------------------------
// State + execution + storage integration
// ---------------------------------------------------------------------------

#[test]
fn state_execution_storage_roundtrip() {
    let mut state = InMemoryState::new();
    let root0 = state.root();

    let mut diff = StateDiff::new();
    let key = StateKey::new(b"account:alice".to_vec()).expect("valid key");
    diff.put(key.clone(), vec![100, 200, 50]);
    let root1 = state.commit(root0, &[diff]).expect("commit succeeds");
    assert_ne!(root0, root1);

    let snapshot = state.snapshot().expect("snapshot");
    assert_eq!(snapshot.get(&key).expect("get"), Some(vec![100, 200, 50]));

    let mut storage = InMemoryStorage::new();
    let batch = CommitBatch {
        block: Block {
            header: BlockHeader {
                height: 0,
                parent: Hash256::ZERO,
                transactions_root: Hash256::ZERO,
                state_root: root1,
                receipts_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: resources(100),
            },
            transactions: Vec::new(),
        },
        finality_certificate: vec![0xAA; 32],
        state_diffs: vec![{
            let mut d = StateDiff::new();
            d.put(key, vec![100, 200, 50]);
            d
        }],
    };

    let cp = storage.commit(&batch).expect("storage commit");
    assert_eq!(cp.height, 0);
    assert_eq!(cp.state_root, root1);
}

// ---------------------------------------------------------------------------
// Transaction validation + execution integration
// ---------------------------------------------------------------------------

#[test]
fn transaction_validates_and_executes() {
    let sender = Address([1u8; 32]);
    let mut accounts = BTreeMap::new();
    accounts.insert(
        sender,
        AccountState {
            nonce: 0,
            balance: 1000,
        },
    );

    let validator_inst = BasicValidator::new(accounts);
    let mut state = InMemoryState::new();
    let root0 = state.root();

    let config = ExecutorConfig {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 1024,
    };

    let mut executor = SimpleExecutor::new(&mut state, validator_inst, config);
    let txs = vec![transaction(1, 0)];
    let (outputs, root1) = executor.execute_block(&txs, root0).expect("executes");

    assert_eq!(outputs.len(), 1);
    assert!(outputs[0].receipt.succeeded);
    assert_ne!(root0, root1);
}

// ---------------------------------------------------------------------------
// P2P frame encode/decode roundtrip
// ---------------------------------------------------------------------------

#[test]
fn p2p_frame_roundtrip() {
    let payload = b"hello astrolune";
    let encoded = FrameEncoder::encode(MessageKind::Hello, payload);
    assert_eq!(encoded[0], MessageKind::Hello as u8);
    assert_eq!(encoded.len(), 5 + payload.len());

    let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
    let frame = decoder.decode(&encoded).expect("decodes");
    assert_eq!(frame.kind, MessageKind::Hello);
    assert_eq!(frame.payload, payload);
}

// ---------------------------------------------------------------------------
// Sync verifier header chain validation
// ---------------------------------------------------------------------------

#[test]
fn sync_verifies_header_chain() {
    let genesis = BlockHeader {
        height: 0,
        parent: Hash256::ZERO,
        transactions_root: Hash256::ZERO,
        state_root: Hash256([0xAA; 32]),
        receipts_root: Hash256::ZERO,
        committee_root: Hash256::ZERO,
        capacity: resources(100),
    };
    let genesis_hash = genesis.compute_hash();

    let verifier = ChainVerifier::new(genesis_hash, 1, 1);

    let h1 = BlockHeader {
        height: 1,
        parent: genesis_hash,
        transactions_root: Hash256::ZERO,
        state_root: Hash256([0xBB; 32]),
        receipts_root: Hash256::ZERO,
        committee_root: Hash256::ZERO,
        capacity: resources(100),
    };

    verifier
        .verify_headers(&[genesis, h1])
        .expect("valid chain");
}

// ---------------------------------------------------------------------------
// RPC service integration
// ---------------------------------------------------------------------------

#[test]
fn rpc_service_full_workflow() {
    let mut rpc = InMemoryRpcService::new(7);

    rpc.set_finalized(10, hash(42));
    let resp = rpc.handle(RpcRequest::ChainStatus).expect("chain status");
    match resp {
        RpcResponse::ChainStatus {
            chain_id,
            finalized_height,
            ..
        } => {
            assert_eq!(chain_id, 7);
            assert_eq!(finalized_height, 10);
        }
        _ => panic!("unexpected response"),
    }

    let resp = rpc
        .handle(RpcRequest::SubmitTransaction(vec![1, 2, 3]))
        .expect("submit tx");
    assert!(matches!(resp, RpcResponse::TransactionAccepted(_)));

    let resp = rpc
        .handle(RpcRequest::Account(Address([99u8; 32])))
        .expect("account");
    assert_eq!(resp, RpcResponse::Account(None));
}

// ---------------------------------------------------------------------------
// DNS + Proxy service integration
// ---------------------------------------------------------------------------

#[test]
fn dns_proxy_service_chain() {
    let mut resolver = InMemoryResolver::new();
    resolver
        .register("app.astro", Record::Service(b"gateway".to_vec()))
        .expect("register dns");

    let record = resolver.resolve("app.astro").expect("resolves");
    assert!(record.is_some());

    let handler = EchoHandler;
    let mut gateway = InMemoryProxyGateway::new(10);
    gateway
        .register_service("app.astro", Box::new(handler))
        .expect("register proxy");

    let request = ProxyRequest {
        name: "app.astro".into(),
        payload: vec![0x01, 0x02, 0x03],
    };
    let response = gateway.forward(&request).expect("forwards");
    assert_eq!(response, vec![0x01, 0x02, 0x03]);
}

// ---------------------------------------------------------------------------
// ID service challenge + verification
// ---------------------------------------------------------------------------

#[test]
fn id_challenge_and_verification() {
    let crypto = MockCryptoProvider::new();
    let mut verifier = InMemoryVerifier::new(Box::new(crypto));

    let challenge = AuthorizationChallenge::new(
        7,
        "https://app.example",
        "backend.example",
        &[Scope::Address],
        1000,
        2000,
    );

    assert!(!challenge.is_expired(1500));
    assert!(challenge.is_expired(2500));

    let proof = id::AuthorizationProof {
        address: Address([1u8; 32]),
        challenge,
        signature: [0xFF; 64],
    };

    let scopes = verifier.verify(&proof).expect("valid proof");
    assert_eq!(scopes, vec![Scope::Address]);

    let err = verifier.verify(&proof);
    assert_eq!(err, Err(id::IdError::Replay));
}

// ---------------------------------------------------------------------------
// Pages service content verification
// ---------------------------------------------------------------------------

#[test]
fn pages_content_integrity() {
    let mut source = InMemoryPageSource::new();
    let owner = Address([1u8; 32]);

    source
        .register(owner, "index.html", b"<h1>Hello</h1>".to_vec())
        .expect("register index");
    source
        .register(owner, "style.css", b"body{}".to_vec())
        .expect("register css");

    let root = source.content_root(owner).expect("root exists");
    assert_ne!(root, Hash256::ZERO);

    let manifest = PageManifest {
        owner,
        content_root: root,
        entrypoint: "index.html".into(),
        revision: 1,
    };

    let content = source.load(&manifest, "index.html").expect("loads");
    assert_eq!(content, b"<h1>Hello</h1>");

    let bad_manifest = PageManifest {
        content_root: Hash256([0xFF; 32]),
        ..manifest
    };
    assert!(source.load(&bad_manifest, "index.html").is_err());
}

// ---------------------------------------------------------------------------
// Telemetry + node capacity integration
// ---------------------------------------------------------------------------

#[test]
fn telemetry_tracks_node_capacity() {
    use node::CapacityController;
    use node::CapacityObservation;
    use telemetry::{InMemoryTelemetry, Metric, TelemetrySink};

    let tel = InMemoryTelemetry::new(64);
    let controller =
        node::AdaptiveCapacityController::new(node::DEFAULT_CAPACITY, node::LATENCY_WINDOW);

    let observations: Vec<CapacityObservation> = (0..8)
        .map(|i| CapacityObservation {
            used: Resources {
                compute: 500 + i * 50,
                memory: 512,
                io: 128,
                bandwidth: 512,
            },
            within_latency_target: true,
        })
        .collect();

    for obs in &observations {
        tel.record(Metric {
            name: "block_compute",
            value: obs.used.compute,
        });
        controller.next_capacity(node::DEFAULT_CAPACITY, std::slice::from_ref(obs));
    }

    assert_eq!(tel.count("block_compute"), 8);
    assert_eq!(tel.latest("block_compute"), Some(850));
}

// ---------------------------------------------------------------------------
// Storage commit + recover
// ---------------------------------------------------------------------------

#[test]
fn storage_commit_and_recover() {
    let mut storage = InMemoryStorage::new();
    assert!(storage.recover().expect("recovers").is_none());

    let batch = CommitBatch {
        block: Block {
            header: BlockHeader {
                height: 0,
                parent: Hash256::ZERO,
                transactions_root: Hash256::ZERO,
                state_root: storage.state().root(),
                receipts_root: Hash256::ZERO,
                committee_root: Hash256::ZERO,
                capacity: resources(100),
            },
            transactions: Vec::new(),
        },
        finality_certificate: vec![0xAA; 32],
        state_diffs: Vec::new(),
    };
    let cp = storage.commit(&batch).expect("commit");
    assert_eq!(cp.height, 0);

    let recovered = storage.recover().expect("recovers");
    assert_eq!(recovered, Some(cp));
}

// ---------------------------------------------------------------------------
// End-to-end: genesis -> mempool -> execution -> storage
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn end_to_end_block_production() {
    let genesis = Genesis {
        version: 1,
        chain_id: 7,
        capacity: resources(1000),
        committee_size: 3,
        rotation_count: 1,
        runtime_version: 1,
        validators: vec![
            GenesisValidator {
                id: validator(1),
                weight: 100,
            },
            GenesisValidator {
                id: validator(2),
                weight: 100,
            },
            GenesisValidator {
                id: validator(3),
                weight: 100,
            },
        ],
        allocations: Vec::new(),
    };
    genesis.validate().expect("genesis valid");

    let mut pool = Mempool::new(PoolLimits {
        max_transactions: 10,
        max_bytes: 10240,
    })
    .expect("valid limits");

    let tx1 = transaction(1, 0);
    let tx2 = transaction(2, 1);

    pool.insert(
        PoolEntry {
            id: hash(1),
            transaction: tx1,
            priority: 10,
            sequence: 1,
        },
        64,
    )
    .expect("insert tx1");
    pool.insert(
        PoolEntry {
            id: hash(2),
            transaction: tx2,
            priority: 20,
            sequence: 2,
        },
        64,
    )
    .expect("insert tx2");

    let selected = pool.select(5, resources(100));
    assert_eq!(selected.len(), 2);

    let sender = Address([1u8; 32]);
    let mut accounts = BTreeMap::new();
    accounts.insert(
        sender,
        AccountState {
            nonce: 0,
            balance: 100_000,
        },
    );
    let validator_inst = BasicValidator::new(accounts);
    let mut state = InMemoryState::new();
    let root0 = state.root();

    let exec_config = ExecutorConfig {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 1024,
    };
    let mut executor = SimpleExecutor::new(&mut state, validator_inst, exec_config);
    let selected_txs: Vec<_> = selected
        .into_iter()
        .map(|e| e.transaction.clone())
        .collect();
    let (outputs, new_root) = executor
        .execute_block(&selected_txs, root0)
        .expect("executes");
    assert_eq!(outputs.len(), 2);
    assert!(outputs.iter().all(|o| o.receipt.succeeded));
    assert_ne!(root0, new_root);

    let mut storage = InMemoryStorage::new();
    let parent_hash = Hash256::ZERO;
    let commit_batch = CommitBatch {
        block: Block {
            header: BlockHeader {
                height: 1,
                parent: parent_hash,
                transactions_root: hash(99),
                state_root: new_root,
                receipts_root: hash(100),
                committee_root: hash(101),
                capacity: resources(1000),
            },
            transactions: selected_txs,
        },
        finality_certificate: vec![0xBB; 64],
        state_diffs: outputs.into_iter().map(|o| o.diff).collect(),
    };
    let cp = storage.commit(&commit_batch).expect("storage commit");
    assert_eq!(cp.height, 1);
    assert_eq!(cp.state_root, new_root);

    let recovered = storage.recover().expect("recovers");
    assert_eq!(recovered, Some(cp));
}
