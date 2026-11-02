// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! One-host certified node pipeline over TCP loopback. This is not distributed consensus.

use codec::{CanonicalDecode, CanonicalEncode};
use consensus::{
    AuthenticatedCommittee, CertificateSignature, Committee, CommitteeMember, FinalityCertificate,
    PotbWeight, Vote, VotePhase,
};
use crypto::blake2s::{derive_key, ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use mempool::PoolLimits;
use node::{BlockProducer, ProducerConfig};
use state::{StateDatabase, read_account};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    time::Instant,
};
use storage::{AppendOnlyStorage, NodeStorage};
use transaction::{Payment, address_from_public_key, signing_hash};
use types::{AccountState, Resources, Transaction, TransactionLane, ValidatorId};

fn committee(height: u64) -> AuthenticatedCommittee {
    let public = [1u8, 2, 3].map(|s| ed25519_public_key(&[s; 32]));
    let mut members: Vec<_> = public
        .iter()
        .map(|key| CommitteeMember {
            id: ValidatorId(crypto::blake2s_hash(key).0),
            power: PotbWeight(1),
        })
        .collect();
    members.sort_by_key(|m| m.id);
    AuthenticatedCommittee::new(7, &Committee { height, members }, &public).unwrap()
}

fn certify(context: &AuthenticatedCommittee, header: &types::BlockHeader) -> FinalityCertificate {
    let block = header.compute_hash();
    let mut signatures: Vec<_> = [1u8, 2, 3]
        .iter()
        .map(|seed| {
            let voter = ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[*seed; 32])).0);
            let vote = Vote {
                chain_id: 7,
                committee_root: context.root(),
                height: context.height(),
                round: 0,
                phase: VotePhase::Precommit,
                block: Some(block),
                voter,
                signature: [0; 64],
            };
            CertificateSignature {
                voter,
                signature: ed25519_sign(&[*seed; 32], vote.signing_hash().as_bytes()),
            }
        })
        .collect();
    signatures.sort_by_key(|s| s.voter);
    FinalityCertificate {
        chain_id: 7,
        height: context.height(),
        round: 0,
        committee_root: context.root(),
        block,
        signatures,
    }
}

#[allow(clippy::too_many_lines)] // Keep all measured and verified pipeline stages together.
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let count: usize = args.get(1).map_or(256, |s| s.parse().unwrap());
    let rounds: usize = args.get(2).map_or(30, |s| s.parse().unwrap());
    let path = PathBuf::from(
        args.get(3)
            .expect("usage: certified_tps count rounds NEW_DIRECTORY shape"),
    );
    let shape = args.get(4).map_or("independent", String::as_str);
    assert!((2..=8192).contains(&count) && (1..=1000).contains(&rounds));
    assert!(["independent", "recipient", "ring"].contains(&shape));
    // Caller chooses a fresh evidence directory; never erase another run.
    std::fs::create_dir(&path).unwrap();
    let keys: Vec<_> = (0..count * 2)
        .map(|i| derive_key(&[42; 32], &format!("local-tps/{i}")))
        .collect();
    let public: Vec<_> = keys.iter().map(ed25519_public_key).collect();
    let addresses: Vec<_> = public.iter().map(address_from_public_key).collect();
    let capacity = Resources {
        compute: 1_000_000,
        memory: 1_000_000,
        io: 1_000_000,
        bandwidth: 16_000_000,
    };
    let mut genesis = Genesis {
        version: 1,
        chain_id: 7,
        capacity,
        committee_size: 3,
        rotation_count: 1,
        runtime_version: 1,
        validators: [1u8, 2, 3]
            .iter()
            .map(|seed| GenesisValidator {
                id: ValidatorId(crypto::blake2s_hash(&ed25519_public_key(&[*seed; 32])).0),
                weight: 1,
            })
            .collect(),
        allocations: addresses
            .iter()
            .map(|&address| Allocation {
                address,
                amount: 1_000_000_000,
            })
            .collect(),
    };
    genesis.validators.sort_by_key(|v| v.id);
    genesis.allocations.sort_by_key(|a| a.address);
    let config = ProducerConfig {
        chain_id: 7,
        max_block_transactions: count,
        max_transaction_bytes: 4096,
        max_block_bytes: 16_000_000,
        block_capacity: capacity,
        pool_limits: PoolLimits {
            max_transactions: count * 2,
            max_bytes: count * 2048,
        },
    };
    let mut store = AppendOnlyStorage::open(path.join("chain.bin")).unwrap();
    store
        .initialize_genesis(
            genesis.commitment().unwrap(),
            genesis.materialize().unwrap(),
        )
        .unwrap();
    let mut producer =
        BlockProducer::from_checkpoint(config, store.recover().unwrap(), store.state().clone())
            .unwrap();
    let mut expected = vec![
        AccountState {
            nonce: 0,
            balance: 1_000_000_000
        };
        count * 2
    ];
    // Pre-signed load; every measured round advances nonces/state and uses fresh IDs.
    let batches: Vec<Vec<u8>> = (0..rounds + 3)
        .map(|round| {
            let mut bytes = Vec::new();
            for i in 0..count {
                let recipient = match shape {
                    "recipient" => count * 2 - 1,
                    "ring" => (i + 1) % count,
                    _ => count + i,
                };
                let mut access = vec![
                    state::account_key(addresses[i]),
                    state::account_key(addresses[recipient]),
                ];
                access.sort();
                let mut tx = Transaction {
                    version: types::TRANSACTION_VERSION,
                    chain_id: 7,
                    sender: addresses[i],
                    nonce: round as u64,
                    expires_at: u64::MAX,
                    lane: TransactionLane::Payments,
                    resource_prices: execution::PAYMENT_PRICES,
                    access_list: access,
                    resource_limit: Resources {
                        compute: 1,
                        memory: 32,
                        io: 4,
                        bandwidth: 1024,
                    },
                    payload: Payment {
                        public_key: public[i],
                        recipient: addresses[recipient],
                        amount: 1,
                    }
                    .to_bytes(),
                    signature: [0; 64],
                };
                tx.signature = ed25519_sign(&keys[i], signing_hash(&tx).as_bytes());
                let encoded = tx.to_bytes();
                bytes.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_le_bytes());
                bytes.extend_from_slice(&encoded);
                expected[i].nonce += 1;
                expected[i].balance -= 2;
                expected[recipient].balance += 1;
            }
            bytes
        })
        .collect();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client.set_nodelay(true).unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_nodelay(true).unwrap();
        for _ in 0..rounds + 3 {
            let start = Instant::now();
            let mut transactions = Vec::with_capacity(count);
            for _ in 0..count {
                let mut length = [0; 4];
                stream.read_exact(&mut length).unwrap();
                let length = u32::from_le_bytes(length) as usize;
                assert!(length <= 4096);
                let mut bytes = vec![0; length];
                stream.read_exact(&mut bytes).unwrap();
                transactions.push(Transaction::decode(&bytes).unwrap());
            }
            for result in producer.submit_transactions(transactions).unwrap() {
                result.unwrap();
            }
            let admission = start.elapsed().as_nanos();
            let start = Instant::now();
            let context = committee(producer.height());
            let proposal = producer.produce_block_for_committee(&context).unwrap();
            assert_eq!(proposal.block.transactions.len(), count);
            let production = start.elapsed().as_nanos();
            let start = Instant::now();
            let certificate = certify(&context, &proposal.block.header);
            let cp = producer
                .commit_certified_block(&proposal, &certificate, &context, &mut store)
                .unwrap();
            let publication = start.elapsed().as_nanos();
            assert_eq!(store.state().root(), producer.state().root());
            for ns in [admission, production, publication] {
                stream
                    .write_all(&u64::try_from(ns).unwrap().to_le_bytes())
                    .unwrap();
            }
            stream.write_all(cp.state_root.as_bytes()).unwrap();
        }
        (
            store.checkpoint().copied().unwrap(),
            store.state().export_snapshot(),
        )
    });
    println!("shape,count,round,transactions,elapsed_ns,admission_ns,production_ns,publication_ns");
    for (round, bytes) in batches.iter().enumerate() {
        let start = Instant::now();
        client.write_all(bytes).unwrap();
        let mut ack = [0; 56];
        client.read_exact(&mut ack).unwrap();
        let elapsed = start.elapsed().as_nanos();
        let times: Vec<_> = ack[..24]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|v| u64::from_le_bytes(*v))
            .collect();
        if round >= 3 {
            println!(
                "{shape},{count},{},{count},{elapsed},{},{},{}",
                round - 3,
                times[0],
                times[1],
                times[2]
            );
        }
    }
    let (checkpoint, snapshot) = worker.join().unwrap();
    let recovered = AppendOnlyStorage::open(path.join("chain.bin")).unwrap();
    assert_eq!(recovered.checkpoint(), Some(&checkpoint));
    assert_eq!(recovered.state().export_snapshot(), snapshot);
    assert_eq!(recovered.block_count(), rounds + 3);
    let state = recovered.state().snapshot().unwrap();
    for (index, &address) in addresses.iter().enumerate() {
        assert_eq!(
            read_account(state.as_ref(), address).unwrap(),
            Some(expected[index].clone())
        );
    }
    for height in 1..=rounds as u64 + 3 {
        let (block, certificate) = recovered.read_finalized(height).unwrap().unwrap();
        committee(height)
            .verify_certificate(
                &FinalityCertificate::decode(&certificate).unwrap(),
                &block.header,
            )
            .unwrap();
        let receipts = recovered.read_receipts(height).unwrap().unwrap();
        assert_eq!(receipts.effects.receipts.len(), count);
        assert!(receipts.effects.receipts.iter().all(|r| r.succeeded));
    }
    eprintln!(
        "verified {} durable signed transfers, {} certificates and full state after reopen",
        (rounds + 3) * count,
        rounds + 3
    );
}
