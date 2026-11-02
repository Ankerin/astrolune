// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Ordered bulk admission and speculative candidate-selection fallback.

use codec::CanonicalEncode;
use crypto::blake2s::{derive_key, ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use node::{BlockProducer, ProducerConfig};
use state::{StateDatabase, StateDiff, account_key};
use storage::Checkpoint;
use transaction::{Payment, address_from_public_key, signing_hash};
use types::{AccountState, Resources, Transaction, TransactionLane, ValidatorId};

fn fixture(count: usize) -> (Genesis, Vec<Transaction>) {
    let secrets: Vec<_> = (0..=count)
        .map(|i| derive_key(&[5; 32], &format!("throughput/{i}")))
        .collect();
    let public: Vec<_> = secrets.iter().map(ed25519_public_key).collect();
    let addresses: Vec<_> = public.iter().map(address_from_public_key).collect();
    let capacity = Resources {
        compute: 100_000,
        memory: 100_000,
        io: 100_000,
        bandwidth: 10_000_000,
    };
    let mut genesis = Genesis {
        version: 1,
        chain_id: 7,
        runtime_version: 1,
        capacity,
        committee_size: 1,
        rotation_count: 1,
        validators: vec![GenesisValidator {
            id: ValidatorId([1; 32]),
            weight: 1,
        }],
        allocations: addresses
            .iter()
            .map(|&address| Allocation {
                address,
                amount: 1_000_000,
            })
            .collect(),
    };
    genesis.allocations.sort_by_key(|a| a.address);
    let txs = (0..count)
        .map(|i| {
            let mut access = vec![account_key(addresses[i]), account_key(addresses[count])];
            access.sort();
            let mut tx = Transaction {
                version: types::TRANSACTION_VERSION,
                chain_id: 7,
                sender: addresses[i],
                nonce: 0,
                expires_at: 10,
                lane: TransactionLane::Payments,
                access_list: access,
                resource_prices: execution::PAYMENT_PRICES,
                resource_limit: Resources {
                    compute: 1,
                    memory: 32,
                    io: 4,
                    bandwidth: 1024,
                },
                payload: Payment {
                    public_key: public[i],
                    recipient: addresses[count],
                    amount: 1,
                }
                .to_bytes(),
                signature: [0; 64],
            };
            tx.signature = ed25519_sign(&secrets[i], signing_hash(&tx).as_bytes());
            tx
        })
        .collect();
    (genesis, txs)
}

fn producer(genesis: &Genesis) -> BlockProducer {
    producer_with_budget(genesis, usize::MAX)
}

fn producer_with_budget(genesis: &Genesis, max_block_bytes: usize) -> BlockProducer {
    let state = genesis.materialize().unwrap();
    BlockProducer::from_checkpoint(
        ProducerConfig {
            block_capacity: genesis.capacity,
            max_block_bytes,
            ..ProducerConfig::default()
        },
        Some(Checkpoint {
            height: 0,
            block: genesis.commitment().unwrap(),
            state_root: state.root(),
        }),
        state,
    )
    .unwrap()
}

#[test]
fn block_byte_budget_matches_codec_and_rejects_oversized_received_proposals() {
    let (genesis, txs) = fixture(80);
    let budget = node::network_wire::BLOCK_ENVELOPE_BYTES
        + txs.iter().map(|tx| 4 + tx.to_bytes().len()).sum::<usize>();
    let mut exact = producer_with_budget(&genesis, budget);
    assert!(
        exact
            .submit_transactions(txs.clone())
            .unwrap()
            .iter()
            .all(Result::is_ok)
    );
    let proposal = exact.produce_block().unwrap();
    assert_eq!(proposal.block.transactions, txs);
    assert_eq!(
        node::network_wire::encode_block(&proposal.block)
            .unwrap()
            .len(),
        budget
    );
    exact.validate_proposal(&proposal).unwrap();
    let mut short = producer_with_budget(&genesis, budget - 1);
    assert!(
        short
            .execute_received_block(proposal.block.clone())
            .is_err()
    );
    assert!(short.validate_proposal(&proposal).is_err());
    short.submit_transactions(txs).unwrap();
    let smaller = short.produce_block().unwrap();
    assert_eq!(smaller.block.transactions.len(), 79);
    assert!(
        node::network_wire::encode_block(&smaller.block)
            .unwrap()
            .len()
            < budget
    );
    assert_eq!(
        short.state().export_snapshot(),
        genesis.materialize().unwrap().export_snapshot()
    );
    let empty = producer_with_budget(&genesis, node::network_wire::BLOCK_ENVELOPE_BYTES)
        .produce_block()
        .unwrap();
    assert_eq!(
        node::network_wire::encode_block(&empty.block)
            .unwrap()
            .len(),
        node::network_wire::BLOCK_ENVELOPE_BYTES
    );
    assert!(
        producer_with_budget(&genesis, node::network_wire::BLOCK_ENVELOPE_BYTES - 1)
            .produce_block()
            .is_err()
    );
}

#[test]
fn oversized_candidate_does_not_execute_or_consume_byte_budget() {
    let (genesis, mut txs) = fixture(2);
    let budget = node::network_wire::BLOCK_ENVELOPE_BYTES + 4 + txs[1].to_bytes().len();
    txs[0].access_list.push(types::StateKey(vec![255; 128]));
    txs[0].access_list.sort();
    let secret = derive_key(&[5; 32], "throughput/0");
    txs[0].signature = ed25519_sign(&secret, signing_hash(&txs[0]).as_bytes());
    let mut node = producer_with_budget(&genesis, budget);
    assert!(
        node.submit_transactions(txs.clone())
            .unwrap()
            .iter()
            .all(Result::is_ok)
    );
    let proposal = node.produce_block().unwrap();
    assert_eq!(proposal.block.transactions, vec![txs[1].clone()]);
    let mut scalar = producer(&genesis);
    scalar.submit_transaction(txs[1].clone()).unwrap();
    assert_eq!(proposal, scalar.produce_block().unwrap());
    assert_eq!(node.pending_count(), 2);
}

#[test]
fn batch_admission_preserves_individual_errors_order_and_pool() {
    let (genesis, mut txs) = fixture(80);
    txs[3].signature[0] ^= 1;
    txs.insert(9, txs[8].clone());
    txs[24].nonce = 1;
    let mut scalar = producer(&genesis);
    let expected: Vec<_> = txs
        .iter()
        .map(|tx| {
            scalar
                .submit_transaction(tx.clone())
                .map_err(|e| e.to_string())
        })
        .collect();
    let mut bulk = producer(&genesis);
    let actual: Vec<_> = bulk
        .submit_transactions(txs)
        .unwrap()
        .into_iter()
        .map(|r| r.map_err(|e| e.to_string()))
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(bulk.pending_transactions(), scalar.pending_transactions());
    assert_eq!(
        bulk.produce_block().unwrap(),
        scalar.produce_block().unwrap()
    );
    assert_eq!(
        bulk.state().export_snapshot(),
        genesis.materialize().unwrap().export_snapshot()
    );
}

#[test]
fn rejected_parallel_candidate_prefix_uses_original_skip_selector() {
    let (genesis, txs) = fixture(80);
    let recipient = Payment::decode(&txs[0].payload).unwrap().recipient;
    let mut initial = genesis.materialize().unwrap();
    let mut diff = StateDiff::new();
    diff.put(
        account_key(recipient),
        AccountState {
            nonce: 0,
            balance: u64::MAX - 1,
        }
        .to_bytes(),
    );
    initial.commit(initial.root(), &[diff]).unwrap();
    let mut producer = BlockProducer::from_checkpoint(
        ProducerConfig {
            block_capacity: genesis.capacity,
            ..ProducerConfig::default()
        },
        Some(Checkpoint {
            height: 0,
            block: genesis.commitment().unwrap(),
            state_root: initial.root(),
        }),
        initial.clone(),
    )
    .unwrap();
    // Every candidate succeeds against the admission snapshot. Only the first can
    // credit the receiver in the ordered block; remaining candidates stay pending.
    assert!(
        producer
            .submit_transactions(txs.clone())
            .unwrap()
            .iter()
            .all(Result::is_ok)
    );
    let proposal = producer.produce_block().unwrap();
    assert_eq!(proposal.block.transactions, vec![txs[0].clone()]);
    assert_eq!(producer.pending_count(), 80);
    assert_eq!(
        producer.state().export_snapshot(),
        initial.export_snapshot()
    );
    producer.validate_proposal(&proposal).unwrap();
    let mut forged = proposal.clone();
    forged.outputs[0]
        .diff
        .put(account_key(txs[0].sender), vec![0; 16]);
    forged.outputs[0].receipt.output_root = forged.outputs[0].diff.commitment();
    forged.block.header.receipts_root = node::compute_receipts_root(
        &forged
            .outputs
            .iter()
            .map(|o| o.receipt.clone())
            .collect::<Vec<_>>(),
    );
    assert!(producer.validate_proposal(&forged).is_err());
}

#[test]
fn rejected_candidate_leaves_bytes_for_later_valid_payment() {
    let (genesis, mut txs) = fixture(3);
    let mut payment = Payment::decode(&txs[2].payload).unwrap();
    let recipient = payment.recipient;
    payment.recipient = txs[0].sender;
    txs[2].payload = payment.to_bytes();
    txs[2].access_list = vec![account_key(txs[2].sender), account_key(payment.recipient)];
    txs[2].access_list.sort();
    txs[2].signature = ed25519_sign(
        &derive_key(&[5; 32], "throughput/2"),
        signing_hash(&txs[2]).as_bytes(),
    );
    let mut initial = genesis.materialize().unwrap();
    let mut diff = StateDiff::new();
    diff.put(
        account_key(recipient),
        AccountState {
            nonce: 0,
            balance: u64::MAX - 1,
        }
        .to_bytes(),
    );
    initial.commit(initial.root(), &[diff]).unwrap();
    let config = ProducerConfig {
        block_capacity: genesis.capacity,
        max_block_bytes: node::network_wire::BLOCK_ENVELOPE_BYTES
            + txs[..2]
                .iter()
                .map(|tx| 4 + tx.to_bytes().len())
                .sum::<usize>(),
        ..ProducerConfig::default()
    };
    let mut producer = BlockProducer::from_checkpoint(
        config,
        Some(Checkpoint {
            height: 0,
            block: genesis.commitment().unwrap(),
            state_root: initial.root(),
        }),
        initial.clone(),
    )
    .unwrap();
    assert!(
        producer
            .submit_transactions(txs.clone())
            .unwrap()
            .iter()
            .all(Result::is_ok)
    );
    let proposal = producer.produce_block().unwrap();
    assert_eq!(
        proposal.block.transactions,
        vec![txs[0].clone(), txs[2].clone()]
    );
    producer.validate_proposal(&proposal).unwrap();
    assert_eq!(
        producer.state().export_snapshot(),
        initial.export_snapshot()
    );
}
