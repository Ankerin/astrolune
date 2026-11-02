// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Advancing signed-payment execution benchmark; excludes consensus, disk and transport.

use codec::CanonicalEncode;
use crypto::blake2s::{derive_key, ed25519_public_key, ed25519_sign};
use execution::{
    ExecutionAcceleration, ExecutionPolicy, PAYMENT_PRICES, execute_parallel_with_acceleration,
};
use state::{InMemoryState, StateDatabase, StateDiff, account_key, read_account};
use std::time::Instant;
use transaction::{Payment, ValidationContext, address_from_public_key, signing_hash};
use types::{AccountState, Resources, Transaction, TransactionLane};

#[allow(clippy::too_many_lines)] // Entire measured lifecycle is visible in one benchmark.
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let count: usize = args.get(1).map_or(256, |s| s.parse().unwrap());
    let rounds: usize = args.get(2).map_or(30, |s| s.parse().unwrap());
    let workers: usize = args.get(3).map_or(8, |s| s.parse().unwrap());
    let shape = args.get(4).map_or("sender", String::as_str);
    let mode = args.get(5).map_or("fold", String::as_str);
    let acceleration = match mode {
        "waves" => ExecutionAcceleration::Waves,
        "fold" => ExecutionAcceleration::Fold,
        "seal" => ExecutionAcceleration::FoldAndSeal,
        _ => panic!("mode must be waves, fold or seal"),
    };
    assert!((1..=8192).contains(&count) && (1..=1000).contains(&rounds));
    assert!(["sender", "recipient", "ring", "independent"].contains(&shape));
    let accounts = if shape == "sender" { 2 } else { count * 2 };
    let keys: Vec<_> = (0..accounts)
        .map(|i| derive_key(&[42; 32], &format!("local-tps/{i}")))
        .collect();
    let public: Vec<_> = keys.iter().map(ed25519_public_key).collect();
    let addresses: Vec<_> = public.iter().map(address_from_public_key).collect();
    let mut state = InMemoryState::new();
    let mut seed = StateDiff::new();
    for &address in &addresses {
        seed.put(
            account_key(address),
            AccountState {
                nonce: 0,
                balance: 1_000_000_000,
            }
            .to_bytes(),
        );
    }
    state.commit(state.root(), &[seed]).unwrap();
    let limit = Resources {
        compute: 1,
        memory: 32,
        io: 4,
        bandwidth: 1024,
    };
    let policy = ExecutionPolicy {
        capacity: Resources {
            compute: 1 << 40,
            memory: 1 << 40,
            io: 1 << 40,
            bandwidth: 1 << 40,
        },
        prices: PAYMENT_PRICES,
        contracts: false,
    };
    // Fresh IDs/nonces on every round; signing and fixture construction are untimed.
    let mut nonces = vec![0; accounts];
    let mut expected = vec![
        AccountState {
            nonce: 0,
            balance: 1_000_000_000
        };
        accounts
    ];
    let batches: Vec<Vec<_>> = (0..rounds + 3)
        .map(|_| {
            (0..count)
                .map(|i| {
                    let (sender, recipient) = match shape {
                        "sender" => (0, 1),
                        "recipient" => (i, accounts - 1),
                        "ring" => (i % count, (i + 1) % count),
                        _ => (i, count + i),
                    };
                    let mut access = vec![
                        account_key(addresses[sender]),
                        account_key(addresses[recipient]),
                    ];
                    access.sort();
                    access.dedup();
                    let mut tx = Transaction {
                        version: types::TRANSACTION_VERSION,
                        chain_id: 7,
                        sender: addresses[sender],
                        nonce: nonces[sender],
                        expires_at: u64::MAX,
                        lane: TransactionLane::Payments,
                        resource_prices: PAYMENT_PRICES,
                        access_list: access,
                        resource_limit: limit,
                        payload: Payment {
                            public_key: public[sender],
                            recipient: addresses[recipient],
                            amount: 1,
                        }
                        .to_bytes(),
                        signature: [0; 64],
                    };
                    tx.signature = ed25519_sign(&keys[sender], signing_hash(&tx).as_bytes());
                    nonces[sender] += 1;
                    expected[sender].nonce += 1;
                    expected[sender].balance -= 2;
                    expected[recipient].balance += 1;
                    tx
                })
                .collect()
        })
        .collect();
    println!("mode,shape,count,workers,round,transactions,elapsed_ns,state_root");
    for (round, batch) in batches.iter().enumerate() {
        let start = Instant::now();
        let parent = state.root();
        let (outputs, root) = execute_parallel_with_acceleration(
            &mut state,
            batch,
            parent,
            ValidationContext {
                chain_id: 7,
                next_height: round as u64 + 1,
                max_transaction_bytes: 4096,
            },
            policy,
            workers,
            acceleration,
        )
        .unwrap();
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(outputs.len(), count);
        assert!(outputs.iter().all(|o| o.receipt.succeeded));
        assert_eq!(state.root(), root);
        if round >= 3 {
            println!(
                "{mode},{shape},{count},{workers},{},{count},{elapsed},{root}",
                round - 3
            );
        }
    }
    let snapshot = state.snapshot().unwrap();
    for (index, &address) in addresses.iter().enumerate() {
        assert_eq!(
            read_account(snapshot.as_ref(), address).unwrap(),
            Some(expected[index].clone())
        );
    }
}
