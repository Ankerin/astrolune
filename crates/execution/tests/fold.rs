// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Differential guarded-prefix execution, including canonical failure and rollback.

use codec::CanonicalEncode;
use crypto::blake2s::{derive_key, ed25519_public_key, ed25519_sign};
use execution::{
    ExecutionAcceleration, ExecutionPolicy, PAYMENT_PRICES, execute_parallel_with_acceleration,
};
use state::{InMemoryState, StateDatabase, StateDiff, account_key};
use transaction::{Payment, ValidationContext, address_from_public_key, signing_hash};
use types::{AccountState, Resources, Transaction, TransactionLane};

fn fixtures(count: usize, accounts: usize, seed: u64) -> (InMemoryState, Vec<Transaction>) {
    let secrets: Vec<_> = (0..accounts)
        .map(|i| derive_key(&[42; 32], &format!("fold/{i}")))
        .collect();
    let public: Vec<_> = secrets.iter().map(ed25519_public_key).collect();
    let addresses: Vec<_> = public.iter().map(address_from_public_key).collect();
    let mut state = InMemoryState::new();
    let mut diff = StateDiff::new();
    for &address in &addresses {
        diff.put(
            account_key(address),
            AccountState {
                nonce: 0,
                balance: 1_000_000,
            }
            .to_bytes(),
        );
    }
    state.commit(state.root(), &[diff]).unwrap();
    let mut random = seed;
    let mut nonces = vec![0; accounts];
    let txs = (0..count)
        .map(|i| {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let sender = if accounts > count {
                i
            } else {
                usize::try_from(random % accounts as u64).unwrap()
            };
            let recipient = (sender + 1 + (i % (accounts - 1))) % accounts;
            let mut access = vec![
                account_key(addresses[sender]),
                account_key(addresses[recipient]),
            ];
            access.sort();
            let mut tx = Transaction {
                version: types::TRANSACTION_VERSION,
                chain_id: 7,
                sender: addresses[sender],
                nonce: nonces[sender],
                expires_at: 10,
                lane: TransactionLane::Payments,
                access_list: access,
                resource_prices: PAYMENT_PRICES,
                resource_limit: Resources {
                    compute: 10,
                    memory: 32,
                    io: 4,
                    bandwidth: 1024,
                },
                payload: Payment {
                    public_key: public[sender],
                    recipient: addresses[recipient],
                    amount: (i % 7 + 1) as u64,
                }
                .to_bytes(),
                signature: [0; 64],
            };
            tx.signature = ed25519_sign(&secrets[sender], signing_hash(&tx).as_bytes());
            nonces[sender] += 1;
            tx
        })
        .collect();
    (state, txs)
}

fn policy() -> ExecutionPolicy {
    ExecutionPolicy {
        capacity: Resources {
            compute: 100_000,
            memory: 100_000,
            io: 100_000,
            bandwidth: 10_000_000,
        },
        prices: PAYMENT_PRICES,
        contracts: false,
    }
}

fn compare(state: &InMemoryState, txs: &[Transaction], policy: ExecutionPolicy) {
    let context = ValidationContext {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 4096,
    };
    let mut reference = state.clone();
    let expected = execute_parallel_with_acceleration(
        &mut reference,
        txs,
        state.root(),
        context,
        policy,
        1,
        ExecutionAcceleration::Waves,
    );
    for workers in [2, 8, 16] {
        for accelerator in [
            ExecutionAcceleration::Fold,
            ExecutionAcceleration::FoldAndSeal,
        ] {
            let mut actual = state.clone();
            let result = execute_parallel_with_acceleration(
                &mut actual,
                txs,
                state.root(),
                context,
                policy,
                workers,
                accelerator,
            );
            assert_eq!(result, expected, "{accelerator:?}, {workers} workers");
            assert_eq!(actual.export_snapshot(), reference.export_snapshot());
            if result.is_err() {
                assert_eq!(actual.export_snapshot(), state.export_snapshot());
            }
        }
    }
}

#[test]
fn contended_random_batches_preserve_every_output_and_root() {
    for seed in 0..24 {
        let (state, txs) = fixtures(257, 4, seed);
        compare(&state, &txs, policy());
    }
    // Crosses chunk boundaries in both summaries and state-seal partitions.
    let (state, txs) = fixtures(1025, 2050, 1);
    compare(&state, &txs, policy());
}

#[test]
fn failures_replay_in_reference_order_and_publish_no_prefix() {
    let (state, txs) = fixtures(257, 4, 7);
    for mutation in 0..15 {
        let mut bad = txs.clone();
        let tx = &mut bad[193];
        match mutation {
            0 => tx.signature[0] ^= 1,
            1 => tx.nonce += 1,
            2 => tx.nonce = u64::MAX,
            3 => tx.chain_id += 1,
            4 => tx.expires_at = 0,
            5 => tx.version += 1,
            6 => tx.resource_limit.compute = u64::MAX,
            7 => tx.resource_prices.compute = 2,
            8 => tx.resource_limit.io = 0,
            9 => tx.access_list.clear(),
            10 => tx.payload[72..80].copy_from_slice(&u64::MAX.to_le_bytes()),
            11 => tx.payload.pop().map(|_| ()).unwrap(),
            12 => tx.payload[40..72].fill(0),
            13 => {
                tx.payload[40..72].copy_from_slice(tx.sender.as_bytes());
            }
            _ => tx.lane = TransactionLane::System,
        }
        // Earlier balance/resource failure must outrank this later malformed tx.
        compare(&state, &bad, policy());
        let mut limited = policy();
        limited.capacity.compute = 64;
        compare(&state, &bad, limited);
    }
}

#[test]
fn intermediate_funding_overflow_and_reserve_are_not_net_balances() {
    let (state, txs) = fixtures(257, 4, 3);
    for (nonce, balance) in [(0, 5), (0, u64::MAX), (u64::MAX - 1, 1_000_000)] {
        let mut initial = state.clone();
        let mut diff = StateDiff::new();
        diff.put(
            account_key(txs[0].sender),
            AccountState { nonce, balance }.to_bytes(),
        );
        initial.commit(initial.root(), &[diff]).unwrap();
        compare(&initial, &txs, policy());
    }
    let mut priced = policy();
    priced.prices.memory = u64::MAX;
    compare(&state, &txs, priced);
}

#[test]
fn final_nonce_max_and_exact_reservation_boundary_match_reference() {
    let (mut state, mut txs) = fixtures(64, 128, 1);
    let secret = derive_key(&[42; 32], "fold/0");
    txs[0].nonce = u64::MAX - 1;
    txs[0].signature = ed25519_sign(&secret, signing_hash(&txs[0]).as_bytes());
    let mut diff = StateDiff::new();
    diff.put(
        account_key(txs[0].sender),
        AccountState {
            nonce: u64::MAX - 1,
            balance: 11,
        }
        .to_bytes(),
    );
    state.commit(state.root(), &[diff]).unwrap();
    compare(&state, &txs, policy());
    let mut diff = StateDiff::new();
    diff.put(
        account_key(txs[0].sender),
        AccountState {
            nonce: u64::MAX - 1,
            balance: 10,
        }
        .to_bytes(),
    );
    state.commit(state.root(), &[diff]).unwrap();
    compare(&state, &txs, policy());
}
