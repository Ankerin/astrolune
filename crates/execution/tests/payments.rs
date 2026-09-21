// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Signed account transitions, sequential visibility, and atomic rejection.

use codec::CanonicalEncode;
use crypto::blake2s::{ed25519_public_key, ed25519_sign};
use execution::{ExecutionError, PaymentSession, execute_payments, payment_resources};
use state::{InMemoryState, StateDatabase, StateDiff, StateError, account_key, read_account};
use transaction::{
    Payment, TransactionError, ValidationContext, address_from_public_key, signing_hash,
};
use types::{AccountState, Address, Hash256, Resources, Transaction};

fn address(seed: u8) -> Address {
    address_from_public_key(&ed25519_public_key(&[seed; 32]))
}
fn capacity() -> Resources {
    Resources {
        compute: 100,
        memory: 1024,
        io: 100,
        bandwidth: 10000,
    }
}
fn context() -> ValidationContext {
    ValidationContext {
        chain_id: 7,
        next_height: 1,
        max_transaction_bytes: 1024,
    }
}
fn signed(mut tx: Transaction, seed: u8) -> Transaction {
    tx.signature = ed25519_sign(&[seed; 32], signing_hash(&tx).as_bytes());
    tx
}
fn transfer(seed: u8, recipient: Address, nonce: u64, amount: u64) -> Transaction {
    let mut keys = vec![account_key(address(seed)), account_key(recipient)];
    keys.sort();
    keys.dedup();
    let mut tx = Transaction {
        version: types::TRANSACTION_VERSION,
        expires_at: u64::MAX,
        lane: types::TransactionLane::Payments,
        resource_prices: types::Resources {
            compute: 1,
            ..types::Resources::ZERO
        },
        chain_id: 7,
        sender: address(seed),
        nonce,
        access_list: keys,
        resource_limit: Resources::ZERO,
        payload: Payment {
            public_key: ed25519_public_key(&[seed; 32]),
            recipient,
            amount,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = payment_resources(&tx).unwrap();
    signed(tx, seed)
}
fn funded(accounts: &[(u8, u64, u64)]) -> InMemoryState {
    let mut state = InMemoryState::new();
    let mut diff = StateDiff::new();
    for &(seed, nonce, balance) in accounts {
        diff.put(
            account_key(address(seed)),
            AccountState { nonce, balance }.to_bytes(),
        );
    }
    state.commit(state.root(), &[diff]).unwrap();
    state
}
fn account(state: &InMemoryState, seed: u8) -> AccountState {
    read_account(state.snapshot().unwrap().as_ref(), address(seed))
        .unwrap()
        .unwrap()
}
fn execute(state: &mut InMemoryState, txs: &[Transaction]) -> Result<(), ExecutionError> {
    execute_payments(state, txs, state.root(), context(), capacity()).map(|_| ())
}

#[test]
fn sequential_transfers_create_accounts_burn_fees_and_preserve_old_snapshots() {
    let mut state = funded(&[(1, 0, 100)]);
    let old = state.snapshot().unwrap();
    let txs = [
        transfer(1, address(2), 0, 40),
        transfer(2, address(3), 0, 10),
        transfer(1, address(1), 1, 5),
    ];
    let root = state.root();
    let (outputs, _) = execute_payments(&mut state, &txs, root, context(), capacity()).unwrap();
    assert_eq!(
        account(&state, 1),
        AccountState {
            nonce: 2,
            balance: 58
        }
    );
    assert_eq!(
        account(&state, 2),
        AccountState {
            nonce: 1,
            balance: 29
        }
    );
    assert_eq!(
        account(&state, 3),
        AccountState {
            nonce: 0,
            balance: 10
        }
    );
    assert_eq!(
        read_account(old.as_ref(), address(1))
            .unwrap()
            .unwrap()
            .balance,
        100
    );
    assert_eq!(read_account(old.as_ref(), address(2)).unwrap(), None);
    assert_eq!(outputs[2].diff.len(), 1);
    assert_eq!(outputs[2].observed_lease.requests.len(), 1);
    for (output, tx) in outputs.iter().zip(txs) {
        assert_eq!(output.receipt.resources, payment_resources(&tx).unwrap());
        assert_eq!(output.receipt.output_root, output.diff.commitment());
    }
}

#[test]
fn malformed_or_unauthorized_payments_roll_back_the_entire_block() {
    let mut state = funded(&[(1, 0, 100), (2, 0, u64::MAX)]);
    let before = state.export_snapshot();
    let good = transfer(1, address(3), 0, 10);
    let base = transfer(1, address(3), 1, 10);
    let mut invalid = Vec::new();
    let mut tx = base.clone();
    tx.signature[0] ^= 1;
    invalid.push(tx);
    let mut tx = base.clone();
    tx.chain_id = 8;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.nonce = 0;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.nonce = u64::MAX;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.access_list.clear();
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.resource_limit.io = 0;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.resource_limit.compute = u64::MAX;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.payload[0] ^= 1;
    invalid.push(signed(tx, 1));
    let mut tx = base.clone();
    tx.payload[8] ^= 1;
    invalid.push(signed(tx, 1));
    invalid.push(transfer(1, address(3), 1, 90));
    invalid.push(transfer(1, address(3), 1, u64::MAX));
    invalid.push(transfer(1, address(2), 1, 1));
    invalid.push(transfer(4, address(3), 0, 1));
    for tx in invalid {
        assert!(execute(&mut state, &[good.clone(), tx]).is_err());
        assert_eq!(state.export_snapshot(), before);
    }
}

#[test]
fn rejected_overlay_entry_does_not_consume_balance_nonce_or_resources() {
    let state = funded(&[(1, 0, 100), (2, 0, u64::MAX)]);
    let snapshot = state.snapshot().unwrap();
    let mut session = PaymentSession::new(snapshot.as_ref(), context(), capacity());
    assert_eq!(
        session.execute(&transfer(1, address(2), 0, 1)),
        Err(ExecutionError::Trap)
    );
    let output = session.execute(&transfer(1, address(3), 0, 99)).unwrap();
    let committed = state.prepare(state.root(), &[output.diff]).unwrap();
    assert_eq!(
        account(&committed, 1),
        AccountState {
            nonce: 1,
            balance: 0
        }
    );
}

#[test]
fn stale_roots_corrupt_accounts_and_total_resource_exhaustion_fail_closed() {
    let mut state = funded(&[(1, 0, 100)]);
    let before = state.export_snapshot();
    assert_eq!(
        execute_payments(&mut state, &[], Hash256::ZERO, context(), capacity()),
        Err(ExecutionError::State(StateError::StaleSnapshot))
    );
    let txs = [transfer(1, address(2), 0, 1), transfer(1, address(2), 1, 1)];
    let root = state.root();
    assert_eq!(
        execute_payments(
            &mut state,
            &txs,
            root,
            context(),
            Resources {
                compute: 1,
                ..capacity()
            }
        ),
        Err(ExecutionError::ResourceLimit)
    );
    assert_eq!(state.export_snapshot(), before);
    let mut diff = StateDiff::new();
    diff.put(account_key(address(2)), vec![0]);
    state.commit(root, &[diff]).unwrap();
    let before = state.export_snapshot();
    assert_eq!(
        execute(&mut state, &txs[..1]),
        Err(ExecutionError::State(StateError::Corrupt))
    );
    assert_eq!(state.export_snapshot(), before);
}

#[test]
fn fee_reserve_nonce_exhaustion_and_transaction_bounds_are_checked() {
    let mut state = funded(&[(1, 0, 100), (2, u64::MAX, 100)]);
    let mut tx = transfer(1, address(1), 0, 90);
    tx.resource_limit.compute = 11;
    assert_eq!(
        execute(&mut state, &[signed(tx, 1)]),
        Err(ExecutionError::TransactionValidation(
            TransactionError::InsufficientResources
        ))
    );
    assert_eq!(
        execute(&mut state, &[transfer(2, address(1), u64::MAX, 1)]),
        Err(ExecutionError::TransactionValidation(
            TransactionError::InvalidNonce
        ))
    );
    let tx = transfer(1, address(3), 0, 1);
    let root = state.root();
    assert_eq!(
        execute_payments(
            &mut state,
            &[tx],
            root,
            ValidationContext {
                max_transaction_bytes: 10,
                ..context()
            },
            capacity()
        ),
        Err(ExecutionError::TransactionValidation(
            TransactionError::InvalidEnvelope
        ))
    );
}

#[test]
fn payment_payload_has_fixed_canonical_bytes_and_rejects_every_truncation() {
    let payment = Payment {
        public_key: [7; 32],
        recipient: Address([8; 32]),
        amount: 0x0102_0304_0506_0708,
    };
    let bytes = payment.to_bytes();
    assert_eq!(&bytes[..8], b"ALPAY001");
    assert_eq!(&bytes[8..40], &[7; 32]);
    assert_eq!(&bytes[40..72], &[8; 32]);
    assert_eq!(&bytes[72..], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(Payment::decode(&bytes), Ok(payment));
    for len in 0..bytes.len() {
        assert!(Payment::decode(&bytes[..len]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Payment::decode(&trailing).is_err());
    assert!(
        Payment::decode(
            &Payment {
                amount: 0,
                ..payment
            }
            .to_bytes()
        )
        .is_err()
    );
    assert!(
        Payment::decode(
            &Payment {
                recipient: Address([0; 32]),
                ..payment
            }
            .to_bytes()
        )
        .is_err()
    );
}

#[test]
fn changed_height_lane_or_prices_reject_the_entire_block() {
    for (field, expected) in [
        (0, TransactionError::Expired),
        (1, TransactionError::UnsupportedPayload),
        (2, TransactionError::InsufficientResources),
    ] {
        let mut state = funded(&[(1, 0, 100), (2, 0, 100)]);
        let root = state.root();
        let first = transfer(1, address(3), 0, 5);
        let mut second = transfer(2, address(3), 0, 5);
        match field {
            0 => second.expires_at = 0,
            1 => second.lane = types::TransactionLane::Contracts,
            _ => second.resource_prices = Resources::ZERO,
        }
        assert_eq!(
            execute(&mut state, &[first, signed(second, 2)]),
            Err(ExecutionError::TransactionValidation(expected))
        );
        assert_eq!(state.root(), root);
        assert_eq!(account(&state, 1).nonce, 0);
        assert_eq!(account(&state, 2).nonce, 0);
    }
    let mut state = funded(&[(1, 0, 100)]);
    let root = state.root();
    let mut tx = transfer(1, address(2), 0, 5);
    tx.expires_at = 1;
    let tx = signed(tx, 1);
    let mut later = context();
    later.next_height = 2;
    assert!(
        execute_payments(
            &mut state,
            std::slice::from_ref(&tx),
            root,
            later,
            capacity()
        )
        .is_err()
    );
    assert_eq!(state.root(), root);
    execute(&mut state, &[tx]).unwrap();
}
