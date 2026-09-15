// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

#![allow(missing_docs)]

use std::path::PathBuf;

use codec::{DecodeError, Decoder, PROTOCOL_VERSION};
use config::{NetworkConfig, NodeConfig, SecretRef};
use consensus::quorum_power;
use genesis::{Genesis, GenesisValidator};
use mempool::{Mempool, PoolEntry, PoolLimits};
use testkit::{hash, resources, transaction, validator};

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
