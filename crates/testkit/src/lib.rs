// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic non-production fixtures for workspace tests.

#![forbid(unsafe_code)]

use types::{Address, Hash256, Resources, Transaction, ValidatorId};

/// Creates a digest filled with one byte for readable fixtures.
#[must_use]
pub const fn hash(byte: u8) -> Hash256 {
    Hash256([byte; 32])
}

/// Creates an address filled with one byte for readable fixtures.
#[must_use]
pub const fn address(byte: u8) -> Address {
    Address([byte; 32])
}

/// Creates a validator identity filled with one byte for readable fixtures.
#[must_use]
pub const fn validator(byte: u8) -> ValidatorId {
    ValidatorId([byte; 32])
}

/// Creates non-zero resource limits suitable only for tests.
#[must_use]
pub const fn resources(value: u64) -> Resources {
    Resources {
        compute: value,
        memory: value,
        io: value,
        bandwidth: value,
    }
}

/// Creates a minimal unsigned fixture transaction.
#[must_use]
pub fn transaction(sender: u8, nonce: u64) -> Transaction {
    let mut sig = [0u8; 64];
    sig[0] = sender; // non-zero signature for validation
    Transaction {
        chain_id: 1,
        sender: address(sender),
        nonce,
        access_list: Vec::new(),
        resource_limit: resources(1),
        payload: Vec::new(),
        signature: sig,
    }
}
