// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Canonical signed transaction envelope.

use crate::address::Address;
use crate::resources::Resources;
use crate::state_key::StateKey;

/// A canonical signed transaction envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    /// Network replay-protection identifier.
    pub chain_id: u32,
    /// Sender account.
    pub sender: Address,
    /// Sender sequence number.
    pub nonce: u64,
    /// Declared state keys needed by execution.
    pub access_list: Vec<StateKey>,
    /// Maximum resources the sender authorizes.
    pub resource_limit: Resources,
    /// Canonical transaction payload.
    pub payload: Vec<u8>,
    /// Signature over every preceding canonical field.
    pub signature: [u8; 64],
}
