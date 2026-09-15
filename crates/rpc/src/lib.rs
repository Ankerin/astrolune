// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Bounded external `RPC` types for wallets, applications, and operators.
//!
//! This interface is deliberately separate from the binary consensus protocol.

#![forbid(unsafe_code)]

use types::{Address, Hash256};

/// Public request accepted by the baseline service boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcRequest {
    /// Returns chain status.
    ChainStatus,
    /// Returns one finalized account view.
    Account(Address),
    /// Submits canonical signed transaction bytes.
    SubmitTransaction(Vec<u8>),
}

/// Public response produced by the service boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcResponse {
    /// Chain identity and finalized head.
    ChainStatus {
        /// Chain replay-protection identifier.
        chain_id: u32,
        /// Highest finalized height.
        finalized_height: u64,
        /// Highest finalized block hash.
        finalized_block: Hash256,
    },
    /// Opaque canonical account bytes for the requested finalized state.
    Account(Option<Vec<u8>>),
    /// Accepted transaction identifier.
    TransactionAccepted(Hash256),
}

/// Handles authenticated and rate-limited external requests.
pub trait RpcService {
    /// Processes one already bounded transport request.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] for invalid input, overload, authorization failure,
    /// or unavailable node state.
    fn handle(&self, request: RpcRequest) -> Result<RpcResponse, RpcError>;
}

/// External API failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcError {
    /// Request structure or canonical payload is invalid.
    InvalidRequest,
    /// Caller is not authorized for this operation.
    Unauthorized,
    /// Request or response exceeds a configured bound.
    LimitExceeded,
    /// Node is synchronizing or otherwise unavailable.
    Unavailable,
}
