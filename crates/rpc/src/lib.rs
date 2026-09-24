// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Bounded external `RPC` types for wallets, applications, and operators.
//!
//! This interface is deliberately separate from the binary consensus protocol.
//! The `TcpRpcServer` provides a synchronous JSON-RPC server over TCP.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

pub mod client;
pub mod json;
pub mod server;

pub use client::{ChainStatus, ClientError, TcpRpcClient};
pub use json::{JsonRpcRequest, JsonRpcResponse};
pub use server::TcpRpcServer;

use std::collections::BTreeMap;
use std::fmt;
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
pub trait RpcService: Send {
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

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => write!(f, "invalid request"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::LimitExceeded => write!(f, "limit exceeded"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

impl std::error::Error for RpcError {}

/// A simple in-memory RPC service for testing and development.
///
/// Stores chain state, account data, and pending transactions in memory
/// using deterministic data structures.
#[derive(Clone, Debug)]
pub struct InMemoryRpcService {
    chain_id: u32,
    finalized_height: u64,
    finalized_block: Hash256,
    accounts: BTreeMap<Address, Vec<u8>>,
    pending_transactions: Vec<Hash256>,
}

impl InMemoryRpcService {
    /// Creates a new in-memory service with the given chain identifier.
    ///
    /// The service starts at height 0 with the all-zero finalized block.
    #[must_use]
    pub fn new(chain_id: u32) -> Self {
        Self {
            chain_id,
            finalized_height: 0,
            finalized_block: Hash256::ZERO,
            accounts: BTreeMap::new(),
            pending_transactions: Vec::new(),
        }
    }

    /// Sets the finalized head to the given height and block hash.
    pub fn set_finalized(&mut self, height: u64, block: Hash256) {
        self.finalized_height = height;
        self.finalized_block = block;
    }

    /// Stores opaque account state for the given address.
    pub fn set_account(&mut self, addr: Address, data: Vec<u8>) {
        self.accounts.insert(addr, data);
    }

    /// Returns a reference to all pending transaction hashes.
    #[must_use]
    pub fn pending_transactions(&self) -> &[Hash256] {
        &self.pending_transactions
    }

    /// Computes a simple deterministic hash of transaction bytes.
    fn hash_transaction(bytes: &[u8]) -> Hash256 {
        let mut hash = [0u8; 32];
        for (i, byte) in bytes.iter().enumerate() {
            hash[i % 32] ^= byte;
        }
        Hash256(hash)
    }
}

impl RpcService for InMemoryRpcService {
    fn handle(&self, request: RpcRequest) -> Result<RpcResponse, RpcError> {
        match request {
            RpcRequest::ChainStatus => Ok(RpcResponse::ChainStatus {
                chain_id: self.chain_id,
                finalized_height: self.finalized_height,
                finalized_block: self.finalized_block,
            }),
            RpcRequest::Account(addr) => {
                let data = self.accounts.get(&addr).cloned();
                Ok(RpcResponse::Account(data))
            }
            RpcRequest::SubmitTransaction(bytes) => {
                if bytes.is_empty() {
                    return Err(RpcError::InvalidRequest);
                }
                let hash = Self::hash_transaction(&bytes);
                Ok(RpcResponse::TransactionAccepted(hash))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_status_query() {
        let service = InMemoryRpcService::new(42);
        let resp = service.handle(RpcRequest::ChainStatus).unwrap();
        match resp {
            RpcResponse::ChainStatus {
                chain_id,
                finalized_height,
                finalized_block,
            } => {
                assert_eq!(chain_id, 42);
                assert_eq!(finalized_height, 0);
                assert_eq!(finalized_block, Hash256::ZERO);
            }
            _ => panic!("expected ChainStatus response"),
        }
    }

    #[test]
    fn account_lookup_found() {
        let mut service = InMemoryRpcService::new(1);
        let addr = Address::from_bytes([0xAA; 32]);
        service.set_account(addr, vec![1, 2, 3]);

        let resp = service.handle(RpcRequest::Account(addr)).unwrap();
        assert_eq!(resp, RpcResponse::Account(Some(vec![1, 2, 3])));
    }

    #[test]
    fn account_lookup_missing() {
        let service = InMemoryRpcService::new(1);
        let addr = Address::from_bytes([0xBB; 32]);

        let resp = service.handle(RpcRequest::Account(addr)).unwrap();
        assert_eq!(resp, RpcResponse::Account(None));
    }

    #[test]
    fn submit_valid_transaction() {
        let service = InMemoryRpcService::new(1);
        let tx = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let resp = service.handle(RpcRequest::SubmitTransaction(tx)).unwrap();
        match resp {
            RpcResponse::TransactionAccepted(hash) => {
                assert_ne!(hash, Hash256::ZERO);
            }
            _ => panic!("expected TransactionAccepted response"),
        }
    }

    #[test]
    fn submit_empty_transaction_rejected() {
        let service = InMemoryRpcService::new(1);
        let result = service.handle(RpcRequest::SubmitTransaction(Vec::new()));
        assert_eq!(result, Err(RpcError::InvalidRequest));
    }

    #[test]
    fn full_lifecycle() {
        let mut service = InMemoryRpcService::new(7);

        // Initial status
        let resp = service.handle(RpcRequest::ChainStatus).unwrap();
        match resp {
            RpcResponse::ChainStatus {
                chain_id,
                finalized_height,
                ..
            } => {
                assert_eq!(chain_id, 7);
                assert_eq!(finalized_height, 0);
            }
            _ => panic!("expected ChainStatus"),
        }

        // Set finalized
        let block = Hash256::from_bytes([0xCC; 32]);
        service.set_finalized(10, block);

        let resp = service.handle(RpcRequest::ChainStatus).unwrap();
        match resp {
            RpcResponse::ChainStatus {
                finalized_height,
                finalized_block,
                ..
            } => {
                assert_eq!(finalized_height, 10);
                assert_eq!(finalized_block, block);
            }
            _ => panic!("expected ChainStatus"),
        }

        // Account missing then set
        let addr = Address::from_bytes([0x11; 32]);
        assert_eq!(
            service.handle(RpcRequest::Account(addr)).unwrap(),
            RpcResponse::Account(None)
        );

        service.set_account(addr, vec![42, 43]);
        assert_eq!(
            service.handle(RpcRequest::Account(addr)).unwrap(),
            RpcResponse::Account(Some(vec![42, 43]))
        );

        // Submit transaction
        let tx = vec![1, 2, 3];
        let resp = service
            .handle(RpcRequest::SubmitTransaction(tx.clone()))
            .unwrap();
        match resp {
            RpcResponse::TransactionAccepted(hash) => {
                assert_eq!(hash, InMemoryRpcService::hash_transaction(&tx));
            }
            _ => panic!("expected TransactionAccepted"),
        }
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(RpcError::InvalidRequest.to_string(), "invalid request");
        assert_eq!(RpcError::Unauthorized.to_string(), "unauthorized");
        assert_eq!(RpcError::LimitExceeded.to_string(), "limit exceeded");
        assert_eq!(RpcError::Unavailable.to_string(), "unavailable");
    }

    #[test]
    fn error_is_std_error() {
        let err: &dyn std::error::Error = &RpcError::InvalidRequest;
        assert_eq!(err.to_string(), "invalid request");
    }

    #[test]
    fn pending_transactions_empty_by_default() {
        let service = InMemoryRpcService::new(1);
        assert!(service.pending_transactions().is_empty());
    }

    #[test]
    fn transaction_hash_deterministic() {
        let tx = vec![0xCA, 0xFE];
        let h1 = InMemoryRpcService::hash_transaction(&tx);
        let h2 = InMemoryRpcService::hash_transaction(&tx);
        assert_eq!(h1, h2);
    }
}
