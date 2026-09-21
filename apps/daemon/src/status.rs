// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! RPC admission and account reads serialized with durable node publication.

use std::sync::{Arc, Mutex};

use codec::{CanonicalDecode, CanonicalEncode};
use node::{FullNodeService, ProducerError};
use rpc::{RpcError, RpcRequest, RpcResponse, RpcService};
use state::{StateDatabase, read_account};
use storage::FileBackedStorage;
use types::{Hash256, Transaction};

pub(crate) struct ChainStatus {
    pub chain_id: u32,
    pub accounts_enabled: bool,
    pub node: Arc<Mutex<FullNodeService<FileBackedStorage>>>,
}

impl RpcService for ChainStatus {
    fn handle(&self, request: RpcRequest) -> Result<RpcResponse, RpcError> {
        let mut node = self.node.lock().map_err(|_| RpcError::Unavailable)?;
        match request {
            RpcRequest::ChainStatus => {
                let checkpoint = node.storage().checkpoint();
                Ok(RpcResponse::ChainStatus {
                    chain_id: self.chain_id,
                    finalized_height: checkpoint.map_or(0, |head| head.height),
                    finalized_block: checkpoint.map_or(Hash256::ZERO, |head| head.block),
                })
            }
            RpcRequest::Account(address) if self.accounts_enabled => {
                let snapshot = node
                    .storage()
                    .state()
                    .snapshot()
                    .map_err(|_| RpcError::Unavailable)?;
                let account =
                    read_account(snapshot.as_ref(), address).map_err(|_| RpcError::Unavailable)?;
                Ok(RpcResponse::Account(account.map(|value| value.to_bytes())))
            }
            RpcRequest::SubmitTransaction(bytes) if self.accounts_enabled => {
                if bytes.len() > 1024 * 1024 {
                    return Err(RpcError::LimitExceeded);
                }
                let tx = Transaction::decode(&bytes).map_err(|_| RpcError::InvalidRequest)?;
                let id = node.submit_transaction(tx).map_err(|error| match error {
                    ProducerError::Mempool(_) => RpcError::LimitExceeded,
                    ProducerError::Storage(_) => RpcError::Unavailable,
                    _ => RpcError::InvalidRequest,
                })?;
                Ok(RpcResponse::TransactionAccepted(id))
            }
            RpcRequest::Account(_) | RpcRequest::SubmitTransaction(_) => Err(RpcError::Unavailable),
        }
    }
}
