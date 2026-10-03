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
            RpcRequest::Receipt { id, height } => {
                let height = height.or_else(|| {
                    node.storage()
                        .transaction_location(id)
                        .map(|(height, _)| height)
                });
                let Some(height) = height else {
                    return Ok(RpcResponse::Receipt(None));
                };
                let stored = node.storage().read_receipts(height).map_err(|error| {
                    let _ = error;
                    RpcError::Unavailable
                })?;
                let proof = stored
                    .filter(|stored| {
                        stored
                            .effects
                            .receipts
                            .iter()
                            .any(|receipt| receipt.transaction == id)
                    })
                    .map(|stored| rpc::CertifiedReceiptProof(stored).to_bytes())
                    .transpose()?;
                Ok(RpcResponse::Receipt(proof))
            }
            RpcRequest::StateProof(key) if self.accounts_enabled => {
                let snapshot = node
                    .storage()
                    .state()
                    .snapshot()
                    .map_err(|_| RpcError::Unavailable)?;
                let height = node
                    .storage()
                    .checkpoint()
                    .ok_or(RpcError::Unavailable)?
                    .height;
                let finality = if height == 0 {
                    None
                } else {
                    let (block, certificate) = node
                        .storage()
                        .read_finalized(height)
                        .map_err(|_| RpcError::Unavailable)?
                        .ok_or(RpcError::Unavailable)?;
                    Some((block.header, certificate))
                };
                let proof = rpc::CertifiedStateProof::create(snapshot.as_ref(), &key, finality)?;
                Ok(RpcResponse::StateProof(proof.to_bytes()?))
            }
            RpcRequest::CommitteeHandoff(_) => Ok(RpcResponse::CommitteeHandoff(None)),
            RpcRequest::PotbHandoff(_) => Ok(RpcResponse::PotbHandoff(None)),
            RpcRequest::SubmitPotbAdmission(_) | RpcRequest::SubmitPotbEvidence(_) => {
                Err(RpcError::Unavailable)
            }
            RpcRequest::Block(height) => {
                let block = node
                    .storage()
                    .read_finalized(height)
                    .map_err(|_| RpcError::Unavailable)?;
                Ok(RpcResponse::Block(block.map(|(block, _)| Box::new(block))))
            }
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
            RpcRequest::Account(_)
            | RpcRequest::SubmitTransaction(_)
            | RpcRequest::StateProof(_) => Err(RpcError::Unavailable),
        }
    }
}
