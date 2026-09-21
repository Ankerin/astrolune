// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! RPC view of the daemon's last successful durable commit.

use rpc::{RpcError, RpcRequest, RpcResponse, RpcService};
use storage::Checkpoint;
use types::Hash256;

pub(crate) struct ChainStatus {
    pub chain_id: u32,
    pub checkpoint: Option<Checkpoint>,
}

impl RpcService for ChainStatus {
    fn handle(&self, request: RpcRequest) -> Result<RpcResponse, RpcError> {
        match request {
            RpcRequest::ChainStatus => Ok(RpcResponse::ChainStatus {
                chain_id: self.chain_id,
                finalized_height: self.checkpoint.map_or(0, |head| head.height),
                finalized_block: self.checkpoint.map_or(Hash256::ZERO, |head| head.block),
            }),
            // These operations require finalized account state and signed admission.
            RpcRequest::Account(_) | RpcRequest::SubmitTransaction(_) => Err(RpcError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_recovered_head_and_rejects_unwired_operations() {
        let service = ChainStatus {
            chain_id: 7,
            checkpoint: Some(Checkpoint {
                height: 12,
                block: Hash256([1; 32]),
                state_root: Hash256([2; 32]),
            }),
        };
        assert_eq!(
            service.handle(RpcRequest::ChainStatus),
            Ok(RpcResponse::ChainStatus {
                chain_id: 7,
                finalized_height: 12,
                finalized_block: Hash256([1; 32]),
            })
        );
        assert_eq!(
            service.handle(RpcRequest::SubmitTransaction(vec![1])),
            Err(RpcError::Unavailable)
        );
        assert_eq!(
            service.handle(RpcRequest::Account(types::Address([1; 32]))),
            Err(RpcError::Unavailable)
        );
    }
}
