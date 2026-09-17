// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Scheduling traits and the default serial scheduler implementation.

use state::{AccessMode, StateLease};
use types::Transaction;

use crate::wave::{ExecutionPlan, ExecutionWave};

/// Schedules declared and predicted state accesses.
pub trait ExecutionScheduler {
    /// Builds a canonical plan. Predictions may improve placement, but validators
    /// must derive the same fallback ordering when predictions are absent or wrong.
    fn plan(&self, transactions: &[Transaction]) -> ExecutionPlan;

    /// Reserves declared keys for a transaction during its execution wave.
    fn lease(&self, transaction: &Transaction) -> StateLease;
}

/// Default scheduler that places each transaction in its own wave (serial execution).
pub struct SerialScheduler;

impl ExecutionScheduler for SerialScheduler {
    fn plan(&self, transactions: &[Transaction]) -> ExecutionPlan {
        let waves = (0..transactions.len())
            .map(|i| ExecutionWave {
                transaction_indexes: vec![i],
            })
            .collect();
        ExecutionPlan { waves }
    }

    fn lease(&self, transaction: &Transaction) -> StateLease {
        let requests = transaction
            .access_list
            .iter()
            .map(|key| state::AccessRequest {
                key: key.clone(),
                mode: AccessMode::Write,
            })
            .collect();
        StateLease { requests }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Address, Resources};

    fn sender() -> Address {
        Address([1u8; 32])
    }

    fn make_tx(nonce: u64, payload: Vec<u8>) -> Transaction {
        Transaction {
            chain_id: 7,
            sender: sender(),
            nonce,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 10,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload,
            signature: [0xFF; 64],
        }
    }

    #[test]
    fn serial_scheduler_plan_one_per_wave() {
        let scheduler = SerialScheduler;
        let txs = vec![make_tx(0, vec![]), make_tx(0, vec![]), make_tx(0, vec![])];
        let plan = scheduler.plan(&txs);
        assert_eq!(plan.waves.len(), 3);
        assert_eq!(plan.waves[0].transaction_indexes, vec![0]);
        assert_eq!(plan.waves[1].transaction_indexes, vec![1]);
        assert_eq!(plan.waves[2].transaction_indexes, vec![2]);
    }

    #[test]
    fn serial_scheduler_lease_from_access_list() {
        let scheduler = SerialScheduler;
        let mut tx = make_tx(0, vec![]);
        tx.access_list = vec![types::StateKey(vec![1, 2]), types::StateKey(vec![3, 4])];
        let lease = scheduler.lease(&tx);
        assert_eq!(lease.requests.len(), 2);
        assert!(lease.covers(&types::StateKey(vec![1, 2]), AccessMode::Write));
        assert!(lease.covers(&types::StateKey(vec![3, 4]), AccessMode::Write));
    }
}
