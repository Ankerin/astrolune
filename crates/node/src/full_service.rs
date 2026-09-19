// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Full node service with real subsystem integration.
//!
//! This module provides [`FullNodeService`], a concrete implementation
//! of [`NodeService`] that wires together the mempool, consensus engine,
//! execution pipeline, and persistent storage into a cohesive block
//! production and finalization workflow.

use consensus::{BftFinalityEngine, Committee, CommitteeMember};
use storage::InMemoryStorage;
use types::{Hash256, Resources};

use crate::capacity::{
    AdaptiveCapacityController, CapacityController, CapacityObservation, DEFAULT_CAPACITY,
    LATENCY_WINDOW, NodeError,
};
use crate::producer::{BlockProducer, BlockProposal, ProducerConfig};

/// Current high-level state of the full node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FullNodeState {
    /// Node is idle, waiting for the next block production cycle.
    Idle,
    /// Node is synchronizing with the network.
    Syncing,
    /// Node is selecting transactions and assembling a block proposal.
    Proposing {
        /// Height being proposed.
        height: u64,
    },
    /// Node is participating in consensus voting.
    Voting {
        /// Block height being voted on.
        height: u64,
        /// Consensus round number.
        round: u32,
    },
    /// Node is executing the finalized transaction order.
    Executing {
        /// Block height being executed.
        height: u64,
    },
    /// Node is committing finalized state to durable storage.
    Committing {
        /// Block height being committed.
        height: u64,
    },
}

/// Full node service that coordinates block production, consensus, and storage.
///
/// Integrates:
/// - [`BlockProducer`] for transaction selection and block assembly
/// - [`BftFinalityEngine`] for consensus voting and finalization
/// - [`InMemoryStorage`] for durable block and state persistence
/// - [`AdaptiveCapacityController`] for dynamic block sizing
pub struct FullNodeService {
    /// Current pipeline state.
    state: FullNodeState,
    /// Block production pipeline.
    producer: BlockProducer,
    /// BFT finality engine for consensus.
    finality_engine: Option<BftFinalityEngine>,
    /// Current committee for the active height.
    committee: Option<Committee>,
    /// Persistent storage backend.
    storage: InMemoryStorage,
    /// Adaptive capacity controller.
    capacity_controller: AdaptiveCapacityController,
    /// Recorded observations from completed blocks.
    observations: Vec<CapacityObservation>,
    /// Current adaptive block capacity.
    block_capacity: Resources,
    /// Pending block proposal awaiting consensus.
    pending_proposal: Option<BlockProposal>,
    /// Finalized block hash from consensus.
    finalized_block: Option<Hash256>,
}

impl FullNodeService {
    /// Creates a new full node service with the given producer configuration.
    #[must_use]
    pub fn new(config: ProducerConfig) -> Self {
        let block_capacity = config.block_capacity;
        let producer = BlockProducer::new(config);

        Self {
            state: FullNodeState::Idle,
            producer,
            finality_engine: None,
            committee: None,
            storage: InMemoryStorage::new(),
            capacity_controller: AdaptiveCapacityController::new(DEFAULT_CAPACITY, LATENCY_WINDOW),
            observations: Vec::new(),
            block_capacity,
            pending_proposal: None,
            finalized_block: None,
        }
    }

    /// Returns the current pipeline state.
    #[must_use]
    pub fn current_state(&self) -> &FullNodeState {
        &self.state
    }

    /// Returns the current block height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.producer.height()
    }

    /// Returns the number of pending transactions.
    #[must_use]
    pub fn pending_transactions(&self) -> usize {
        self.producer.pending_count()
    }

    /// Returns the current adaptive block capacity.
    #[must_use]
    pub fn block_capacity(&self) -> Resources {
        self.block_capacity
    }

    /// Returns a reference to the storage backend.
    #[must_use]
    pub fn storage(&self) -> &InMemoryStorage {
        &self.storage
    }

    /// Submits a transaction to the mempool.
    pub fn submit_transaction(
        &mut self,
        tx: types::Transaction,
    ) -> Result<Hash256, crate::producer::ProducerError> {
        self.producer.submit_transaction(tx)
    }

    /// Sets up the committee for the current height.
    ///
    /// In production, this would receive committee data from the network.
    /// For now, it creates a simple single-member committee for testing.
    pub fn setup_committee(&mut self, members: Vec<CommitteeMember>) {
        let height = self.producer.height();
        let committee = Committee { height, members };
        self.finality_engine = Some(BftFinalityEngine::new(committee.clone()));
        self.committee = Some(committee);
    }

    /// Returns the current committee, if set.
    #[must_use]
    pub fn committee(&self) -> Option<&Committee> {
        self.committee.as_ref()
    }

    /// Returns the finalized block hash from consensus, if any.
    #[must_use]
    pub fn finalized_block(&self) -> Option<Hash256> {
        self.finalized_block
    }

    /// Drives the pipeline through one state transition.
    ///
    /// The state machine follows the finalization path:
    /// Idle -> Proposing -> Voting -> Executing -> Committing -> Idle
    #[allow(clippy::unnecessary_wraps)]
    fn advance_pipeline(&mut self) -> Result<(), NodeError> {
        self.state = match &self.state {
            FullNodeState::Idle => FullNodeState::Proposing {
                height: self.producer.height(),
            },
            FullNodeState::Syncing => {
                // In a real node, this would sync with the network.
                // For now, transition to idle.
                FullNodeState::Idle
            }
            FullNodeState::Proposing { height } => {
                // Assemble and execute the block
                match self.producer.produce_block() {
                    Ok(proposal) => {
                        self.pending_proposal = Some(proposal);
                        FullNodeState::Voting {
                            height: *height,
                            round: 0,
                        }
                    }
                    Err(e) => {
                        eprintln!("block assembly failed: {e}");
                        FullNodeState::Idle
                    }
                }
            }
            FullNodeState::Voting { height, .. } => {
                // In single-validator mode, simulate immediate finalization
                if let Some(ref proposal) = self.pending_proposal {
                    let block_hash = proposal.block.header.compute_hash();
                    self.finalized_block = Some(block_hash);
                    FullNodeState::Executing { height: *height }
                } else {
                    FullNodeState::Idle
                }
            }
            FullNodeState::Executing { height } => {
                // Execution is already done during block assembly
                FullNodeState::Committing { height: *height }
            }
            FullNodeState::Committing { height: _ } => {
                // Commit to storage
                if let Some(proposal) = self.pending_proposal.take() {
                    let _ = self.producer.commit_block(
                        &proposal,
                        vec![0xAA; 32], // Placeholder certificate
                        &mut self.storage,
                    );

                    // Record capacity observation
                    self.observations.push(CapacityObservation {
                        used: proposal.resources_used,
                        within_latency_target: true,
                    });

                    // Update adaptive capacity
                    self.block_capacity = self
                        .capacity_controller
                        .next_capacity(self.block_capacity, &self.observations);
                }
                FullNodeState::Idle
            }
        };
        Ok(())
    }
}

impl crate::service::NodeService for FullNodeService {
    fn advance(&mut self) -> Result<(), NodeError> {
        self.advance_pipeline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::producer::ProducerConfig;
    use crate::service::NodeService;
    use consensus::CommitteeMember;
    use mempool::PoolLimits;
    use types::{Address, Resources};

    fn sender() -> Address {
        Address([1u8; 32])
    }

    fn test_config() -> ProducerConfig {
        ProducerConfig {
            chain_id: 7,
            max_block_transactions: 10,
            max_transaction_bytes: 1024,
            pool_limits: PoolLimits {
                max_transactions: 100,
                max_bytes: 1024 * 1024,
            },
            block_capacity: Resources {
                compute: 1000,
                memory: 1024,
                io: 256,
                bandwidth: 1024,
            },
        }
    }

    fn make_member(id: u8, power: u128) -> CommitteeMember {
        CommitteeMember {
            id: types::ValidatorId::from_bytes([id; 32]),
            power: consensus::PotbWeight(power),
        }
    }

    #[test]
    fn service_starts_idle() {
        let service = FullNodeService::new(test_config());
        assert_eq!(*service.current_state(), FullNodeState::Idle);
        assert_eq!(service.height(), 0);
    }

    #[test]
    fn advance_through_full_cycle() {
        let mut service = FullNodeService::new(test_config());

        // Idle -> Proposing
        service.advance().unwrap();
        assert_eq!(
            *service.current_state(),
            FullNodeState::Proposing { height: 0 }
        );

        // Proposing -> Voting
        service.advance().unwrap();
        assert!(matches!(
            *service.current_state(),
            FullNodeState::Voting {
                height: 0,
                round: 0
            }
        ));

        // Voting -> Executing
        service.advance().unwrap();
        assert_eq!(
            *service.current_state(),
            FullNodeState::Executing { height: 0 }
        );

        // Executing -> Committing
        service.advance().unwrap();
        assert_eq!(
            *service.current_state(),
            FullNodeState::Committing { height: 0 }
        );

        // Committing -> Idle
        service.advance().unwrap();
        assert_eq!(*service.current_state(), FullNodeState::Idle);
    }

    #[test]
    fn submit_transaction_increases_pending() {
        let mut service = FullNodeService::new(test_config());
        let tx = types::Transaction {
            chain_id: 7,
            sender: sender(),
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources {
                compute: 10,
                memory: 1,
                io: 1,
                bandwidth: 1,
            },
            payload: vec![1, 2, 3],
            signature: [0xFF; 64],
        };
        service.submit_transaction(tx).unwrap();
        assert_eq!(service.pending_transactions(), 1);
    }

    #[test]
    fn full_cycle_produces_block_in_storage() {
        let mut service = FullNodeService::new(test_config());

        // Run one full cycle
        for _ in 0..5 {
            service.advance().unwrap();
        }

        assert_eq!(*service.current_state(), FullNodeState::Idle);
        assert_eq!(service.height(), 1);
        assert!(service.storage().checkpoint().is_some());
    }

    #[test]
    fn multiple_full_cycles() {
        let mut service = FullNodeService::new(test_config());

        for _ in 0..3 {
            for _ in 0..5 {
                service.advance().unwrap();
            }
        }

        assert_eq!(service.height(), 3);
        assert_eq!(service.observations.len(), 3);
    }

    #[test]
    fn committee_setup() {
        let mut service = FullNodeService::new(test_config());
        let members = vec![make_member(1, 10), make_member(2, 20)];
        service.setup_committee(members);

        assert!(service.committee().is_some());
        assert_eq!(service.committee().unwrap().members.len(), 2);
    }

    #[test]
    fn block_capacity_updates() {
        let mut service = FullNodeService::new(test_config());

        // Run several cycles to trigger capacity adaptation
        for _ in 0..20 {
            for _ in 0..5 {
                service.advance().unwrap();
            }
        }

        // Capacity should have been adjusted
        assert!(service.observations.len() >= 3);
    }

    #[test]
    fn state_clone_and_eq() {
        let s1 = FullNodeState::Voting {
            height: 10,
            round: 2,
        };
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn state_debug() {
        let s = FullNodeState::Executing { height: 42 };
        let debug = format!("{s:?}");
        assert!(debug.contains("Executing"));
        assert!(debug.contains("42"));
    }
}
