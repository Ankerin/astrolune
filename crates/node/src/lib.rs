// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Node pipeline coordination across propagation, consensus, execution, and commit.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use types::Resources;

/// Overlappable stages for height `h` and `h + 1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipelineStage {
    /// Receive or reconstruct an ordered proposal.
    Propagation,
    /// Collect prevotes and precommits without mutating canonical state.
    Voting,
    /// Execute the consensus-fixed transaction order on a snapshot.
    Execution,
    /// Publish deferred state changes after execution and finality validation.
    Commit,
}

/// Finalized performance observations used by adaptive block sizing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityObservation {
    /// Measured resources consumed by a finalized block.
    pub used: Resources,
    /// Whether the block met the finality latency target.
    pub within_latency_target: bool,
}

/// Deterministically adjusts block limits from a finalized observation window.
pub trait CapacityController {
    /// Computes the next consensus-visible capacity. Local live measurements may
    /// inform proposals, but only finalized, quantized observations may change it.
    fn next_capacity(&self, current: Resources, observations: &[CapacityObservation]) -> Resources;
}

/// Top-level node service boundary.
pub trait NodeService {
    /// Advances available stages without coupling finality to execution threads.
    fn advance(&mut self) -> Result<(), NodeError>;
}

/// Node orchestration failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeError {
    /// A required subsystem is not ready.
    NotReady,
    /// A finalized commitment disagrees with deterministic execution.
    CommitmentMismatch,
    /// A bounded queue or configured resource ceiling was reached.
    CapacityExceeded,
}
