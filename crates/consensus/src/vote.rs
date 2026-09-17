// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! BFT vote types and voting phases.

use types::{Hash256, ValidatorId};

/// The two voting phases used by fast `BFT` finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VotePhase {
    /// A validator considers the proposal valid for the round.
    Prevote,
    /// A validator locks and commits after observing a prevote quorum.
    Precommit,
}

/// A signed `BFT` vote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vote {
    /// Target height.
    pub height: u64,
    /// Round within the height.
    pub round: u32,
    /// Voting phase.
    pub phase: VotePhase,
    /// Proposed block, or `None` for a nil vote.
    pub block: Option<Hash256>,
    /// Committee member that produced the vote.
    pub voter: ValidatorId,
    /// Canonical signature bytes.
    pub signature: [u8; 64],
}
