// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Specialized binary `P2P` primitives for consensus and block propagation.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use types::{BlockHeader, Hash256, Transaction};

/// Binary protocol message kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    /// Negotiates chain, protocol version, and capabilities.
    Hello = 0,
    /// Announces transaction identifiers.
    Transactions = 1,
    /// Announces a compact block.
    CompactBlock = 2,
    /// Carries a consensus proposal.
    Proposal = 3,
    /// Carries a prevote or precommit.
    Vote = 4,
    /// Carries a finality certificate.
    Finality = 5,
}

/// Compact block reconstructed from transactions likely present in the mempool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlock {
    /// Full header required before reconstruction.
    pub header: BlockHeader,
    /// Short identifiers in committed transaction order.
    pub short_ids: Vec<u64>,
    /// Transactions the sender predicts the receiver does not have.
    pub prefilled: Vec<(usize, Transaction)>,
}

/// Result of compact-block reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reconstruction {
    /// The complete ordered transaction list is available.
    Complete(Vec<Transaction>),
    /// Missing identifiers must be requested from the announcing peer.
    Missing(Vec<Hash256>),
}

/// A zero-copy view over a validated binary frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    /// Message discriminator.
    pub kind: MessageKind,
    /// Borrowed payload from the transport receive buffer.
    pub payload: &'a [u8],
}

/// Decodes one bounded canonical frame without owning the input buffer.
pub trait FrameDecoder {
    /// Rejects unknown versions, oversized frames, non-canonical lengths, and
    /// trailing bytes before returning a borrowed payload.
    fn decode<'a>(&self, bytes: &'a [u8]) -> Result<Frame<'a>, NetworkError>;
}

/// `P2P` protocol failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkError {
    /// Frame bytes are malformed or non-canonical.
    InvalidFrame,
    /// Peer protocol or chain identity is incompatible.
    IncompatiblePeer,
    /// Configured queue, frame, or rate limit was exceeded.
    LimitExceeded,
}
