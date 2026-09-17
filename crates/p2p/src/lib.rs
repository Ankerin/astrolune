// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Specialized binary `P2P` primitives for consensus and block propagation.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;
use std::fmt;

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

impl MessageKind {
    /// Attempts to convert a raw discriminant byte into a [`MessageKind`].
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Hello),
            1 => Some(Self::Transactions),
            2 => Some(Self::CompactBlock),
            3 => Some(Self::Proposal),
            4 => Some(Self::Vote),
            5 => Some(Self::Finality),
            _ => None,
        }
    }
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

impl CompactBlock {
    /// Attempts to reconstruct the full transaction list from `known_txs`.
    ///
    /// Prefilled transactions are placed at their declared indices. Remaining
    /// indices are matched against `known_txs` by short-id lookup. If any
    /// short-id has no matching transaction the result is
    /// [`Reconstruction::Missing`] listing the unresolved identifiers.
    ///
    /// # Panics
    ///
    /// Panics if the total number of slots exceeds `usize::MAX` (practically
    /// unreachable).
    #[must_use]
    pub fn reconstruct(&self, known_txs: &BTreeMap<u64, Transaction>) -> Reconstruction {
        let total = self.short_ids.len() + self.prefilled.len();
        let mut txs: Vec<Option<Transaction>> = vec![None; total];

        for &(idx, ref tx) in &self.prefilled {
            if idx < total {
                txs[idx] = Some(tx.clone());
            }
        }

        let mut missing = Vec::new();
        let mut short_idx = 0;
        for slot in &mut txs {
            if slot.is_some() {
                continue;
            }
            if short_idx >= self.short_ids.len() {
                break;
            }
            let short_id = self.short_ids[short_idx];
            short_idx += 1;

            if let Some(tx) = known_txs.get(&short_id) {
                *slot = Some(tx.clone());
            } else {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&short_id.to_le_bytes());
                missing.push(Hash256(h));
            }
        }

        if missing.is_empty() {
            Reconstruction::Complete(
                txs.into_iter()
                    .map(|opt| opt.expect("all slots filled"))
                    .collect(),
            )
        } else {
            Reconstruction::Missing(missing)
        }
    }
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

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrame => write!(f, "invalid frame"),
            Self::IncompatiblePeer => write!(f, "incompatible peer"),
            Self::LimitExceeded => write!(f, "limit exceeded"),
        }
    }
}

impl std::error::Error for NetworkError {}

/// Maximum frame payload size in bytes (1 MiB).
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Frame header size: 1 byte kind + 4 bytes LE length.
pub const FRAME_HEADER_SIZE: usize = 5;

/// A [`FrameDecoder`] implementation that enforces a maximum payload size.
#[derive(Clone, Copy, Debug)]
pub struct BoundedFrameDecoder {
    max_frame_size: usize,
}

impl BoundedFrameDecoder {
    /// Creates a new decoder with the given maximum frame payload size.
    #[must_use]
    pub fn new(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }
}

impl FrameDecoder for BoundedFrameDecoder {
    fn decode<'a>(&self, bytes: &'a [u8]) -> Result<Frame<'a>, NetworkError> {
        if bytes.len() < FRAME_HEADER_SIZE {
            return Err(NetworkError::InvalidFrame);
        }

        let kind = MessageKind::from_u8(bytes[0]).ok_or(NetworkError::InvalidFrame)?;

        let len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;

        if len > self.max_frame_size {
            return Err(NetworkError::LimitExceeded);
        }

        if bytes.len() != FRAME_HEADER_SIZE + len {
            return Err(NetworkError::InvalidFrame);
        }

        Ok(Frame {
            kind,
            payload: &bytes[FRAME_HEADER_SIZE..],
        })
    }
}

/// Encodes a message kind and payload into a canonical binary frame.
#[derive(Clone, Copy, Debug)]
pub struct FrameEncoder;

impl FrameEncoder {
    /// Encodes `kind` and `payload` into a byte vector with a 5-byte header.
    ///
    /// # Panics
    ///
    /// Panics if `payload.len()` exceeds `u32::MAX`.
    #[must_use]
    pub fn encode(kind: MessageKind, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).expect("payload exceeds u32::MAX");
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
        buf.push(kind as u8);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> BlockHeader {
        BlockHeader {
            height: 1,
            parent: Hash256([0xAA; 32]),
            transactions_root: Hash256([1u8; 32]),
            state_root: Hash256([2u8; 32]),
            receipts_root: Hash256([3u8; 32]),
            committee_root: Hash256([4u8; 32]),
            capacity: types::Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
        }
    }

    fn sample_tx(nonce: u64) -> Transaction {
        Transaction {
            chain_id: 1,
            sender: types::Address([0x10; 32]),
            nonce,
            access_list: Vec::new(),
            resource_limit: types::Resources::ZERO,
            payload: vec![0xDE, 0xAD],
            signature: [0xAB; 64],
        }
    }

    // --- NetworkError Display and Error ---

    #[test]
    fn network_error_display() {
        assert_eq!(format!("{}", NetworkError::InvalidFrame), "invalid frame");
        assert_eq!(
            format!("{}", NetworkError::IncompatiblePeer),
            "incompatible peer"
        );
        assert_eq!(format!("{}", NetworkError::LimitExceeded), "limit exceeded");
    }

    #[test]
    fn network_error_is_error() {
        let err: &dyn std::error::Error = &NetworkError::InvalidFrame;
        assert_eq!(err.to_string(), "invalid frame");
    }

    // --- Constants ---

    #[test]
    fn max_frame_size_is_1_mib() {
        assert_eq!(MAX_FRAME_SIZE, 1024 * 1024);
    }

    #[test]
    fn frame_header_size_is_5() {
        assert_eq!(FRAME_HEADER_SIZE, 5);
    }

    // --- Encode / Decode roundtrip ---

    #[test]
    fn encode_decode_roundtrip() {
        for kind in [
            MessageKind::Hello,
            MessageKind::Transactions,
            MessageKind::CompactBlock,
            MessageKind::Proposal,
            MessageKind::Vote,
            MessageKind::Finality,
        ] {
            let payload = b"hello world";
            let encoded = FrameEncoder::encode(kind, payload);
            let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
            let frame = decoder.decode(&encoded).unwrap();
            assert_eq!(frame.kind, kind);
            assert_eq!(frame.payload, payload);
        }
    }

    #[test]
    fn encode_decode_empty_payload() {
        let encoded = FrameEncoder::encode(MessageKind::Hello, &[]);
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        let frame = decoder.decode(&encoded).unwrap();
        assert_eq!(frame.kind, MessageKind::Hello);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn encode_decode_max_payload() {
        let payload = vec![0xAB; MAX_FRAME_SIZE];
        let encoded = FrameEncoder::encode(MessageKind::Vote, &payload);
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        let frame = decoder.decode(&encoded).unwrap();
        assert_eq!(frame.kind, MessageKind::Vote);
        assert_eq!(frame.payload, &payload[..]);
    }

    // --- Oversized frame rejection ---

    #[test]
    fn oversized_frame_rejected() {
        let payload = vec![0u8; 100];
        let encoded = FrameEncoder::encode(MessageKind::Hello, &payload);
        let decoder = BoundedFrameDecoder::new(50);
        assert_eq!(decoder.decode(&encoded), Err(NetworkError::LimitExceeded));
    }

    // --- Unknown kind rejection ---

    #[test]
    fn unknown_kind_rejected() {
        let mut bytes = vec![0xFF; 10];
        bytes[0] = 0xFF;
        bytes[1] = 5;
        bytes[2] = 0;
        bytes[3] = 0;
        bytes[4] = 0;
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        assert_eq!(decoder.decode(&bytes), Err(NetworkError::InvalidFrame));
    }

    // --- Trailing bytes rejection ---

    #[test]
    fn trailing_bytes_rejected() {
        let payload = b"payload";
        let mut encoded = FrameEncoder::encode(MessageKind::Hello, payload);
        encoded.push(0xFF); // trailing byte
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        assert_eq!(decoder.decode(&encoded), Err(NetworkError::InvalidFrame));
    }

    #[test]
    fn too_short_header_rejected() {
        let decoder = BoundedFrameDecoder::new(MAX_FRAME_SIZE);
        assert_eq!(decoder.decode(&[0, 1, 2]), Err(NetworkError::InvalidFrame));
        assert_eq!(decoder.decode(&[]), Err(NetworkError::InvalidFrame));
    }

    // --- Compact block reconstruction: complete ---

    #[test]
    fn compact_block_reconstruct_complete() {
        let tx0 = sample_tx(0);
        let tx1 = sample_tx(1);
        let tx2 = sample_tx(2);

        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![100, 300],
            prefilled: vec![(1, tx1.clone())],
        };

        let mut known = BTreeMap::new();
        known.insert(100, tx0.clone());
        known.insert(300, tx2.clone());

        let result = block.reconstruct(&known);
        match result {
            Reconstruction::Complete(txs) => {
                assert_eq!(txs.len(), 3);
                assert_eq!(txs[0], tx0);
                assert_eq!(txs[1], tx1);
                assert_eq!(txs[2], tx2);
            }
            Reconstruction::Missing(_) => panic!("expected Complete"),
        }
    }

    // --- Compact block reconstruction: missing ---

    #[test]
    fn compact_block_reconstruct_missing() {
        let tx0 = sample_tx(0);

        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![100, 200, 300],
            prefilled: vec![],
        };

        let mut known = BTreeMap::new();
        known.insert(100, tx0);

        let result = block.reconstruct(&known);
        match result {
            Reconstruction::Complete(_) => panic!("expected Missing"),
            Reconstruction::Missing(missing) => {
                assert_eq!(missing.len(), 2);
                let mut h0 = [0u8; 32];
                h0[..8].copy_from_slice(&200u64.to_le_bytes());
                assert_eq!(missing[0], Hash256(h0));
                let mut h1 = [0u8; 32];
                h1[..8].copy_from_slice(&300u64.to_le_bytes());
                assert_eq!(missing[1], Hash256(h1));
            }
        }
    }

    #[test]
    fn compact_block_reconstruct_all_prefilled() {
        let tx0 = sample_tx(0);
        let tx1 = sample_tx(1);

        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![],
            prefilled: vec![(0, tx0.clone()), (1, tx1.clone())],
        };

        let known = BTreeMap::new();
        let result = block.reconstruct(&known);
        match result {
            Reconstruction::Complete(txs) => {
                assert_eq!(txs, vec![tx0, tx1]);
            }
            Reconstruction::Missing(_) => panic!("expected Complete"),
        }
    }

    #[test]
    fn compact_block_reconstruct_empty() {
        let block = CompactBlock {
            header: sample_header(),
            short_ids: vec![],
            prefilled: vec![],
        };
        let known = BTreeMap::new();
        let result = block.reconstruct(&known);
        assert_eq!(result, Reconstruction::Complete(vec![]));
    }

    // --- MessageKind from_u8 ---

    #[test]
    fn message_kind_from_u8_roundtrips() {
        let kinds = [
            MessageKind::Hello,
            MessageKind::Transactions,
            MessageKind::CompactBlock,
            MessageKind::Proposal,
            MessageKind::Vote,
            MessageKind::Finality,
        ];
        for kind in kinds {
            assert_eq!(MessageKind::from_u8(kind as u8), Some(kind));
        }
        assert_eq!(MessageKind::from_u8(6), None);
        assert_eq!(MessageKind::from_u8(255), None);
    }
}
