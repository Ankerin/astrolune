// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Canonical, bounded protocol encoding primitives.
//!
//! All multi-byte integers use little-endian byte order. Length-prefixed byte
//! sequences use a compact 1-byte or 5-byte length encoding:
//!
//! - If the length fits in 7 bits (< 128), it is stored as one byte.
//! - Otherwise, the first byte is `0x80` followed by 4 little-endian bytes
//!   representing the length, giving a maximum of 2^32 - 1 bytes.
//!
//! This avoids the overhead of varint libraries while remaining compact for
//! the expected range of inputs.

#![forbid(unsafe_code)]

use types::{Address, BlockHeader, Hash256, Resources, StateKey, Transaction, ValidatorId};

/// Maximum allowed payload size (1 MiB).
pub const MAX_PAYLOAD: usize = 1 << 20;

/// Maximum allowed number of items in a length-prefixed list.
pub const MAX_LIST_LEN: usize = 1 << 20;

/// Maximum allowed state key length.
pub const MAX_STATE_KEY_LEN: usize = 256;

/// Current canonical encoding version.
pub const PROTOCOL_VERSION: u16 = 1;

/// A value that has one canonical byte representation.
pub trait CanonicalEncode {
    /// Appends the canonical representation to `output`.
    fn encode(&self, output: &mut Vec<u8>);

    /// Returns the canonical representation.
    #[must_use]
    fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.encode(&mut output);
        output
    }
}

/// A value decoded from one complete canonical input.
pub trait CanonicalDecode: Sized {
    /// Decodes exactly one value and rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] when the input is malformed, non-canonical,
    /// unsupported, too large, truncated, or contains trailing bytes.
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError>;
}

impl CanonicalEncode for u8 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(*self);
    }
}

impl CanonicalEncode for u16 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.to_le_bytes());
    }
}

impl CanonicalEncode for u32 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.to_le_bytes());
    }
}

impl CanonicalEncode for u64 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.to_le_bytes());
    }
}

impl CanonicalEncode for bool {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(u8::from(*self));
    }
}

impl<const N: usize> CanonicalEncode for [u8; N] {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(self);
    }
}

impl CanonicalDecode for u8 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u8()?;
        decoder.finish()?;
        Ok(value)
    }
}

impl CanonicalDecode for u16 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u16()?;
        decoder.finish()?;
        Ok(value)
    }
}

impl CanonicalDecode for u32 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u32()?;
        decoder.finish()?;
        Ok(value)
    }
}

impl CanonicalDecode for u64 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u64()?;
        decoder.finish()?;
        Ok(value)
    }
}

impl CanonicalDecode for bool {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_u8()?;
        decoder.finish()?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::NonCanonical),
        }
    }
}

impl<const N: usize> CanonicalDecode for [u8; N] {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_fixed::<N>()?;
        decoder.finish()?;
        Ok(value)
    }
}

/// Encodes a length as a compact prefix.
fn encode_length(len: usize, output: &mut Vec<u8>) {
    if len < 128 {
        output.push(u8::try_from(len).expect("length < 128 fits in u8"));
    } else {
        output.push(0x80);
        let len32 = u32::try_from(len).expect("length validated by caller");
        output.extend_from_slice(&len32.to_le_bytes());
    }
}

/// Decodes a compact length prefix.
fn decode_length(decoder: &mut Decoder<'_>) -> Result<usize, DecodeError> {
    let first = decoder.read_u8()?;
    if first < 128 {
        return Ok(first as usize);
    }
    let value = decoder.read_u32()?;
    if value as usize > MAX_LIST_LEN {
        return Err(DecodeError::LimitExceeded);
    }
    Ok(value as usize)
}

/// Encodes a byte slice with a length prefix.
fn encode_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    encode_length(bytes.len(), output);
    output.extend_from_slice(bytes);
}

/// Decodes a length-prefixed byte slice.
fn decode_bytes<'a>(decoder: &mut Decoder<'a>) -> Result<&'a [u8], DecodeError> {
    let len = decode_length(decoder)?;
    decoder.read_exact(len)
}

impl CanonicalEncode for Hash256 {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }
}

impl CanonicalDecode for Hash256 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_fixed::<32>()?;
        decoder.finish()?;
        Ok(Self(value))
    }
}

impl CanonicalEncode for Address {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }
}

impl CanonicalDecode for Address {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_fixed::<32>()?;
        decoder.finish()?;
        Ok(Self(value))
    }
}

impl CanonicalEncode for ValidatorId {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }
}

impl CanonicalDecode for ValidatorId {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.read_fixed::<32>()?;
        decoder.finish()?;
        Ok(Self(value))
    }
}

impl CanonicalEncode for StateKey {
    fn encode(&self, output: &mut Vec<u8>) {
        encode_bytes(&self.0, output);
    }
}

impl CanonicalDecode for StateKey {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let key = decode_bytes(&mut decoder)?;
        if key.len() > MAX_STATE_KEY_LEN {
            return Err(DecodeError::LimitExceeded);
        }
        decoder.finish()?;
        Ok(Self(key.to_vec()))
    }
}

impl CanonicalEncode for Resources {
    fn encode(&self, output: &mut Vec<u8>) {
        self.compute.encode(output);
        self.memory.encode(output);
        self.io.encode(output);
        self.bandwidth.encode(output);
    }
}

impl CanonicalDecode for Resources {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);
        let compute = decoder.read_u64()?;
        let memory = decoder.read_u64()?;
        let io = decoder.read_u64()?;
        let bandwidth = decoder.read_u64()?;
        decoder.finish()?;
        Ok(Self {
            compute,
            memory,
            io,
            bandwidth,
        })
    }
}

impl CanonicalEncode for Transaction {
    fn encode(&self, output: &mut Vec<u8>) {
        self.chain_id.encode(output);
        self.sender.encode(output);
        self.nonce.encode(output);

        // Access list: length-prefixed list of state keys
        encode_length(self.access_list.len(), output);
        for key in &self.access_list {
            key.encode(output);
        }

        self.resource_limit.encode(output);
        encode_bytes(&self.payload, output);
        output.extend_from_slice(&self.signature);
    }
}

impl CanonicalDecode for Transaction {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);

        let chain_id = decoder.read_u32()?;

        let sender_bytes = decoder.read_fixed::<32>()?;
        let sender = Address(sender_bytes);

        let nonce = decoder.read_u64()?;

        let list_len = decode_length(&mut decoder)?;
        if list_len > MAX_LIST_LEN {
            return Err(DecodeError::LimitExceeded);
        }
        let mut access_list = Vec::with_capacity(list_len.min(MAX_LIST_LEN));
        for _ in 0..list_len {
            access_list.push(StateKey::decode_at(&mut decoder)?);
        }

        let resource_limit = Resources::decode_at(&mut decoder)?;

        let payload_len = decode_length(&mut decoder)?;
        if payload_len > MAX_PAYLOAD {
            return Err(DecodeError::LimitExceeded);
        }
        let payload = decoder.read_exact(payload_len)?.to_vec();

        let signature: [u8; 64] = decoder.read_fixed::<64>()?;

        decoder.finish()?;

        Ok(Self {
            chain_id,
            sender,
            nonce,
            access_list,
            resource_limit,
            payload,
            signature,
        })
    }
}

impl CanonicalEncode for BlockHeader {
    fn encode(&self, output: &mut Vec<u8>) {
        self.height.encode(output);
        self.parent.encode(output);
        self.transactions_root.encode(output);
        self.state_root.encode(output);
        self.receipts_root.encode(output);
        self.committee_root.encode(output);
        self.capacity.encode(output);
    }
}

impl CanonicalDecode for BlockHeader {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(bytes);

        let height = decoder.read_u64()?;
        let parent = Hash256(decoder.read_fixed::<32>()?);
        let transactions_root = Hash256(decoder.read_fixed::<32>()?);
        let state_root = Hash256(decoder.read_fixed::<32>()?);
        let receipts_root = Hash256(decoder.read_fixed::<32>()?);
        let committee_root = Hash256(decoder.read_fixed::<32>()?);
        let capacity = Resources::decode_at(&mut decoder)?;

        decoder.finish()?;

        Ok(Self {
            height,
            parent,
            transactions_root,
            state_root,
            receipts_root,
            committee_root,
            capacity,
        })
    }
}

/// Cursor that performs bounded reads without allocation.
#[derive(Clone, Copy, Debug)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a decoder over borrowed input.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Returns the number of unread bytes.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    /// Reads an exact borrowed slice.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when fewer than `length` bytes remain.
    pub fn read_exact(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DecodeError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(DecodeError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    /// Reads a fixed-size byte array.
    ///
    /// # Panics
    ///
    /// Panics if the decoder has fewer than `N` bytes remaining. Callers must
    /// validate that at least `N` bytes are available before calling.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when fewer than `N` bytes remain.
    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let bytes = self.read_exact(N)?;
        Ok(bytes.try_into().expect("length already validated"))
    }

    /// Reads one little-endian `u8`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] when no bytes remain.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    /// Reads one little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] unless two bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let bytes: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Reads one little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] unless four bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Reads one little-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Truncated`] unless eight bytes remain.
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Completes decoding and rejects unconsumed input.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::TrailingBytes`] when unread bytes remain.
    pub const fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// Extension trait for decoding a value from an already-positioned decoder.
trait DecoderExt<'a> {
    /// Reads a `StateKey` at the current position.
    fn read_state_key(&mut self) -> Result<StateKey, DecodeError>;

    /// Reads a `Resources` at the current position.
    fn read_resources(&mut self) -> Result<Resources, DecodeError>;
}

impl<'a> DecoderExt<'a> for Decoder<'a> {
    fn read_state_key(&mut self) -> Result<StateKey, DecodeError> {
        let key = decode_bytes(self)?;
        if key.len() > MAX_STATE_KEY_LEN {
            return Err(DecodeError::LimitExceeded);
        }
        Ok(StateKey(key.to_vec()))
    }

    fn read_resources(&mut self) -> Result<Resources, DecodeError> {
        let compute = self.read_u64()?;
        let memory = self.read_u64()?;
        let io = self.read_u64()?;
        let bandwidth = self.read_u64()?;
        Ok(Resources {
            compute,
            memory,
            io,
            bandwidth,
        })
    }
}

// Helper trait for decoding at a decoder position
trait DecodeAt: Sized {
    fn decode_at(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError>;
}

impl DecodeAt for StateKey {
    fn decode_at(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_state_key()
    }
}

impl DecodeAt for Resources {
    fn decode_at(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        decoder.read_resources()
    }
}

/// Canonical decoding failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Input ended before the declared value was complete.
    Truncated,
    /// A length computation overflowed the host index type.
    LengthOverflow,
    /// Input exceeded a protocol bound.
    LimitExceeded,
    /// Input has more than one representation for the same value.
    NonCanonical,
    /// Input uses an unsupported version or mandatory feature.
    Unsupported,
    /// Bytes remained after decoding one complete value.
    TrailingBytes,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "input truncated"),
            Self::LengthOverflow => write!(f, "length overflow"),
            Self::LimitExceeded => write!(f, "protocol limit exceeded"),
            Self::NonCanonical => write!(f, "non-canonical encoding"),
            Self::Unsupported => write!(f, "unsupported version or feature"),
            Self::TrailingBytes => write!(f, "trailing bytes after value"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Primitive encoding roundtrips --

    #[test]
    fn u8_roundtrip() {
        let values = [0u8, 1, 127, 128, 255];
        for v in values {
            let encoded = v.to_bytes();
            let decoded = u8::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn u16_roundtrip() {
        let values = [0u16, 1, 255, 256, 1024, u16::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 2);
            let decoded = u16::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn u32_roundtrip() {
        let values = [0u32, 1, 256, 65536, u32::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 4);
            let decoded = u32::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn u64_roundtrip() {
        let values = [0u64, 1, 256, 65536, u64::from(u32::MAX) + 1, u64::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 8);
            let decoded = u64::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    #[test]
    fn bool_roundtrip() {
        let encoded_false = false.to_bytes();
        assert_eq!(encoded_false, [0]);
        assert!(!bool::decode(&encoded_false).unwrap());

        let encoded_true = true.to_bytes();
        assert_eq!(encoded_true, [1]);
        assert!(bool::decode(&encoded_true).unwrap());
    }

    #[test]
    fn bool_rejects_non_canonical() {
        assert_eq!(bool::decode(&[2]), Err(DecodeError::NonCanonical));
        assert_eq!(bool::decode(&[255]), Err(DecodeError::NonCanonical));
    }

    // -- Hash256 roundtrip --

    #[test]
    fn hash256_roundtrip() {
        let hash = Hash256([0xAB; 32]);
        let encoded = hash.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Hash256::decode(&encoded).unwrap();
        assert_eq!(hash, decoded);
    }

    // -- Address roundtrip --

    #[test]
    fn address_roundtrip() {
        let addr = Address([0x42; 32]);
        let encoded = addr.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Address::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    // -- ValidatorId roundtrip --

    #[test]
    fn validator_id_roundtrip() {
        let vid = ValidatorId([0x99; 32]);
        let encoded = vid.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = ValidatorId::decode(&encoded).unwrap();
        assert_eq!(vid, decoded);
    }

    // -- StateKey roundtrip --

    #[test]
    fn state_key_roundtrip() {
        let key = StateKey(vec![1, 2, 3, 4, 5]);
        let encoded = key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn state_key_empty_roundtrip() {
        let key = StateKey(Vec::new());
        let encoded = key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    // -- Resources roundtrip --

    #[test]
    fn resources_roundtrip() {
        let r = Resources {
            compute: 100,
            memory: 200,
            io: 300,
            bandwidth: 400,
        };
        let encoded = r.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Resources::decode(&encoded).unwrap();
        assert_eq!(r, decoded);
    }

    // -- Transaction roundtrip --

    #[test]
    fn transaction_roundtrip() {
        let tx = Transaction {
            chain_id: 7,
            sender: Address([1u8; 32]),
            nonce: 42,
            access_list: vec![StateKey(vec![10, 20])],
            resource_limit: Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
            payload: vec![0xDE, 0xAD],
            signature: [0xBE; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn transaction_empty_access_list() {
        let tx = Transaction {
            chain_id: 1,
            sender: Address::ZERO,
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources::ZERO,
            payload: Vec::new(),
            signature: [0; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    // -- BlockHeader roundtrip --

    #[test]
    fn block_header_roundtrip() {
        let header = BlockHeader {
            height: 100,
            parent: Hash256([1u8; 32]),
            transactions_root: Hash256([2u8; 32]),
            state_root: Hash256([3u8; 32]),
            receipts_root: Hash256([4u8; 32]),
            committee_root: Hash256([5u8; 32]),
            capacity: Resources {
                compute: 10,
                memory: 20,
                io: 30,
                bandwidth: 40,
            },
        };
        let encoded = header.to_bytes();
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    // -- Decoder boundary tests --

    #[test]
    fn decoder_rejects_truncation() {
        let mut decoder = Decoder::new(&[1]);
        assert_eq!(decoder.read_u16(), Err(DecodeError::Truncated));
    }

    #[test]
    fn decoder_rejects_trailing_bytes() {
        let decoder = Decoder::new(&[1, 2, 3]);
        assert_eq!(decoder.finish(), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn decoder_empty_succeeds() {
        let decoder = Decoder::new(&[]);
        assert_eq!(decoder.remaining(), 0);
        assert!(decoder.finish().is_ok());
    }

    #[test]
    fn length_prefix_short() {
        // Length 5 encoded as single byte
        let encoded = [5u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let mut decoder = Decoder::new(&encoded);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 5);
        let data = decoder.read_exact(5).unwrap();
        assert_eq!(data, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn length_prefix_long() {
        // Length 300 encoded as 0x80 + 4 LE bytes
        let mut encoded = vec![0x80u8];
        encoded.extend_from_slice(&300u32.to_le_bytes());
        encoded.extend_from_slice(&[0xAB; 300]);

        let mut decoder = Decoder::new(&encoded);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 300);
        let data = decoder.read_exact(300).unwrap();
        assert_eq!(data, &[0xAB; 300]);
    }

    // -- Decode error Display --

    #[test]
    fn decode_error_display() {
        assert!(!DecodeError::Truncated.to_string().is_empty());
        assert!(!DecodeError::LengthOverflow.to_string().is_empty());
        assert!(!DecodeError::LimitExceeded.to_string().is_empty());
        assert!(!DecodeError::NonCanonical.to_string().is_empty());
        assert!(!DecodeError::Unsupported.to_string().is_empty());
        assert!(!DecodeError::TrailingBytes.to_string().is_empty());
    }

    // -- Golden vector: known encoded values --

    #[test]
    fn golden_u16_zero() {
        assert_eq!(0u16.to_bytes(), [0, 0]);
    }

    #[test]
    fn golden_u16_one() {
        assert_eq!(1u16.to_bytes(), [1, 0]);
    }

    #[test]
    fn golden_u16_256() {
        assert_eq!(256u16.to_bytes(), [0, 1]);
    }

    #[test]
    fn golden_u32_max() {
        assert_eq!(u32::MAX.to_bytes(), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn golden_u64_one() {
        assert_eq!(1u64.to_bytes(), [1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn golden_resources_zero() {
        let r = Resources::ZERO;
        let encoded = r.to_bytes();
        assert_eq!(encoded, [0u8; 32]);
    }

    // -- Golden vectors: known Transaction encoding --

    #[test]
    fn golden_transaction_minimal() {
        let tx = Transaction {
            chain_id: 1,
            sender: Address([0xAA; 32]),
            nonce: 0,
            access_list: Vec::new(),
            resource_limit: Resources::ZERO,
            payload: Vec::new(),
            signature: [0xBB; 64],
        };
        let encoded = tx.to_bytes();
        // Verify length: 4 (chain_id) + 32 (sender) + 8 (nonce) + 1 (list len)
        //   + 32 (resource_limit) + 1 (payload len) + 64 (signature) = 142
        assert_eq!(encoded.len(), 142);
        // Verify roundtrip
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn golden_transaction_with_access_list() {
        let tx = Transaction {
            chain_id: 42,
            sender: Address([0x11; 32]),
            nonce: 99,
            access_list: vec![StateKey(vec![1, 2, 3]), StateKey(vec![4, 5])],
            resource_limit: Resources {
                compute: 100,
                memory: 200,
                io: 300,
                bandwidth: 400,
            },
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            signature: [0xCC; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
        // Verify access list encoding: 2 entries, each with length prefix + key bytes
        // First key: 1 byte len (3 < 128) + 3 bytes = 4
        // Second key: 1 byte len (2 < 128) + 2 bytes = 3
        // List prefix: 1 byte (2 < 128)
        // Total access list: 1 + 4 + 3 = 8
        assert!(encoded.len() > 142);
    }

    #[test]
    fn golden_block_header_all_zeros() {
        let header = BlockHeader {
            height: 0,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };
        let encoded = header.to_bytes();
        assert_eq!(encoded, [0u8; 200]);
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    // -- Boundary: decoder rejects every error variant --

    #[test]
    fn decode_error_variants_are_distinct() {
        let errors = [
            DecodeError::Truncated,
            DecodeError::LengthOverflow,
            DecodeError::LimitExceeded,
            DecodeError::NonCanonical,
            DecodeError::Unsupported,
            DecodeError::TrailingBytes,
        ];
        for (i, a) in errors.iter().enumerate() {
            for (j, b) in errors.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // -- Exhaustive roundtrip: u8 all 256 values --

    #[test]
    fn u8_exhaustive_roundtrip() {
        for v in 0u8..=255 {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 1);
            let decoded = u8::decode(&encoded).unwrap();
            assert_eq!(v, decoded);
        }
    }

    // -- u16 boundary values --

    #[test]
    fn u16_boundary_values() {
        let values = [0, 1, 127, 128, 255, 256, 1023, 1024, 32767, 32768, u16::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 2);
            assert_eq!(u16::decode(&encoded).unwrap(), v);
        }
    }

    // -- u32 boundary values --

    #[test]
    fn u32_boundary_values() {
        let values = [0u32, 1, 255, 256, 65535, 65536, u32::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 4);
            assert_eq!(u32::decode(&encoded).unwrap(), v);
        }
    }

    // -- u64 boundary values --

    #[test]
    fn u64_boundary_values() {
        let values: [u64; 8] = [0, 1, 255, 256, 65535, 65536, u64::from(u32::MAX), u64::MAX];
        for v in values {
            let encoded = v.to_bytes();
            assert_eq!(encoded.len(), 8);
            assert_eq!(u64::decode(&encoded).unwrap(), v);
        }
    }

    // -- bool only valid values are 0 and 1 --

    #[test]
    fn bool_only_canonical_values_accepted() {
        assert!(!bool::decode(&[0]).unwrap()); // 0 = false
        assert!(bool::decode(&[1]).unwrap()); // 1 = true
        for v in 2..=255 {
            assert_eq!(bool::decode(&[v]), Err(DecodeError::NonCanonical));
        }
    }

    // -- Fixed-size array roundtrips --

    #[test]
    fn fixed_array_roundtrips() {
        let arr1: [u8; 1] = [42];
        assert_eq!(<[u8; 1]>::decode(&arr1.to_bytes()).unwrap(), arr1);

        let arr4: [u8; 4] = [1, 2, 3, 4];
        assert_eq!(<[u8; 4]>::decode(&arr4.to_bytes()).unwrap(), arr4);

        let arr32: [u8; 32] = [0xAB; 32];
        assert_eq!(<[u8; 32]>::decode(&arr32.to_bytes()).unwrap(), arr32);
    }

    // -- StateKey length boundary --

    #[test]
    fn state_key_length_boundary() {
        // Exactly at max length (256) — should succeed
        let max_key = StateKey::new(vec![0xAA; 256]).unwrap();
        let encoded = max_key.to_bytes();
        let decoded = StateKey::decode(&encoded).unwrap();
        assert_eq!(max_key, decoded);

        // Over max length — should fail during decode
        let over_max = StateKey(vec![0xBB; 257]);
        let encoded = over_max.to_bytes();
        assert_eq!(StateKey::decode(&encoded), Err(DecodeError::LimitExceeded));
    }

    // -- Length prefix edge cases --

    #[test]
    fn length_prefix_exactly_127() {
        // Length 127: fits in 7 bits, encoded as single byte
        let data = vec![0xAA; 127];
        let mut encoded = vec![127u8];
        encoded.extend_from_slice(&data);
        let mut decoder = Decoder::new(&encoded);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 127);
        let result = decoder.read_exact(127).unwrap();
        assert_eq!(result, &[0xAA; 127]);
    }

    #[test]
    fn length_prefix_exactly_128() {
        // Length 128: needs 5-byte encoding
        let data = vec![0xBB; 128];
        let mut encoded = vec![0x80u8];
        encoded.extend_from_slice(&128u32.to_le_bytes());
        encoded.extend_from_slice(&data);
        let mut decoder = Decoder::new(&encoded);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 128);
        let result = decoder.read_exact(128).unwrap();
        assert_eq!(result, &[0xBB; 128]);
    }

    #[test]
    fn length_prefix_zero() {
        let mut decoder = Decoder::new(&[0u8]);
        let len = decode_length(&mut decoder).unwrap();
        assert_eq!(len, 0);
        assert!(decoder.finish().is_ok());
    }

    // -- Decoder position tracking --

    #[test]
    fn decoder_tracks_position() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut decoder = Decoder::new(&data);
        assert_eq!(decoder.remaining(), 8);
        let _ = decoder.read_u8();
        assert_eq!(decoder.remaining(), 7);
        let _ = decoder.read_u32();
        assert_eq!(decoder.remaining(), 3);
        let _ = decoder.read_exact(3).unwrap();
        assert_eq!(decoder.remaining(), 0);
    }

    // -- Transaction with maximum access list --

    #[test]
    fn transaction_roundtrip_many_access_list_entries() {
        let access_list: Vec<StateKey> = (0u8..100).map(|i| StateKey(vec![i; 10])).collect();
        let tx = Transaction {
            chain_id: u32::MAX,
            sender: Address([0xFF; 32]),
            nonce: u64::MAX,
            access_list,
            resource_limit: Resources {
                compute: u64::MAX,
                memory: u64::MAX,
                io: u64::MAX,
                bandwidth: u64::MAX,
            },
            payload: vec![0xDE; 512],
            signature: [0xAD; 64],
        };
        let encoded = tx.to_bytes();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    // -- BlockHeader all-max values --

    #[test]
    fn block_header_roundtrip_all_max() {
        let header = BlockHeader {
            height: u64::MAX,
            parent: Hash256([0xFF; 32]),
            transactions_root: Hash256([0xFF; 32]),
            state_root: Hash256([0xFF; 32]),
            receipts_root: Hash256([0xFF; 32]),
            committee_root: Hash256([0xFF; 32]),
            capacity: Resources {
                compute: u64::MAX,
                memory: u64::MAX,
                io: u64::MAX,
                bandwidth: u64::MAX,
            },
        };
        let encoded = header.to_bytes();
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    // -- Encoding is deterministic (same input -> same output) --

    #[test]
    fn encoding_determinism() {
        for v in [0u64, 1, 42, u64::MAX / 2, u64::MAX] {
            let e1 = v.to_bytes();
            let e2 = v.to_bytes();
            assert_eq!(e1, e2);
        }
    }

    // -- Trailing byte rejection for all types --

    #[test]
    fn trailing_byte_rejection_all_types() {
        // u8 with trailing byte
        assert_eq!(u8::decode(&[0, 0xFF]), Err(DecodeError::TrailingBytes));
        // u16 with trailing byte
        assert_eq!(u16::decode(&[0, 0, 0xFF]), Err(DecodeError::TrailingBytes));
        // u32 with trailing byte
        assert_eq!(
            u32::decode(&[0, 0, 0, 0, 0xFF]),
            Err(DecodeError::TrailingBytes)
        );
        // u64 with trailing byte
        assert_eq!(u64::decode(&[0; 9]), Err(DecodeError::TrailingBytes));
        // bool with trailing byte
        assert_eq!(bool::decode(&[0, 0xFF]), Err(DecodeError::TrailingBytes));
        // Hash256 with trailing byte
        let data = vec![0u8; 33];
        assert_eq!(Hash256::decode(&data), Err(DecodeError::TrailingBytes));
    }

    // -- Truncation rejection for all types --

    #[test]
    fn truncation_rejection_all_types() {
        // Each type requires exactly N bytes; fewer bytes must fail
        assert!(u16::decode(&[0]).is_err());
        assert!(u32::decode(&[0, 0]).is_err());
        assert!(u64::decode(&[0; 7]).is_err());
        assert!(Hash256::decode(&[0; 31]).is_err());
        assert!(Address::decode(&[0; 31]).is_err());
        assert!(ValidatorId::decode(&[0; 31]).is_err());
    }

    // -- Resources non-zero roundtrip --

    #[test]
    fn resources_nonzero_roundtrip() {
        let r = Resources {
            compute: 18_446_744_073_709_551_615,
            memory: 123_456_789,
            io: 987_654_321,
            bandwidth: 42,
        };
        let encoded = r.to_bytes();
        assert_eq!(encoded.len(), 32);
        let decoded = Resources::decode(&encoded).unwrap();
        assert_eq!(r, decoded);
    }

    // -- Mixed type sequence encoding --

    #[test]
    fn mixed_sequence_encoding() {
        let mut output = Vec::new();
        42u32.encode(&mut output);
        Address([0x42; 32]).encode(&mut output);
        true.encode(&mut output);
        255u8.encode(&mut output);

        let mut decoder = Decoder::new(&output);
        assert_eq!(decoder.read_u32().unwrap(), 42);
        let addr_bytes = decoder.read_fixed::<32>().unwrap();
        assert_eq!(addr_bytes, [0x42; 32]);
        let b = decoder.read_u8().unwrap();
        assert_eq!(b, 1); // true = 1
        let last = decoder.read_u8().unwrap();
        assert_eq!(last, 255);
        assert!(decoder.finish().is_ok());
    }
}
