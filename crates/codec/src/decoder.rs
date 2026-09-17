// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Bounded cursor for canonical decoding without allocation.

use crate::error::DecodeError;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncation() {
        let mut decoder = Decoder::new(&[1]);
        assert_eq!(decoder.read_u16(), Err(DecodeError::Truncated));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let decoder = Decoder::new(&[1, 2, 3]);
        assert_eq!(decoder.finish(), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn empty_succeeds() {
        let decoder = Decoder::new(&[]);
        assert_eq!(decoder.remaining(), 0);
        assert!(decoder.finish().is_ok());
    }

    #[test]
    fn tracks_position() {
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
}
