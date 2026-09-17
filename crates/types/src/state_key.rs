// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Bounded-length state keys for deterministic state access.

/// A state key. Canonical encoding must impose a bounded length before use.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateKey(pub Vec<u8>);

impl StateKey {
    /// Maximum allowed key length in bytes.
    pub const MAX_LEN: usize = 256;

    /// Creates a new state key from bytes.
    ///
    /// Returns `None` if the key exceeds [`Self::MAX_LEN`].
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() > Self::MAX_LEN {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// Returns the key bytes as a slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the key is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_len_enforced() {
        let ok = StateKey::new(vec![0u8; 256]);
        assert!(ok.is_some());

        let too_long = StateKey::new(vec![0u8; 257]);
        assert!(too_long.is_none());
    }

    #[test]
    fn empty() {
        let key = StateKey(Vec::new());
        assert!(key.is_empty());
        assert_eq!(key.len(), 0);
    }
}
