// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! State access leasing for deterministic scheduling.

use types::StateKey;

/// Access mode requested by a transaction lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessMode {
    /// Concurrent immutable access.
    Read,
    /// Exclusive mutable access.
    Write,
}

/// One declared state access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    /// Canonical state key.
    pub key: StateKey,
    /// Required access mode.
    pub mode: AccessMode,
}

/// A deterministic lease over state keys for one execution wave.
///
/// Keys are canonically sorted and deduplicated before scheduling. A lease
/// that omits an accessed key or uses the wrong mode triggers deterministic
/// failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateLease {
    /// Canonically sorted and deduplicated requests.
    pub requests: Vec<AccessRequest>,
}

impl StateLease {
    /// Returns `true` if the lease contains the given key in the required mode.
    #[must_use]
    pub fn covers(&self, key: &StateKey, mode: AccessMode) -> bool {
        self.requests
            .iter()
            .any(|req| req.key == *key && req.mode == mode)
    }

    /// Returns `true` if the lease has any write access.
    #[must_use]
    pub fn has_writes(&self) -> bool {
        self.requests
            .iter()
            .any(|req| req.mode == AccessMode::Write)
    }

    /// Returns the set of keys with write access.
    #[must_use]
    pub fn write_keys(&self) -> Vec<&StateKey> {
        self.requests
            .iter()
            .filter(|req| req.mode == AccessMode::Write)
            .map(|req| &req.key)
            .collect()
    }
}
