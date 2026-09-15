// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune DNS` resolves authenticated in-network names.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use types::{Address, Hash256};

/// A supported `AstroLune` name record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Record {
    /// Wallet or contract destination.
    Address(Address),
    /// Static `AstroLune` Pages manifest.
    Page(Hash256),
    /// Service endpoint interpreted by the access proxy.
    Service(Vec<u8>),
}

/// Resolves normalized names from finalized registry state.
pub trait Resolver {
    /// Returns the active record and never falls back to public `DNS` implicitly.
    fn resolve(&self, name: &str) -> Result<Option<Record>, DnsError>;
}

/// Name resolution failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsError {
    /// Name encoding or normalization is invalid.
    InvalidName,
    /// Registry state could not be verified.
    InvalidRegistryProof,
}
