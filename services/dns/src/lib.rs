// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune DNS` resolves authenticated in-network names.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use core::fmt;
use std::collections::BTreeMap;

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

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => write!(f, "invalid name"),
            Self::InvalidRegistryProof => write!(f, "invalid registry proof"),
        }
    }
}

impl std::error::Error for DnsError {}

/// Normalize a DNS name for registry lookup.
///
/// * Trims leading/trailing whitespace.
/// * Converts to lowercase ASCII (rejects non-ASCII bytes).
/// * Rejects empty names, names containing dots, and names longer than 64 bytes.
pub fn normalize_name(name: &str) -> Result<String, DnsError> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(DnsError::InvalidName);
    }

    if trimmed.len() > 64 {
        return Err(DnsError::InvalidName);
    }

    for byte in trimmed.as_bytes() {
        if !byte.is_ascii() {
            return Err(DnsError::InvalidName);
        }
    }

    let lowered = trimmed.to_ascii_lowercase();

    if lowered.contains('.') {
        return Err(DnsError::InvalidName);
    }

    Ok(lowered)
}

/// An in-memory resolver backed by a deterministic `BTreeMap`.
#[derive(Clone, Debug, Default)]
pub struct InMemoryResolver {
    records: BTreeMap<String, Record>,
}

impl InMemoryResolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the record for `name`.
    pub fn register(&mut self, name: &str, record: Record) -> Result<(), DnsError> {
        let normalized = normalize_name(name)?;
        self.records.insert(normalized, record);
        Ok(())
    }

    /// Remove the record for `name` if present.
    pub fn remove(&mut self, name: &str) -> Result<bool, DnsError> {
        let normalized = normalize_name(name)?;
        Ok(self.records.remove(&normalized).is_some())
    }

    /// Returns `true` if a record exists for the given name.
    pub fn has_name(&self, name: &str) -> Result<bool, DnsError> {
        let normalized = normalize_name(name)?;
        Ok(self.records.contains_key(&normalized))
    }

    /// Number of records currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` when no records are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Resolver for InMemoryResolver {
    fn resolve(&self, name: &str) -> Result<Option<Record>, DnsError> {
        let normalized = normalize_name(name)?;
        Ok(self.records.get(&normalized).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_valid_name() {
        assert_eq!(normalize_name("  Alice  ").unwrap(), "alice");
        assert_eq!(normalize_name("BOB").unwrap(), "bob");
        assert_eq!(normalize_name("charlie").unwrap(), "charlie");
    }

    #[test]
    fn normalize_empty_name() {
        assert_eq!(normalize_name(""), Err(DnsError::InvalidName));
        assert_eq!(normalize_name("   "), Err(DnsError::InvalidName));
    }

    #[test]
    fn normalize_too_long() {
        let long = "a".repeat(65);
        assert_eq!(normalize_name(&long), Err(DnsError::InvalidName));
    }

    #[test]
    fn normalize_max_length() {
        let exact = "a".repeat(64);
        assert_eq!(normalize_name(&exact).unwrap(), exact);
    }

    #[test]
    fn normalize_non_ascii() {
        assert_eq!(normalize_name("café"), Err(DnsError::InvalidName));
        assert_eq!(normalize_name("日本語"), Err(DnsError::InvalidName));
    }

    #[test]
    fn normalize_rejects_dots() {
        assert_eq!(normalize_name("a.b"), Err(DnsError::InvalidName));
        assert_eq!(normalize_name("sub.example"), Err(DnsError::InvalidName));
    }

    #[test]
    fn display_and_error_trait() {
        let err = DnsError::InvalidName;
        assert_eq!(format!("{err}"), "invalid name");
        let err: Box<dyn std::error::Error> = Box::new(DnsError::InvalidRegistryProof);
        assert_eq!(err.to_string(), "invalid registry proof");
    }

    #[test]
    fn register_and_resolve() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver.register("alice", Record::Address(addr)).unwrap();
        assert_eq!(resolver.len(), 1);

        let result = resolver.resolve("alice").unwrap().unwrap();
        assert_eq!(result, Record::Address(addr));
    }

    #[test]
    fn resolve_missing_returns_none() {
        let resolver = InMemoryResolver::new();
        assert!(resolver.resolve("nobody").unwrap().is_none());
    }

    #[test]
    fn resolve_case_insensitive() {
        let mut resolver = InMemoryResolver::new();
        let addr = Address::default();
        resolver.register("Alice", Record::Address(addr)).unwrap();

        assert_eq!(
            resolver.resolve("alice").unwrap(),
            Some(Record::Address(addr))
        );
        assert_eq!(
            resolver.resolve("ALICE").unwrap(),
            Some(Record::Address(addr))
        );
    }

    #[test]
    fn remove_name() {
        let mut resolver = InMemoryResolver::new();
        resolver
            .register("alice", Record::Page(Hash256::default()))
            .unwrap();

        assert!(resolver.remove("alice").unwrap());
        assert!(!resolver.remove("alice").unwrap());
        assert!(resolver.is_empty());
    }

    #[test]
    fn has_name() {
        let mut resolver = InMemoryResolver::new();
        resolver
            .register("bob", Record::Service(vec![1, 2, 3]))
            .unwrap();

        assert!(resolver.has_name("bob").unwrap());
        assert!(!resolver.has_name("carol").unwrap());
    }

    #[test]
    fn multiple_records() {
        let mut resolver = InMemoryResolver::new();
        let a1 = Address::default();
        let h = Hash256::default();

        resolver.register("alice", Record::Address(a1)).unwrap();
        resolver.register("bob", Record::Page(h)).unwrap();
        resolver
            .register("carol", Record::Service(vec![42]))
            .unwrap();

        assert_eq!(resolver.len(), 3);

        assert_eq!(
            resolver.resolve("alice").unwrap(),
            Some(Record::Address(a1))
        );
        assert_eq!(resolver.resolve("bob").unwrap(), Some(Record::Page(h)));
        assert_eq!(
            resolver.resolve("carol").unwrap(),
            Some(Record::Service(vec![42]))
        );

        // BTreeMap gives deterministic iteration order
        let names: Vec<&String> = resolver.records.keys().collect();
        assert_eq!(names, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn register_overwrites_existing() {
        let mut resolver = InMemoryResolver::new();
        let a1 = Address::default();
        let a2 = Address::default();

        resolver.register("alice", Record::Address(a1)).unwrap();
        resolver.register("alice", Record::Address(a2)).unwrap();

        assert_eq!(resolver.len(), 1);
        assert_eq!(
            resolver.resolve("alice").unwrap(),
            Some(Record::Address(a2))
        );
    }
}
