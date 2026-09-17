// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Static content manifests served inside the `AstroLune` network.
//!
//! Pages does not provide a general storage or file-sharing network. A page
//! manifest references immutable release assets supplied by an operator or
//! external content origin and authenticated by hash.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;
use std::fmt;
use types::{Address, Hash256};

/// Immutable published website release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageManifest {
    /// Wallet that authorized the release.
    pub owner: Address,
    /// Root hash of normalized static assets.
    pub content_root: Hash256,
    /// Relative entry document, normally `index.html`.
    pub entrypoint: String,
    /// Monotonic owner-controlled release number.
    pub revision: u64,
}

/// Retrieves and verifies assets for an authenticated manifest.
pub trait PageSource {
    /// Loads one normalized relative path and verifies it against `content_root`.
    fn load(&self, manifest: &PageManifest, path: &str) -> Result<Vec<u8>, PageError>;
}

/// Static page retrieval failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageError {
    /// Path is absolute, escapes the root, or is not normalized.
    InvalidPath,
    /// The requested asset does not exist.
    NotFound,
    /// Asset bytes do not match the manifest commitment.
    IntegrityFailure,
}

impl fmt::Display for PageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => write!(f, "invalid path"),
            Self::NotFound => write!(f, "asset not found"),
            Self::IntegrityFailure => write!(f, "integrity failure"),
        }
    }
}

impl std::error::Error for PageError {}

/// Validates and normalizes a relative path.
///
/// # Errors
///
/// Returns [`PageError::InvalidPath`] when the path is empty, absolute,
/// contains `..` components, backslashes, or is otherwise unsafe.
pub fn normalize_path(path: &str) -> Result<String, PageError> {
    if path.is_empty() {
        return Err(PageError::InvalidPath);
    }
    if path.starts_with('/') {
        return Err(PageError::InvalidPath);
    }
    if path.contains('\\') {
        return Err(PageError::InvalidPath);
    }
    if path.contains("..") {
        return Err(PageError::InvalidPath);
    }

    let normalized: String = path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/");

    if normalized.is_empty() {
        return Err(PageError::InvalidPath);
    }

    Ok(normalized)
}

/// Deterministically hashes content bytes into a [`Hash256`].
fn hash_content(content: &[u8]) -> Hash256 {
    let mut hash = [0u8; 32];
    for (i, byte) in content.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    let len_bytes = (content.len() as u64).to_le_bytes();
    for (i, byte) in len_bytes.iter().enumerate() {
        hash[i % 32] ^= byte;
    }
    Hash256(hash)
}

/// Recomputes the content root from a deterministic iteration of entries.
fn compute_content_root(entries: &BTreeMap<(Address, String), Vec<u8>>, owner: Address) -> Hash256 {
    let mut root = Hash256::ZERO;
    for ((addr, _path), content) in entries.range((owner, String::new())..) {
        if *addr != owner {
            break;
        }
        root = root.xor(hash_content(content));
    }
    root
}

/// An in-memory [`PageSource`] implementation keyed by `(owner, path)`.
///
/// Content roots are recomputed via XOR of per-file content hashes on each
/// registration, enabling deterministic integrity verification.
pub struct InMemoryPageSource {
    /// Stored page content keyed by `(owner, normalized_path)`.
    entries: BTreeMap<(Address, String), Vec<u8>>,
    /// Cached content roots per owner.
    roots: BTreeMap<Address, Hash256>,
}

impl InMemoryPageSource {
    /// Creates an empty page source.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            roots: BTreeMap::new(),
        }
    }

    /// Registers content at the given path for an owner.
    ///
    /// The path is normalized and the owner's content root is recomputed.
    ///
    /// # Errors
    ///
    /// Returns [`PageError::InvalidPath`] if the path is not normalizable.
    pub fn register(
        &mut self,
        owner: Address,
        path: &str,
        content: Vec<u8>,
    ) -> Result<(), PageError> {
        let normalized = normalize_path(path)?;
        self.entries.insert((owner, normalized), content);
        let root = compute_content_root(&self.entries, owner);
        self.roots.insert(owner, root);
        Ok(())
    }

    /// Returns the current content root for an owner, if any content is
    /// registered.
    #[must_use]
    pub fn content_root(&self, owner: Address) -> Option<Hash256> {
        self.roots.get(&owner).copied()
    }
}

impl Default for InMemoryPageSource {
    fn default() -> Self {
        Self::new()
    }
}

impl PageSource for InMemoryPageSource {
    fn load(&self, manifest: &PageManifest, path: &str) -> Result<Vec<u8>, PageError> {
        let normalized = normalize_path(path)?;

        let stored_root = self.roots.get(&manifest.owner).ok_or(PageError::NotFound)?;

        if *stored_root != manifest.content_root {
            return Err(PageError::IntegrityFailure);
        }

        self.entries
            .get(&(manifest.owner, normalized))
            .cloned()
            .ok_or(PageError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Address {
        Address::from_bytes([0xAA; 32])
    }

    fn other_owner() -> Address {
        Address::from_bytes([0xBB; 32])
    }

    // -- normalize_path tests --

    #[test]
    fn normalize_valid_path() {
        assert_eq!(normalize_path("index.html").unwrap(), "index.html");
    }

    #[test]
    fn normalize_nested_path() {
        assert_eq!(
            normalize_path("assets/img/logo.png").unwrap(),
            "assets/img/logo.png"
        );
    }

    #[test]
    fn normalize_rejects_absolute() {
        assert_eq!(normalize_path("/etc/passwd"), Err(PageError::InvalidPath));
    }

    #[test]
    fn normalize_rejects_dots() {
        assert_eq!(normalize_path("../secret"), Err(PageError::InvalidPath));
    }

    #[test]
    fn normalize_rejects_backslash() {
        assert_eq!(normalize_path("foo\\bar"), Err(PageError::InvalidPath));
    }

    #[test]
    fn normalize_rejects_empty() {
        assert_eq!(normalize_path(""), Err(PageError::InvalidPath));
    }

    #[test]
    fn normalize_collapses_slashes() {
        assert_eq!(normalize_path("a///b////c").unwrap(), "a/b/c");
    }

    #[test]
    fn normalize_rejects_dots_in_middle() {
        assert_eq!(normalize_path("a/../b"), Err(PageError::InvalidPath));
    }

    #[test]
    fn normalize_rejects_trailing_dots() {
        assert_eq!(normalize_path("a/b/.."), Err(PageError::InvalidPath));
    }

    // -- PageError Display and Error --

    #[test]
    fn page_error_display() {
        assert_eq!(format!("{}", PageError::InvalidPath), "invalid path");
        assert_eq!(format!("{}", PageError::NotFound), "asset not found");
        assert_eq!(
            format!("{}", PageError::IntegrityFailure),
            "integrity failure"
        );
    }

    #[test]
    fn page_error_is_std_error() {
        let err: &dyn std::error::Error = &PageError::NotFound;
        assert_eq!(err.to_string(), "asset not found");
    }

    // -- register and load --

    #[test]
    fn register_and_load_roundtrip() {
        let mut source = InMemoryPageSource::new();
        let o = owner();
        let content = b"hello world".to_vec();

        source.register(o, "index.html", content.clone()).unwrap();

        let root = source.content_root(o).unwrap();
        let manifest = PageManifest {
            owner: o,
            content_root: root,
            entrypoint: "index.html".into(),
            revision: 1,
        };

        let loaded = source.load(&manifest, "index.html").unwrap();
        assert_eq!(loaded, content);
    }

    #[test]
    fn load_not_found() {
        let mut source = InMemoryPageSource::new();
        let o = owner();

        source.register(o, "index.html", b"hi".to_vec()).unwrap();

        let root = source.content_root(o).unwrap();
        let manifest = PageManifest {
            owner: o,
            content_root: root,
            entrypoint: "index.html".into(),
            revision: 1,
        };

        assert_eq!(
            source.load(&manifest, "missing.html"),
            Err(PageError::NotFound)
        );
    }

    #[test]
    fn load_integrity_failure() {
        let mut source = InMemoryPageSource::new();
        let o = owner();

        source
            .register(o, "index.html", b"content".to_vec())
            .unwrap();

        let fake_root = Hash256([0xFF; 32]);
        let manifest = PageManifest {
            owner: o,
            content_root: fake_root,
            entrypoint: "index.html".into(),
            revision: 1,
        };

        assert_eq!(
            source.load(&manifest, "index.html"),
            Err(PageError::IntegrityFailure)
        );
    }

    #[test]
    fn load_entrypoint() {
        let mut source = InMemoryPageSource::new();
        let o = owner();
        let page = b"<!DOCTYPE html><html></html>".to_vec();

        source.register(o, "index.html", page.clone()).unwrap();

        let root = source.content_root(o).unwrap();
        let manifest = PageManifest {
            owner: o,
            content_root: root,
            entrypoint: "index.html".into(),
            revision: 1,
        };

        let loaded = source.load(&manifest, &manifest.entrypoint).unwrap();
        assert_eq!(loaded, page);
    }

    #[test]
    fn multiple_owners_isolated() {
        let mut source = InMemoryPageSource::new();
        let a = owner();
        let b = other_owner();

        source
            .register(a, "page.html", b"owner_a".to_vec())
            .unwrap();
        source
            .register(b, "page.html", b"owner_b".to_vec())
            .unwrap();

        let root_a = source.content_root(a).unwrap();
        let root_b = source.content_root(b).unwrap();

        assert_ne!(root_a, root_b);

        let manifest_a = PageManifest {
            owner: a,
            content_root: root_a,
            entrypoint: "page.html".into(),
            revision: 1,
        };
        let manifest_b = PageManifest {
            owner: b,
            content_root: root_b,
            entrypoint: "page.html".into(),
            revision: 1,
        };

        assert_eq!(source.load(&manifest_a, "page.html").unwrap(), b"owner_a");
        assert_eq!(source.load(&manifest_b, "page.html").unwrap(), b"owner_b");
    }

    #[test]
    fn register_rejects_invalid_path() {
        let mut source = InMemoryPageSource::new();
        let o = owner();

        assert_eq!(
            source.register(o, "/etc/passwd", vec![]),
            Err(PageError::InvalidPath)
        );
        assert_eq!(
            source.register(o, "../escape", vec![]),
            Err(PageError::InvalidPath)
        );
        assert_eq!(
            source.register(o, "foo\\bar", vec![]),
            Err(PageError::InvalidPath)
        );
        assert_eq!(source.register(o, "", vec![]), Err(PageError::InvalidPath));
    }

    #[test]
    fn content_root_none_for_unknown_owner() {
        let source = InMemoryPageSource::new();
        assert!(source.content_root(owner()).is_none());
    }

    #[test]
    fn content_root_updates_on_reregister() {
        let mut source = InMemoryPageSource::new();
        let o = owner();

        source.register(o, "a.txt", b"first".to_vec()).unwrap();
        let root1 = source.content_root(o).unwrap();

        source.register(o, "a.txt", b"second".to_vec()).unwrap();
        let root2 = source.content_root(o).unwrap();

        assert_ne!(root1, root2);
    }

    #[test]
    fn load_rejects_invalid_path() {
        let source = InMemoryPageSource::new();
        let manifest = PageManifest {
            owner: owner(),
            content_root: Hash256::ZERO,
            entrypoint: "index.html".into(),
            revision: 1,
        };

        assert_eq!(source.load(&manifest, "/bad"), Err(PageError::InvalidPath));
    }

    #[test]
    fn multiple_files_root_ordering() {
        let mut source = InMemoryPageSource::new();
        let o = owner();

        source.register(o, "a.txt", b"aaa".to_vec()).unwrap();
        let root_a = source.content_root(o).unwrap();

        source.register(o, "b.txt", b"bbb".to_vec()).unwrap();
        let root_ab = source.content_root(o).unwrap();

        assert_ne!(root_a, root_ab);
    }
}
