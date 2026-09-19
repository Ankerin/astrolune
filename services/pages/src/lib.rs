// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Static content manifests served inside the `AstroLune` network.
//!
//! Pages does not provide a general storage or file-sharing network. A page
//! manifest references immutable release assets supplied by an operator or
//! external content origin and authenticated by hash.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use types::{Address, Hash256};

/// Maximum size in bytes for a single asset.
pub const MAX_ASSET_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of assets allowed in a single manifest.
pub const MAX_MANIFEST_ASSETS: usize = 1000;

/// Default Content-Security-Policy header value.
pub const CSP_HEADER: &str = "default-src 'self'; script-src 'self'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
    font-src 'self'; connect-src 'self'; frame-ancestors 'none'";

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

impl PageManifest {
    /// Validates manifest invariants.
    ///
    /// The entrypoint must be non-empty and the revision must be non-zero.
    ///
    /// # Errors
    ///
    /// Returns [`PageError::InvalidManifest`] if any invariant is violated.
    #[must_use = "call .is_ok() or handle the error"]
    pub fn validate(&self) -> Result<(), PageError> {
        if self.entrypoint.is_empty() {
            return Err(PageError::InvalidManifest);
        }
        if self.revision == 0 {
            return Err(PageError::InvalidManifest);
        }
        Ok(())
    }
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
    /// Asset exceeds the maximum allowed size.
    PayloadTooLarge,
    /// Manifest violates structural invariants.
    InvalidManifest,
    /// Too many assets have been registered.
    TooManyAssets,
}

impl fmt::Display for PageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => write!(f, "invalid path"),
            Self::NotFound => write!(f, "asset not found"),
            Self::IntegrityFailure => write!(f, "integrity failure"),
            Self::PayloadTooLarge => write!(f, "payload too large"),
            Self::InvalidManifest => write!(f, "invalid manifest"),
            Self::TooManyAssets => write!(f, "too many assets"),
        }
    }
}

impl std::error::Error for PageError {}

/// Returns the MIME type for a file extension.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(pages::mime_type("index.html"), "text/html");
/// assert_eq!(pages::mime_type("style.css"), "text/css");
/// assert_eq!(pages::mime_type("unknown"), "application/octet-stream");
/// ```
#[must_use]
pub fn mime_type(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "txt" => "text/plain",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

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

/// Origin-based access policy.
///
/// Controls which HTTP `Origin` headers are permitted to access protected
/// resources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginPolicy {
    /// Allowed origins. An empty set blocks all cross-origin requests.
    pub allowed_origins: BTreeSet<String>,
}

impl OriginPolicy {
    /// Creates a new policy with the given allowed origins.
    #[must_use]
    pub fn new(allowed_origins: BTreeSet<String>) -> Self {
        Self { allowed_origins }
    }

    /// Returns `true` if the origin is in the allowed set.
    #[must_use]
    pub fn is_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.contains(origin)
    }
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

    /// Returns the total number of registered assets.
    #[must_use]
    pub fn asset_count(&self) -> usize {
        self.entries.len()
    }

    /// Registers content at the given path for an owner.
    ///
    /// The path is normalized and the owner's content root is recomputed.
    /// Content exceeding [`MAX_ASSET_SIZE`] or adding more than
    /// [`MAX_MANIFEST_ASSETS`] total assets is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`PageError::InvalidPath`] if the path is not normalizable,
    /// [`PageError::PayloadTooLarge`] if the content exceeds the size limit,
    /// or [`PageError::TooManyAssets`] if the asset limit is reached.
    pub fn register(
        &mut self,
        owner: Address,
        path: &str,
        content: Vec<u8>,
    ) -> Result<(), PageError> {
        let normalized = normalize_path(path)?;
        if content.len() > MAX_ASSET_SIZE {
            return Err(PageError::PayloadTooLarge);
        }
        if self.entries.len() >= MAX_MANIFEST_ASSETS
            && !self.entries.contains_key(&(owner, normalized.clone()))
        {
            return Err(PageError::TooManyAssets);
        }
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
        assert_eq!(
            format!("{}", PageError::PayloadTooLarge),
            "payload too large"
        );
        assert_eq!(
            format!("{}", PageError::InvalidManifest),
            "invalid manifest"
        );
        assert_eq!(format!("{}", PageError::TooManyAssets), "too many assets");
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

    // -- mime_type tests --

    #[test]
    fn mime_type_html() {
        assert_eq!(mime_type("index.html"), "text/html");
        assert_eq!(mime_type("page.htm"), "text/html");
    }

    #[test]
    fn mime_type_css() {
        assert_eq!(mime_type("style.css"), "text/css");
    }

    #[test]
    fn mime_type_javascript() {
        assert_eq!(mime_type("app.js"), "application/javascript");
        assert_eq!(mime_type("module.mjs"), "application/javascript");
    }

    #[test]
    fn mime_type_json() {
        assert_eq!(mime_type("data.json"), "application/json");
    }

    #[test]
    fn mime_type_images() {
        assert_eq!(mime_type("logo.png"), "image/png");
        assert_eq!(mime_type("photo.jpg"), "image/jpeg");
        assert_eq!(mime_type("photo.jpeg"), "image/jpeg");
        assert_eq!(mime_type("animation.gif"), "image/gif");
        assert_eq!(mime_type("icon.svg"), "image/svg+xml");
        assert_eq!(mime_type("favicon.ico"), "image/x-icon");
    }

    #[test]
    fn mime_type_text() {
        assert_eq!(mime_type("readme.txt"), "text/plain");
    }

    #[test]
    fn mime_type_wasm() {
        assert_eq!(mime_type("module.wasm"), "application/wasm");
    }

    #[test]
    fn mime_type_fonts() {
        assert_eq!(mime_type("font.woff"), "font/woff");
        assert_eq!(mime_type("font.woff2"), "font/woff2");
        assert_eq!(mime_type("font.ttf"), "font/ttf");
    }

    #[test]
    fn mime_type_xml() {
        assert_eq!(mime_type("feed.xml"), "application/xml");
    }

    #[test]
    fn mime_type_pdf() {
        assert_eq!(mime_type("document.pdf"), "application/pdf");
    }

    #[test]
    fn mime_type_unknown_extension() {
        assert_eq!(mime_type("file.xyz"), "application/octet-stream");
        assert_eq!(mime_type("noextension"), "application/octet-stream");
    }

    // -- CSP_HEADER test --

    #[test]
    fn csp_header_value() {
        assert!(CSP_HEADER.contains("default-src 'self'"));
        assert!(CSP_HEADER.contains("script-src 'self'"));
        assert!(CSP_HEADER.contains("frame-ancestors 'none'"));
    }

    // -- constants tests --

    #[test]
    fn max_asset_size_is_ten_megabytes() {
        assert_eq!(MAX_ASSET_SIZE, 10 * 1024 * 1024);
    }

    #[test]
    fn max_manifest_assets_is_one_thousand() {
        assert_eq!(MAX_MANIFEST_ASSETS, 1000);
    }

    // -- PageManifest::validate tests --

    #[test]
    fn validate_valid_manifest() {
        let manifest = PageManifest {
            owner: owner(),
            content_root: Hash256::ZERO,
            entrypoint: "index.html".into(),
            revision: 1,
        };
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_entrypoint() {
        let manifest = PageManifest {
            owner: owner(),
            content_root: Hash256::ZERO,
            entrypoint: String::new(),
            revision: 1,
        };
        assert_eq!(manifest.validate(), Err(PageError::InvalidManifest));
    }

    #[test]
    fn validate_rejects_zero_revision() {
        let manifest = PageManifest {
            owner: owner(),
            content_root: Hash256::ZERO,
            entrypoint: "index.html".into(),
            revision: 0,
        };
        assert_eq!(manifest.validate(), Err(PageError::InvalidManifest));
    }

    #[test]
    fn validate_rejects_empty_entrypoint_and_zero_revision() {
        let manifest = PageManifest {
            owner: owner(),
            content_root: Hash256::ZERO,
            entrypoint: String::new(),
            revision: 0,
        };
        assert_eq!(manifest.validate(), Err(PageError::InvalidManifest));
    }

    // -- OriginPolicy tests --

    #[test]
    fn origin_policy_allows_listed() {
        let mut origins = BTreeSet::new();
        origins.insert("https://example.com".into());
        origins.insert("https://app.example.com".into());
        let policy = OriginPolicy::new(origins);

        assert!(policy.is_allowed("https://example.com"));
        assert!(policy.is_allowed("https://app.example.com"));
        assert!(!policy.is_allowed("https://evil.com"));
    }

    #[test]
    fn origin_policy_empty_blocks_all() {
        let policy = OriginPolicy::new(BTreeSet::new());
        assert!(!policy.is_allowed("https://example.com"));
        assert!(!policy.is_allowed(""));
    }

    #[test]
    fn origin_policy_exact_match() {
        let mut origins = BTreeSet::new();
        origins.insert("https://example.com".into());
        let policy = OriginPolicy::new(origins);

        assert!(policy.is_allowed("https://example.com"));
        assert!(!policy.is_allowed("https://Example.com"));
        assert!(!policy.is_allowed("https://example.com/"));
    }

    // -- register PayloadTooLarge tests --

    #[test]
    fn register_rejects_oversized_content() {
        let mut source = InMemoryPageSource::new();
        let o = owner();
        let oversized = vec![0u8; MAX_ASSET_SIZE + 1];

        assert_eq!(
            source.register(o, "big.bin", oversized),
            Err(PageError::PayloadTooLarge)
        );
    }

    #[test]
    fn register_accepts_content_at_limit() {
        let mut source = InMemoryPageSource::new();
        let o = owner();
        let at_limit = vec![0u8; MAX_ASSET_SIZE];

        assert!(source.register(o, "exact.bin", at_limit).is_ok());
    }

    #[test]
    fn register_rejects_invalid_path_before_size_check() {
        let mut source = InMemoryPageSource::new();
        let o = owner();
        let oversized = vec![0u8; MAX_ASSET_SIZE + 1];

        assert_eq!(
            source.register(o, "/bad", oversized),
            Err(PageError::InvalidPath)
        );
    }

    // -- register TooManyAssets tests --

    #[test]
    fn register_rejects_when_too_many_assets() {
        let mut source = InMemoryPageSource::new();
        let o = owner();

        for i in 0..MAX_MANIFEST_ASSETS {
            let path = format!("file_{i}.txt");
            source.register(o, &path, b"x".to_vec()).unwrap();
        }

        assert_eq!(
            source.register(o, "one_more.txt", b"y".to_vec()),
            Err(PageError::TooManyAssets)
        );
    }

    #[test]
    fn register_allows_reregister_at_limit() {
        let mut source = InMemoryPageSource::new();
        let o = owner();

        for i in 0..MAX_MANIFEST_ASSETS {
            let path = format!("file_{i}.txt");
            source.register(o, &path, b"x".to_vec()).unwrap();
        }

        assert!(
            source
                .register(o, "file_0.txt", b"updated".to_vec())
                .is_ok()
        );
    }

    #[test]
    fn register_allows_other_owner_at_limit() {
        let mut source = InMemoryPageSource::new();
        let a = owner();
        let b = other_owner();

        for i in 0..MAX_MANIFEST_ASSETS {
            let path = format!("file_{i}.txt");
            source.register(a, &path, b"x".to_vec()).unwrap();
        }

        assert!(source.register(b, "file_0.txt", b"other".to_vec()).is_ok());
    }

    // -- asset_count tests --

    #[test]
    fn asset_count_starts_at_zero() {
        let source = InMemoryPageSource::new();
        assert_eq!(source.asset_count(), 0);
    }

    #[test]
    fn asset_count_increases() {
        let mut source = InMemoryPageSource::new();
        let o = owner();

        source.register(o, "a.txt", b"a".to_vec()).unwrap();
        assert_eq!(source.asset_count(), 1);

        source.register(o, "b.txt", b"b".to_vec()).unwrap();
        assert_eq!(source.asset_count(), 2);
    }

    #[test]
    fn asset_count_unchanged_on_reregister() {
        let mut source = InMemoryPageSource::new();
        let o = owner();

        source.register(o, "a.txt", b"first".to_vec()).unwrap();
        assert_eq!(source.asset_count(), 1);

        source.register(o, "a.txt", b"second".to_vec()).unwrap();
        assert_eq!(source.asset_count(), 1);
    }
}
