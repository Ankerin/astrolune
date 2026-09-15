// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Static content manifests served inside the `AstroLune` network.
//!
//! Pages does not provide a general storage or file-sharing network. A page
//! manifest references immutable release assets supplied by an operator or
//! external content origin and authenticated by hash.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

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
