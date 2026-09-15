// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Access proxy boundary for `AstroLune DNS`, Pages, and application services.
//!
//! The baseline is an authenticated gateway, not an anonymity claim. Onion
//! routing, traffic-analysis resistance, and exit relaying require a separate
//! threat model and security review before they may be advertised.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

/// Destination selected after `AstroLune` DNS resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyRequest {
    /// Normalized `AstroLune` name.
    pub name: String,
    /// Application protocol bytes.
    pub payload: Vec<u8>,
}

/// Routes bounded requests to internal `AstroLune` services.
pub trait ProxyGateway {
    /// Returns a bounded service response.
    fn forward(&self, request: &ProxyRequest) -> Result<Vec<u8>, ProxyError>;
}

/// Proxy request failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyError {
    /// No active name record exists.
    NotFound,
    /// Destination protocol is unsupported.
    Unsupported,
    /// Request or response exceeded a configured bound.
    LimitExceeded,
}
