// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Access proxy boundary for `AstroLune DNS`, Pages, and application services.
//!
//! The baseline is an authenticated gateway, not an anonymity claim. Onion
//! routing, traffic-analysis resistance, and exit relaying require a separate
//! threat model and security review before they may be advertised.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;
use std::fmt;

/// Maximum allowed service name length in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// Maximum allowed request payload length in bytes.
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024;

/// Maximum allowed response length in bytes.
pub const MAX_RESPONSE_LEN: usize = 1024 * 1024;

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

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "service not found"),
            Self::Unsupported => write!(f, "unsupported protocol"),
            Self::LimitExceeded => write!(f, "request or response exceeded limit"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// A handler for a single named service.
pub trait ServiceHandler {
    /// Processes a request payload and returns the response bytes.
    fn handle(&self, name: &str, payload: &[u8]) -> Result<Vec<u8>, ProxyError>;
}

/// An in-memory proxy gateway that routes requests to registered service handlers.
///
/// Services are stored in a `BTreeMap` for deterministic iteration order.
pub struct InMemoryProxyGateway {
    handlers: BTreeMap<String, Box<dyn ServiceHandler>>,
    max_peers: usize,
}

impl InMemoryProxyGateway {
    /// Creates a new gateway with the given peer limit.
    #[must_use]
    pub fn new(max_peers: usize) -> Self {
        Self {
            handlers: BTreeMap::new(),
            max_peers,
        }
    }

    /// Registers a service handler under the given name.
    ///
    /// Returns `Ok(())` on success, or `Err(ProxyError::LimitExceeded)` if
    /// the gateway has reached its peer limit.
    pub fn register_service(
        &mut self,
        name: impl Into<String>,
        handler: Box<dyn ServiceHandler>,
    ) -> Result<(), ProxyError> {
        if self.handlers.len() >= self.max_peers {
            return Err(ProxyError::LimitExceeded);
        }
        self.handlers.insert(name.into(), handler);
        Ok(())
    }
}

impl ProxyGateway for InMemoryProxyGateway {
    fn forward(&self, request: &ProxyRequest) -> Result<Vec<u8>, ProxyError> {
        if request.name.is_empty() || request.name.len() > MAX_NAME_LEN {
            return Err(ProxyError::LimitExceeded);
        }
        if request.payload.len() > MAX_PAYLOAD_LEN {
            return Err(ProxyError::LimitExceeded);
        }

        let handler = self
            .handlers
            .get(&request.name)
            .ok_or(ProxyError::NotFound)?;
        let response = handler.handle(&request.name, &request.payload)?;

        if response.len() > MAX_RESPONSE_LEN {
            return Err(ProxyError::LimitExceeded);
        }

        Ok(response)
    }
}

/// A trivial handler that echoes the payload back. Intended for testing.
pub struct EchoHandler;

impl ServiceHandler for EchoHandler {
    fn handle(&self, _name: &str, payload: &[u8]) -> Result<Vec<u8>, ProxyError> {
        Ok(payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_name_is_rejected() {
        let gw = InMemoryProxyGateway::new(8);
        let req = ProxyRequest {
            name: String::new(),
            payload: vec![1, 2, 3],
        };
        assert_eq!(gw.forward(&req), Err(ProxyError::LimitExceeded));
    }

    #[test]
    fn name_too_long_is_rejected() {
        let gw = InMemoryProxyGateway::new(8);
        let req = ProxyRequest {
            name: "a".repeat(MAX_NAME_LEN + 1),
            payload: vec![1],
        };
        assert_eq!(gw.forward(&req), Err(ProxyError::LimitExceeded));
    }

    #[test]
    fn payload_too_long_is_rejected() {
        let gw = InMemoryProxyGateway::new(8);
        let req = ProxyRequest {
            name: "svc".into(),
            payload: vec![0; MAX_PAYLOAD_LEN + 1],
        };
        assert_eq!(gw.forward(&req), Err(ProxyError::LimitExceeded));
    }

    #[test]
    fn missing_service_returns_not_found() {
        let gw = InMemoryProxyGateway::new(8);
        let req = ProxyRequest {
            name: "unknown".into(),
            payload: vec![],
        };
        assert_eq!(gw.forward(&req), Err(ProxyError::NotFound));
    }

    #[test]
    fn echo_handler_roundtrip() {
        let mut gw = InMemoryProxyGateway::new(8);
        gw.register_service("echo", Box::new(EchoHandler)).unwrap();

        let payload = b"hello, astrolune";
        let req = ProxyRequest {
            name: "echo".into(),
            payload: payload.to_vec(),
        };
        assert_eq!(gw.forward(&req), Ok(payload.to_vec()));
    }

    #[test]
    fn multiple_services() {
        let mut gw = InMemoryProxyGateway::new(8);
        gw.register_service("echo", Box::new(EchoHandler)).unwrap();
        gw.register_service("echo2", Box::new(EchoHandler)).unwrap();

        let req = ProxyRequest {
            name: "echo".into(),
            payload: vec![42],
        };
        assert_eq!(gw.forward(&req), Ok(vec![42]));

        let req2 = ProxyRequest {
            name: "echo2".into(),
            payload: vec![99],
        };
        assert_eq!(gw.forward(&req2), Ok(vec![99]));
    }

    #[test]
    fn peer_limit_enforced() {
        let mut gw = InMemoryProxyGateway::new(1);
        gw.register_service("a", Box::new(EchoHandler)).unwrap();
        assert_eq!(
            gw.register_service("b", Box::new(EchoHandler)),
            Err(ProxyError::LimitExceeded)
        );
    }

    #[test]
    fn display_and_error_impls() {
        fn assert_error<E: std::error::Error>(_e: &E) {}
        let cases = [
            (ProxyError::NotFound, "service not found"),
            (ProxyError::Unsupported, "unsupported protocol"),
            (
                ProxyError::LimitExceeded,
                "request or response exceeded limit",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(format!("{err}"), expected);
            assert_error(&err);
        }
    }
}
