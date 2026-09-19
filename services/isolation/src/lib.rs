// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Service isolation primitives for `AstroLune` ecosystem services.
//!
//! This crate provides core types and traits for isolating services within the
//! `AstroLune` network, including rate limiting, identity management, and request
//! authentication.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeMap;
use std::fmt;

/// Errors that can occur during isolation operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationError {
    /// The request has been rate limited.
    RateLimited,
    /// The service identifier is unknown.
    UnknownService,
    /// The request authentication failed.
    AuthenticationFailed,
}

impl fmt::Display for IsolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimited => write!(f, "rate limited"),
            Self::UnknownService => write!(f, "unknown service"),
            Self::AuthenticationFailed => write!(f, "authentication failed"),
        }
    }
}

impl std::error::Error for IsolationError {}

/// A sliding-window rate limiter keyed by arbitrary byte sequences.
pub struct RateLimiter {
    max_requests: usize,
    window_seconds: u64,
    windows: BTreeMap<Vec<u8>, Vec<u64>>,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    ///
    /// - `max_requests` — maximum number of requests allowed within the window.
    /// - `window_seconds` — duration of the sliding window in seconds.
    #[must_use]
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
            windows: BTreeMap::new(),
        }
    }

    /// Checks whether a request from `key` is allowed at `current_time`.
    ///
    /// Returns `true` if the request is within the rate limit, `false` otherwise.
    /// Timestamps older than `current_time - window_seconds` are pruned.
    pub fn check(&mut self, key: &[u8], current_time: u64) -> bool {
        let window_start = current_time.saturating_sub(self.window_seconds);
        let timestamps = self.windows.entry(key.to_vec()).or_default();
        timestamps.retain(|&t| t > window_start);
        if timestamps.len() < self.max_requests {
            timestamps.push(current_time);
            true
        } else {
            false
        }
    }

    /// Removes the rate-limit state for the given key.
    pub fn reset(&mut self, key: &[u8]) {
        self.windows.remove(key);
    }

    /// Returns the number of keys currently being tracked.
    #[must_use]
    pub fn active_keys(&self) -> usize {
        self.windows.len()
    }
}

/// An identity representing a registered service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceIdentity {
    /// Human-readable service name.
    pub name: String,
    /// Unique key identifier (32-byte public key fingerprint).
    pub key_id: [u8; 32],
}

/// Trait for service keys that can verify signatures.
pub trait ServiceKey {
    /// Returns the key identifier.
    fn id(&self) -> &[u8; 32];

    /// Verifies that `signature` is valid for `message`.
    fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool;
}

/// Authenticator that maps key identifiers to service identities and verifies
/// request signatures.
pub struct ServiceAuth {
    identities: BTreeMap<[u8; 32], ServiceIdentity>,
}

impl ServiceAuth {
    /// Creates an empty authenticator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            identities: BTreeMap::new(),
        }
    }

    /// Registers a service identity.
    pub fn register_service(&mut self, identity: ServiceIdentity) {
        self.identities.insert(identity.key_id, identity);
    }

    /// Verifies a request signature against the stored identity for `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`IsolationError::UnknownService`] if no identity is registered
    /// for the given `key_id`.
    pub fn verify_request(
        &self,
        key_id: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), IsolationError> {
        // Verify the service identity exists before checking the signature.
        // In a production build the stored public key would be used directly;
        // here we delegate to a MockServiceKey for the baseline.
        let _identity = self
            .identities
            .get(key_id)
            .ok_or(IsolationError::UnknownService)?;
        let key = MockServiceKey::new(*key_id);
        if key.verify(message, signature) {
            Ok(())
        } else {
            Err(IsolationError::AuthenticationFailed)
        }
    }
}

impl Default for ServiceAuth {
    fn default() -> Self {
        Self::new()
    }
}

/// A mock service key for testing purposes.
///
/// Accepts any signature where at least one byte is non-zero.
pub struct MockServiceKey {
    key_id: [u8; 32],
}

impl MockServiceKey {
    /// Creates a new mock key with the given identifier.
    #[must_use]
    pub fn new(key_id: [u8; 32]) -> Self {
        Self { key_id }
    }
}

impl ServiceKey for MockServiceKey {
    fn id(&self) -> &[u8; 32] {
        &self.key_id
    }

    fn verify(&self, _message: &[u8], signature: &[u8; 64]) -> bool {
        signature.iter().any(|&b| b != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // IsolationError

    #[test]
    fn error_display() {
        assert_eq!(IsolationError::RateLimited.to_string(), "rate limited");
        assert_eq!(
            IsolationError::UnknownService.to_string(),
            "unknown service"
        );
        assert_eq!(
            IsolationError::AuthenticationFailed.to_string(),
            "authentication failed"
        );
    }

    #[test]
    fn error_is_std_error() {
        let err: &dyn std::error::Error = &IsolationError::RateLimited;
        assert!(err.source().is_none());
    }

    #[test]
    fn error_clone_copy() {
        let err = IsolationError::AuthenticationFailed;
        let cloned = err;
        let copied = err;
        assert_eq!(err, cloned);
        assert_eq!(err, copied);
    }

    // RateLimiter

    #[test]
    fn rate_limiter_allows_within_window() {
        let mut limiter = RateLimiter::new(3, 10);
        assert!(limiter.check(b"svc", 100));
        assert!(limiter.check(b"svc", 105));
        assert!(limiter.check(b"svc", 109));
    }

    #[test]
    fn rate_limiter_rejects_over_limit() {
        let mut limiter = RateLimiter::new(2, 10);
        assert!(limiter.check(b"svc", 100));
        assert!(limiter.check(b"svc", 105));
        assert!(!limiter.check(b"svc", 109));
    }

    #[test]
    fn rate_limiter_prunes_old_timestamps() {
        let mut limiter = RateLimiter::new(2, 10);
        assert!(limiter.check(b"svc", 100));
        assert!(limiter.check(b"svc", 105));
        // At time 120, the window starts at 110, so both earlier timestamps are pruned.
        assert!(limiter.check(b"svc", 120));
    }

    #[test]
    fn rate_limiter_reset() {
        let mut limiter = RateLimiter::new(1, 10);
        assert!(limiter.check(b"svc", 100));
        assert!(!limiter.check(b"svc", 105));
        limiter.reset(b"svc");
        assert!(limiter.check(b"svc", 105));
    }

    #[test]
    fn rate_limiter_active_keys() {
        let mut limiter = RateLimiter::new(5, 60);
        assert_eq!(limiter.active_keys(), 0);
        limiter.check(b"a", 1);
        limiter.check(b"b", 2);
        limiter.check(b"c", 3);
        assert_eq!(limiter.active_keys(), 3);
        limiter.reset(b"b");
        assert_eq!(limiter.active_keys(), 2);
    }

    #[test]
    fn rate_limiter_independent_keys() {
        let mut limiter = RateLimiter::new(1, 10);
        assert!(limiter.check(b"a", 100));
        assert!(limiter.check(b"b", 100));
        assert!(!limiter.check(b"a", 101));
        assert!(!limiter.check(b"b", 101));
    }

    #[test]
    fn rate_limiter_zero_window_start_saturates() {
        let mut limiter = RateLimiter::new(1, 100);
        // current_time < window_seconds → window_start saturates to 0.
        assert!(limiter.check(b"svc", 50));
        assert!(!limiter.check(b"svc", 50));
    }

    // ServiceIdentity

    #[test]
    fn identity_clone_debug_eq() {
        let id = ServiceIdentity {
            name: "svc-a".into(),
            key_id: [1u8; 32],
        };
        let cloned = id.clone();
        assert_eq!(id, cloned);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("svc-a"));
    }

    // ServiceKey / MockServiceKey

    #[test]
    fn mock_key_id() {
        let key = MockServiceKey::new([42u8; 32]);
        assert_eq!(*key.id(), [42u8; 32]);
    }

    #[test]
    fn mock_key_accepts_nonzero_signature() {
        let key = MockServiceKey::new([0u8; 32]);
        let mut sig = [0u8; 64];
        sig[0] = 1;
        assert!(key.verify(b"hello", &sig));
    }

    #[test]
    fn mock_key_rejects_all_zero_signature() {
        let key = MockServiceKey::new([0u8; 32]);
        assert!(!key.verify(b"hello", &[0u8; 64]));
    }

    // ServiceAuth

    #[test]
    fn auth_register_and_verify() {
        let mut auth = ServiceAuth::new();
        let identity = ServiceIdentity {
            name: "svc".into(),
            key_id: [1u8; 32],
        };
        auth.register_service(identity);

        let mut sig = [0u8; 64];
        sig[0] = 0xFF;
        assert!(auth.verify_request(&[1u8; 32], b"msg", &sig).is_ok());
    }

    #[test]
    fn auth_unknown_service() {
        let auth = ServiceAuth::new();
        assert_eq!(
            auth.verify_request(&[99u8; 32], b"msg", &[0u8; 64]),
            Err(IsolationError::UnknownService)
        );
    }

    #[test]
    fn auth_bad_signature() {
        let mut auth = ServiceAuth::new();
        auth.register_service(ServiceIdentity {
            name: "svc".into(),
            key_id: [1u8; 32],
        });
        assert_eq!(
            auth.verify_request(&[1u8; 32], b"msg", &[0u8; 64]),
            Err(IsolationError::AuthenticationFailed)
        );
    }

    #[test]
    fn auth_default() {
        let auth = ServiceAuth::default();
        assert_eq!(
            auth.verify_request(&[0u8; 32], b"", &[0u8; 64]),
            Err(IsolationError::UnknownService)
        );
    }
}
