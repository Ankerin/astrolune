// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Core types and constants defining the runtime versioning and module schema.

use types::{Hash256, Resources};

/// Maximum allowed module code size in bytes (1 MiB).
pub const MAX_MODULE_SIZE: usize = 1024 * 1024;

/// Maximum allowed call input size in bytes (256 KiB).
pub const MAX_INPUT_SIZE: usize = 256 * 1024;

/// Maximum allowed call output size in bytes (256 KiB).
pub const MAX_OUTPUT_SIZE: usize = 256 * 1024;

/// Consensus-controlled runtime identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeVersion {
    /// Contract semantics and host `ABI` version.
    pub abi: u32,
    /// Resource instrumentation schedule version.
    pub metering: u32,
}

/// Default runtime version used when no explicit version is provided.
pub const DEFAULT_VERSION: RuntimeVersion = RuntimeVersion {
    abi: 1,
    metering: 1,
};

/// Canonical deployable module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractModule {
    /// Hash of validated canonical bytes.
    pub code_hash: Hash256,
    /// Required runtime version.
    pub version: RuntimeVersion,
    /// Canonical target bytes, never native machine code.
    pub code: Vec<u8>,
}

/// Output returned by a local runtime backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeOutput {
    /// Canonical return bytes.
    pub return_data: Vec<u8>,
    /// Actual resource usage by class.
    pub resources: Resources,
}

/// Native artifact cache identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArtifactKey {
    /// Canonical contract code.
    pub code_hash: Hash256,
    /// Runtime semantics and metering.
    pub version: RuntimeVersion,
    /// Deterministic compiler backend identity.
    pub compiler: Hash256,
    /// Target and enabled CPU feature identity.
    pub target: Hash256,
}
