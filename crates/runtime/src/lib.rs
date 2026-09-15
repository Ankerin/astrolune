// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic Rust smart-contract module and compiler boundaries.

#![forbid(unsafe_code)]

use types::{Hash256, Resources};

/// Consensus-controlled runtime identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeVersion {
    /// Contract semantics and host `ABI` version.
    pub abi: u32,
    /// Resource instrumentation schedule version.
    pub metering: u32,
}

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

/// Validates a canonical contract module before deployment.
pub trait ModuleValidator {
    /// Validates target features, imports, control flow, memory, and metering.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the module is malformed, unsupported, or
    /// exceeds configured limits.
    fn validate(&self, bytes: &[u8], version: RuntimeVersion) -> Result<ContractModule, RuntimeError>;
}

/// Local execution backend class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    /// Portable reference semantics.
    Interpreter,
    /// Ahead-of-time native compilation.
    Aot,
    /// Optional just-in-time native compilation.
    Jit,
}

/// Output returned by a local runtime backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeOutput {
    /// Canonical return bytes.
    pub return_data: Vec<u8>,
    /// Actual resource usage by class.
    pub resources: Resources,
}

/// Executes canonical modules under deterministic host semantics.
pub trait RuntimeBackend: Send + Sync {
    /// Identifies the local backend class.
    fn kind(&self) -> BackendKind;

    /// Executes one call. Optimized backends must match the interpreter.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] for deterministic traps and resource exhaustion.
    fn execute(&self, module: &ContractModule, input: &[u8]) -> Result<RuntimeOutput, RuntimeError>;
}

/// Contract validation and execution failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    /// Canonical module bytes are malformed.
    InvalidModule,
    /// Module requests an unsupported feature or version.
    Unsupported,
    /// Module or call exceeds a configured bound.
    LimitExceeded,
    /// Deterministic contract execution trapped.
    Trap,
}
