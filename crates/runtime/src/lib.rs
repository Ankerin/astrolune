// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Deterministic Rust smart-contract module and compiler boundaries.

#![forbid(unsafe_code)]

use std::fmt;

use types::{Hash256, Resources};

/// Maximum allowed module code size in bytes (1 MiB).
pub const MAX_MODULE_SIZE: usize = 1024 * 1024;

/// Maximum allowed call input size in bytes (256 KiB).
pub const MAX_INPUT_SIZE: usize = 256 * 1024;

/// Maximum allowed call output size in bytes (256 KiB).
pub const MAX_OUTPUT_SIZE: usize = 256 * 1024;

/// Default runtime version used when no explicit version is provided.
pub const DEFAULT_VERSION: RuntimeVersion = RuntimeVersion {
    abi: 1,
    metering: 1,
};

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
    fn validate(
        &self,
        bytes: &[u8],
        version: RuntimeVersion,
    ) -> Result<ContractModule, RuntimeError>;
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
    fn execute(&self, module: &ContractModule, input: &[u8])
    -> Result<RuntimeOutput, RuntimeError>;
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

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidModule => write!(f, "invalid module"),
            Self::Unsupported => write!(f, "unsupported feature or version"),
            Self::LimitExceeded => write!(f, "limit exceeded"),
            Self::Trap => write!(f, "deterministic trap"),
        }
    }
}

impl std::error::Error for RuntimeError {}

/// Simple module validator that enforces size limits and version matching.
pub struct BasicModuleValidator {
    /// Maximum allowed module code size in bytes.
    max_size: usize,
}

impl BasicModuleValidator {
    /// Creates a new validator with the given maximum module size.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self { max_size }
    }
}

impl ModuleValidator for BasicModuleValidator {
    fn validate(
        &self,
        bytes: &[u8],
        version: RuntimeVersion,
    ) -> Result<ContractModule, RuntimeError> {
        if version != DEFAULT_VERSION {
            return Err(RuntimeError::Unsupported);
        }
        if bytes.is_empty() {
            return Err(RuntimeError::InvalidModule);
        }
        if bytes.len() > self.max_size {
            return Err(RuntimeError::LimitExceeded);
        }
        let code_hash = compute_hash(bytes);
        Ok(ContractModule {
            code_hash,
            version,
            code: bytes.to_vec(),
        })
    }
}

/// Interpreter backend that performs a simple deterministic byte transformation.
pub struct InterpreterBackend {
    /// Maximum allowed input size in bytes.
    max_input: usize,
    /// Maximum allowed output size in bytes.
    max_output: usize,
}

impl InterpreterBackend {
    /// Creates a new interpreter backend with the given size limits.
    #[must_use]
    pub fn new(max_input: usize, max_output: usize) -> Self {
        Self {
            max_input,
            max_output,
        }
    }
}

impl RuntimeBackend for InterpreterBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Interpreter
    }

    fn execute(
        &self,
        module: &ContractModule,
        input: &[u8],
    ) -> Result<RuntimeOutput, RuntimeError> {
        if input.len() > self.max_input {
            return Err(RuntimeError::LimitExceeded);
        }

        let code_len = module.code.len();
        if code_len == 0 {
            return Err(RuntimeError::Trap);
        }

        let mut output = Vec::with_capacity(input.len());
        for (i, &byte) in input.iter().enumerate() {
            let key = module.code[i % code_len];
            output.push(byte ^ key);
        }

        if output.len() > self.max_output {
            return Err(RuntimeError::LimitExceeded);
        }

        let input_len = input.len() as u64;
        let resources = Resources {
            compute: input_len.saturating_mul(10),
            memory: input_len,
            io: input_len.saturating_mul(2),
            bandwidth: input_len,
        };

        Ok(RuntimeOutput {
            return_data: output,
            resources,
        })
    }
}

/// Computes a deterministic 32-byte hash from input bytes.
fn compute_hash(data: &[u8]) -> Hash256 {
    let mut state = [0x6a09_e667_u32; 8];
    for (i, &byte) in data.iter().enumerate() {
        let word_idx = i % 8;
        #[allow(clippy::cast_possible_truncation)] // index is bounded by data length
        let idx = i as u32;
        state[word_idx] = state[word_idx]
            .wrapping_mul(0x9e37_79b9)
            .wrapping_add(u32::from(byte))
            .wrapping_add(idx);
    }
    let mut result = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Hash256(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_module() -> Vec<u8> {
        vec![0xAA, 0xBB, 0xCC, 0xDD]
    }

    fn test_version() -> RuntimeVersion {
        DEFAULT_VERSION
    }

    // -- Display and Error --

    #[test]
    fn runtime_error_display() {
        assert_eq!(RuntimeError::InvalidModule.to_string(), "invalid module");
        assert_eq!(
            RuntimeError::Unsupported.to_string(),
            "unsupported feature or version"
        );
        assert_eq!(RuntimeError::LimitExceeded.to_string(), "limit exceeded");
        assert_eq!(RuntimeError::Trap.to_string(), "deterministic trap");
    }

    #[test]
    fn runtime_error_is_std_error() {
        let err: &dyn std::error::Error = &RuntimeError::Trap;
        assert!(err.source().is_none());
    }

    // -- Constants --

    #[test]
    fn constants_are_correct() {
        assert_eq!(MAX_MODULE_SIZE, 1024 * 1024);
        assert_eq!(MAX_INPUT_SIZE, 256 * 1024);
        assert_eq!(MAX_OUTPUT_SIZE, 256 * 1024);
        assert_eq!(DEFAULT_VERSION.abi, 1);
        assert_eq!(DEFAULT_VERSION.metering, 1);
    }

    // -- BasicModuleValidator --

    #[test]
    fn valid_module_accepted() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let code = test_module();
        let result = validator.validate(&code, test_version());
        assert!(result.is_ok());
        let module = result.unwrap();
        assert_eq!(module.version, test_version());
        assert_eq!(module.code, code);
        assert_eq!(module.code_hash, compute_hash(&code));
    }

    #[test]
    fn empty_module_rejected() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let result = validator.validate(&[], test_version());
        assert_eq!(result.unwrap_err(), RuntimeError::InvalidModule);
    }

    #[test]
    fn oversized_module_rejected() {
        let validator = BasicModuleValidator::new(10);
        let code = vec![0xAA; 11];
        let result = validator.validate(&code, test_version());
        assert_eq!(result.unwrap_err(), RuntimeError::LimitExceeded);
    }

    #[test]
    fn wrong_version_rejected() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let code = test_module();
        let version = RuntimeVersion {
            abi: 99,
            metering: 1,
        };
        let result = validator.validate(&code, version);
        assert_eq!(result.unwrap_err(), RuntimeError::Unsupported);
    }

    #[test]
    fn wrong_metering_version_rejected() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let code = test_module();
        let version = RuntimeVersion {
            abi: 1,
            metering: 99,
        };
        let result = validator.validate(&code, version);
        assert_eq!(result.unwrap_err(), RuntimeError::Unsupported);
    }

    #[test]
    fn code_hash_is_deterministic() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let code = test_module();
        let m1 = validator.validate(&code, test_version()).unwrap();
        let m2 = validator.validate(&code, test_version()).unwrap();
        assert_eq!(m1.code_hash, m2.code_hash);
    }

    #[test]
    fn different_code_different_hash() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let m1 = validator.validate(&[0xAA], test_version()).unwrap();
        let m2 = validator.validate(&[0xBB], test_version()).unwrap();
        assert_ne!(m1.code_hash, m2.code_hash);
    }

    #[test]
    fn size_limit_at_boundary() {
        let validator = BasicModuleValidator::new(4);
        assert!(validator.validate(&[0; 4], test_version()).is_ok());
        assert_eq!(
            validator.validate(&[0; 5], test_version()).unwrap_err(),
            RuntimeError::LimitExceeded
        );
    }

    // -- InterpreterBackend --

    #[test]
    fn interpreter_kind() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        assert_eq!(backend.kind(), BackendKind::Interpreter);
    }

    #[test]
    fn interpreter_execute_basic() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01, 0x02, 0x03], test_version())
            .unwrap();
        let input = [0x04, 0x05, 0x06];
        let output = backend.execute(&module, &input).unwrap();
        assert_eq!(
            output.return_data,
            vec![0x04 ^ 0x01, 0x05 ^ 0x02, 0x06 ^ 0x03]
        );
    }

    #[test]
    fn interpreter_xor_wraps_at_code_length() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0xFF], test_version())
            .unwrap();
        let input = [0x01, 0x02, 0x03];
        let output = backend.execute(&module, &input).unwrap();
        // All bytes XOR with the single code byte 0xFF
        assert_eq!(
            output.return_data,
            vec![0x01 ^ 0xFF, 0x02 ^ 0xFF, 0x03 ^ 0xFF]
        );
    }

    #[test]
    fn interpreter_empty_input() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0xAA], test_version())
            .unwrap();
        let output = backend.execute(&module, &[]).unwrap();
        assert_eq!(output.return_data, Vec::<u8>::new());
    }

    #[test]
    fn interpreter_empty_module_trap() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = ContractModule {
            code_hash: Hash256::ZERO,
            version: test_version(),
            code: vec![],
        };
        let result = backend.execute(&module, &[0x01]);
        assert_eq!(result.unwrap_err(), RuntimeError::Trap);
    }

    #[test]
    fn interpreter_input_size_limit() {
        let backend = InterpreterBackend::new(3, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01], test_version())
            .unwrap();
        let input = vec![0x01; 4];
        let result = backend.execute(&module, &input);
        assert_eq!(result.unwrap_err(), RuntimeError::LimitExceeded);
    }

    #[test]
    fn interpreter_output_size_limit() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, 2);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01], test_version())
            .unwrap();
        let input = vec![0x01; 3];
        let result = backend.execute(&module, &input);
        assert_eq!(result.unwrap_err(), RuntimeError::LimitExceeded);
    }

    #[test]
    fn interpreter_resource_metering() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01], test_version())
            .unwrap();
        let input = vec![0x01; 10];
        let output = backend.execute(&module, &input).unwrap();
        assert_eq!(output.resources.compute, 100); // 10 * 10
        assert_eq!(output.resources.memory, 10);
        assert_eq!(output.resources.io, 20); // 10 * 2
        assert_eq!(output.resources.bandwidth, 10);
    }

    #[test]
    fn interpreter_resource_metering_empty() {
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);
        let module = BasicModuleValidator::new(MAX_MODULE_SIZE)
            .validate(&[0x01], test_version())
            .unwrap();
        let output = backend.execute(&module, &[]).unwrap();
        assert_eq!(output.resources, Resources::ZERO);
    }

    // -- Integration: validator + interpreter --

    #[test]
    fn roundtrip_validate_and_execute() {
        let validator = BasicModuleValidator::new(MAX_MODULE_SIZE);
        let backend = InterpreterBackend::new(MAX_INPUT_SIZE, MAX_OUTPUT_SIZE);

        let code = vec![0x10, 0x20, 0x30];
        let module = validator.validate(&code, test_version()).unwrap();
        let input = vec![0x10, 0x20, 0x30];
        let output = backend.execute(&module, &input).unwrap();

        // XOR with same bytes gives zeros
        assert_eq!(output.return_data, vec![0x00, 0x00, 0x00]);
    }

    #[test]
    fn interpreter_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InterpreterBackend>();
    }
}
