// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Execution backends: traits and concrete implementations that run validated
//! contract modules under deterministic host semantics.

use crate::error::RuntimeError;
use crate::version::{ContractModule, RuntimeOutput};
use types::Resources;

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
