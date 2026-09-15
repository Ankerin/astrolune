// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Rust smart-contract SDK boundary for `AstroLune`.
//!
//! Contracts are authored in a deterministic Rust subset and compiled to the
//! canonical runtime target. The target, ABI, metering instrumentation, and
//! compiler version are consensus-controlled; arbitrary native Rust binaries
//! are never deployed directly.
//!
//! The host interface provides a minimal, auditable surface for state access,
//! resource metering, and cross-contract communication.

#![forbid(unsafe_code)]
#![no_std]
#![allow(clippy::missing_errors_doc)]

extern crate alloc;

use alloc::vec::Vec;

/// A contract-visible 32-byte address.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// The zero address.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Returns `true` if the address is the zero value.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// Execution resources charged by their actual class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceUsage {
    /// Metered instruction and host-call work.
    pub compute: u64,
    /// Peak linear-memory usage.
    pub memory: u64,
    /// State input/output bytes and operations.
    pub io: u64,
}

impl ResourceUsage {
    /// All-zero resource usage.
    pub const ZERO: Self = Self {
        compute: 0,
        memory: 0,
        io: 0,
    };

    /// Returns `true` if all resource classes are zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.compute == 0 && self.memory == 0 && self.io == 0
    }

    /// Adds another resource usage to this one.
    #[must_use]
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            compute: self.compute.saturating_add(other.compute),
            memory: self.memory.saturating_add(other.memory),
            io: self.io.saturating_add(other.io),
        }
    }
}

/// A fixed-capacity buffer provided by the host to the contract.
///
/// The contract reads from and writes into this buffer. The host enforces
/// size limits and tracks I/O for resource metering.
pub struct MemoryBuffer {
    data: Vec<u8>,
    capacity: usize,
}

impl MemoryBuffer {
    /// Creates a new buffer with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            data: alloc::vec![0u8; capacity],
            capacity,
        }
    }

    /// Returns the buffer capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the current buffer length (bytes written).
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a reference to the buffer contents.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable reference to the buffer contents.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Copies data into the buffer from a source slice.
    ///
    /// Returns the number of bytes actually copied (limited by capacity).
    pub fn fill_from(&mut self, source: &[u8]) -> usize {
        let len = source.len().min(self.capacity);
        self.data[..len].copy_from_slice(&source[..len]);
        len
    }

    /// Consumes the buffer and returns the underlying data.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

/// Deterministic host functions exposed to Rust contracts.
pub trait Host: Send {
    /// Returns the transaction sender.
    fn caller(&self) -> Address;

    /// Returns the balance of an account in the smallest unit.
    fn balance(&mut self, account: &Address) -> u64;

    /// Transfers tokens from the contract's account to another account.
    fn transfer(&mut self, to: &Address, amount: u64) -> Result<(), ContractError>;

    /// Reads contract-local state into the supplied output buffer.
    ///
    /// Returns the number of bytes actually read.
    fn state_read(&mut self, key: &[u8], output: &mut [u8]) -> Result<usize, ContractError>;

    /// Writes contract-local state under an access lease.
    fn state_write(&mut self, key: &[u8], value: &[u8]) -> Result<(), ContractError>;

    /// Deletes contract-local state under a key.
    fn state_delete(&mut self, key: &[u8]) -> Result<(), ContractError>;

    /// Emits a canonical event.
    fn emit(&mut self, topic: &[u8; 32], data: &[u8]) -> Result<(), ContractError>;

    /// Returns the current block height.
    fn block_height(&self) -> u64;

    /// Returns the current timestamp (Unix seconds).
    fn block_timestamp(&self) -> u64;
}

/// Contract-visible deterministic failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// Caller supplied malformed data.
    InvalidInput,
    /// Contract attempted access outside its declared state lease.
    AccessDenied,
    /// The transaction exhausted a resource class.
    ResourceLimit,
    /// A host operation failed deterministically.
    HostFailure,
    /// Insufficient balance for the requested operation.
    InsufficientBalance,
}

impl core::fmt::Display for ContractError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "invalid input"),
            Self::AccessDenied => write!(f, "access denied"),
            Self::ResourceLimit => write!(f, "resource limit exceeded"),
            Self::HostFailure => write!(f, "host failure"),
            Self::InsufficientBalance => write!(f, "insufficient balance"),
        }
    }
}

/// A `Host` wrapper that tracks resource usage during execution.
///
/// `MeteredHost` delegates all host calls to the inner implementation while
/// accumulating the resource cost of each operation.
pub struct MeteredHost<H: Host> {
    inner: H,
    usage: ResourceUsage,
}

impl<H: Host> MeteredHost<H> {
    /// Wraps a host implementation with resource metering.
    #[must_use]
    pub fn new(inner: H) -> Self {
        Self {
            inner,
            usage: ResourceUsage::ZERO,
        }
    }

    /// Returns the accumulated resource usage.
    #[must_use]
    pub fn usage(&self) -> ResourceUsage {
        self.usage
    }

    /// Consumes the wrapper and returns the inner host and final usage.
    #[must_use]
    pub fn into_parts(self) -> (H, ResourceUsage) {
        (self.inner, self.usage)
    }
}

impl<H: Host> Host for MeteredHost<H> {
    fn caller(&self) -> Address {
        self.inner.caller()
    }

    fn balance(&mut self, account: &Address) -> u64 {
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 1,
            memory: 0,
            io: 1,
        });
        self.inner.balance(account)
    }

    fn transfer(&mut self, to: &Address, amount: u64) -> Result<(), ContractError> {
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 2,
            memory: 0,
            io: 2,
        });
        self.inner.transfer(to, amount)
    }

    fn state_read(&mut self, key: &[u8], output: &mut [u8]) -> Result<usize, ContractError> {
        let cost = key.len() as u64 + output.len() as u64;
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 1,
            memory: 0,
            io: cost,
        });
        self.inner.state_read(key, output)
    }

    fn state_write(&mut self, key: &[u8], value: &[u8]) -> Result<(), ContractError> {
        let cost = key.len() as u64 + value.len() as u64;
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 2,
            memory: 0,
            io: cost,
        });
        self.inner.state_write(key, value)
    }

    fn state_delete(&mut self, key: &[u8]) -> Result<(), ContractError> {
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 1,
            memory: 0,
            io: key.len() as u64,
        });
        self.inner.state_delete(key)
    }

    fn emit(&mut self, topic: &[u8; 32], data: &[u8]) -> Result<(), ContractError> {
        self.usage = self.usage.saturating_add(ResourceUsage {
            compute: 1,
            memory: 0,
            io: 32 + data.len() as u64,
        });
        self.inner.emit(topic, data)
    }

    fn block_height(&self) -> u64 {
        self.inner.block_height()
    }

    fn block_timestamp(&self) -> u64 {
        self.inner.block_timestamp()
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::collections::BTreeMap;
    use alloc::format;

    use super::*;

    struct MockHost {
        balances: BTreeMap<Address, u64>,
        storage: BTreeMap<Vec<u8>, Vec<u8>>,
        events: Vec<([u8; 32], Vec<u8>)>,
        height: u64,
        timestamp: u64,
    }

    impl MockHost {
        fn new() -> Self {
            let mut balances = BTreeMap::new();
            let contract_addr = Address([0x42; 32]);
            balances.insert(contract_addr, 1000);
            Self {
                balances,
                storage: BTreeMap::new(),
                events: Vec::new(),
                height: 1,
                timestamp: 1_000_000,
            }
        }
    }

    impl Host for MockHost {
        fn caller(&self) -> Address {
            Address([0x01; 32])
        }

        fn balance(&mut self, account: &Address) -> u64 {
            self.balances.get(account).copied().unwrap_or(0)
        }

        fn transfer(&mut self, to: &Address, amount: u64) -> Result<(), ContractError> {
            let from = Address([0x42; 32]);
            let balance = self.balances.get(&from).copied().unwrap_or(0);
            if balance < amount {
                return Err(ContractError::InsufficientBalance);
            }
            *self.balances.entry(from).or_insert(0) -= amount;
            *self.balances.entry(*to).or_insert(0) += amount;
            Ok(())
        }

        fn state_read(&mut self, key: &[u8], output: &mut [u8]) -> Result<usize, ContractError> {
            match self.storage.get(key) {
                Some(value) => {
                    let len = value.len().min(output.len());
                    output[..len].copy_from_slice(&value[..len]);
                    Ok(len)
                }
                None => Ok(0),
            }
        }

        fn state_write(&mut self, key: &[u8], value: &[u8]) -> Result<(), ContractError> {
            self.storage.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn state_delete(&mut self, key: &[u8]) -> Result<(), ContractError> {
            self.storage.remove(key);
            Ok(())
        }

        fn emit(&mut self, topic: &[u8; 32], data: &[u8]) -> Result<(), ContractError> {
            self.events.push((*topic, data.to_vec()));
            Ok(())
        }

        fn block_height(&self) -> u64 {
            self.height
        }

        fn block_timestamp(&self) -> u64 {
            self.timestamp
        }
    }

    #[test]
    fn mock_host_basic_operations() {
        let mut host = MockHost::new();
        let caller = host.caller();
        assert!(!caller.is_zero());

        let contract = Address([0x42; 32]);
        assert_eq!(host.balance(&contract), 1000);

        let recipient = Address([0x03; 32]);
        host.transfer(&recipient, 100).unwrap();
        assert_eq!(host.balance(&contract), 900);
        assert_eq!(host.balance(&recipient), 100);
    }

    #[test]
    fn mock_host_insufficient_balance() {
        let mut host = MockHost::new();
        let recipient = Address([0x03; 32]);
        assert_eq!(
            host.transfer(&recipient, 2000),
            Err(ContractError::InsufficientBalance)
        );
    }

    #[test]
    fn mock_host_state_operations() {
        let mut host = MockHost::new();

        host.state_write(b"key1", b"value1").unwrap();
        let mut buf = [0u8; 16];
        let n = host.state_read(b"key1", &mut buf).unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf[..n], b"value1");

        host.state_delete(b"key1").unwrap();
        let n = host.state_read(b"key1", &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn mock_host_events() {
        let mut host = MockHost::new();
        let topic = [0xAA; 32];
        host.emit(&topic, b"hello").unwrap();
        assert_eq!(host.events.len(), 1);
        assert_eq!(host.events[0].0, topic);
        assert_eq!(host.events[0].1, b"hello");
    }

    #[test]
    fn metered_host_tracks_usage() {
        let host = MockHost::new();
        let mut metered = MeteredHost::new(host);

        let _ = metered.balance(&Address([0x42; 32]));
        let usage = metered.usage();
        assert!(usage.compute > 0);
        assert!(usage.io > 0);
    }

    #[test]
    fn metered_host_state_io_cost() {
        let host = MockHost::new();
        let mut metered = MeteredHost::new(host);

        metered.state_write(b"key", b"value").unwrap();
        let usage = metered.usage();
        assert!(usage.io > 0);
    }

    #[test]
    fn resource_usage_saturating_add() {
        let a = ResourceUsage { compute: 1, memory: 2, io: 3 };
        let b = ResourceUsage { compute: 4, memory: 5, io: 6 };
        let sum = a.saturating_add(b);
        assert_eq!(sum, ResourceUsage { compute: 5, memory: 7, io: 9 });
    }

    #[test]
    fn resource_usage_overflow_saturates() {
        let max = ResourceUsage { compute: u64::MAX, memory: 0, io: 0 };
        let one = ResourceUsage { compute: 1, memory: 0, io: 0 };
        let sum = max.saturating_add(one);
        assert_eq!(sum.compute, u64::MAX);
    }

    #[test]
    fn memory_buffer_fill_and_read() {
        let mut buf = MemoryBuffer::new(8);
        assert_eq!(buf.capacity(), 8);

        let copied = buf.fill_from(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(copied, 8);
        assert_eq!(buf.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn memory_buffer_into_vec() {
        let mut buf = MemoryBuffer::new(4);
        buf.fill_from(&[10, 20, 30]);
        let data = buf.into_vec();
        assert_eq!(data, &[10, 20, 30, 0]);
    }

    #[test]
    fn contract_error_display() {
        let _ = format!("{}", ContractError::InvalidInput);
        let _ = format!("{}", ContractError::AccessDenied);
        let _ = format!("{}", ContractError::ResourceLimit);
        let _ = format!("{}", ContractError::HostFailure);
        let _ = format!("{}", ContractError::InsufficientBalance);
    }

    #[test]
    fn address_zero() {
        assert!(Address::ZERO.is_zero());
        assert!(!Address([1u8; 32]).is_zero());
    }
}
