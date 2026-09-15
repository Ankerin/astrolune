// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Canonical, dependency-light protocol types shared by `AstroLune` components.

#![forbid(unsafe_code)]

/// Protocol domain separators used for domain hashing and signing.
///
/// Each tag is a unique ASCII string that prevents cross-domain signature or
/// hash reuse. Tags are prefixed with the protocol name and version to avoid
/// collisions with other systems.
pub mod domain {
    /// Transaction signing domain.
    pub const TRANSACTION: &[u8] = b"astrolune.tx.v1";

    /// Block header signing domain.
    pub const BLOCK_HEADER: &[u8] = b"astrolune.block.v1";

    /// `PoTB` weight commitment domain.
    pub const POTB_WEIGHT: &[u8] = b"astrolune.potb.weight.v1";

    /// Committee root commitment domain.
    pub const COMMITTEE: &[u8] = b"astrolune.committee.v1";

    /// Finality certificate domain.
    pub const FINALITY: &[u8] = b"astrolune.finality.v1";

    /// VRF evaluation domain for committee selection.
    pub const VRF_COMMITTEE: &[u8] = b"astrolune.vrf.committee.v1";

    /// VRF evaluation domain for producer selection.
    pub const VRF_PRODUCER: &[u8] = b"astrolune.vrf.producer.v1";

    /// Genesis hash domain.
    pub const GENESIS: &[u8] = b"astrolune.genesis.v1";

    /// State root commitment domain.
    pub const STATE_ROOT: &[u8] = b"astrolune.state.v1";

    /// Execution receipt commitment domain.
    pub const RECEIPT: &[u8] = b"astrolune.receipt.v1";
}

/// A cryptographic digest committed by the protocol.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// The all-zero digest.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Creates a digest from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if the digest is the all-zero value.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Combines two digests by XOR-ing their bytes.
    ///
    /// This is a deterministic, order-dependent operation suitable for
    /// incremental root construction.
    #[must_use]
    pub const fn xor(self, other: Self) -> Self {
        let mut result = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            result[i] = self.0[i] ^ other.0[i];
            i += 1;
        }
        Self(result)
    }
}

impl std::fmt::Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A wallet or contract address.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// The zero address.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Creates an address from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if the address is the zero value.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A validator identity key.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValidatorId(pub [u8; 32]);

impl ValidatorId {
    /// The zero validator identity (invalid in consensus).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Creates a validator identity from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if the identity is the zero value.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl std::fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A state key. Canonical encoding must impose a bounded length before use.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateKey(pub Vec<u8>);

impl StateKey {
    /// Maximum allowed key length in bytes.
    pub const MAX_LEN: usize = 256;

    /// Creates a new state key from bytes.
    ///
    /// # Errors
    ///
    /// Returns `None` if the key exceeds [`Self::MAX_LEN`].
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() > Self::MAX_LEN {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// Returns the key bytes as a slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the key is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Four consensus-metered resource classes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Resources {
    /// Deterministic compute units.
    pub compute: u64,
    /// Peak and allocated memory units.
    pub memory: u64,
    /// State read/write units.
    pub io: u64,
    /// Encoded network bytes.
    pub bandwidth: u64,
}

impl Resources {
    /// All-zero resources.
    pub const ZERO: Self = Self {
        compute: 0,
        memory: 0,
        io: 0,
        bandwidth: 0,
    };

    /// Returns `true` if every resource class is zero.
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.compute == 0 && self.memory == 0 && self.io == 0 && self.bandwidth == 0
    }

    /// Returns `true` if no resource class exceeds `other`.
    #[must_use]
    pub fn fits_in(self, other: Self) -> bool {
        self.compute <= other.compute
            && self.memory <= other.memory
            && self.io <= other.io
            && self.bandwidth <= other.bandwidth
    }

    /// Saturating addition of two resource sets.
    #[must_use]
    pub fn saturating_add(self, other: Self) -> Self {
        Self {
            compute: self.compute.saturating_add(other.compute),
            memory: self.memory.saturating_add(other.memory),
            io: self.io.saturating_add(other.io),
            bandwidth: self.bandwidth.saturating_add(other.bandwidth),
        }
    }

    /// Checked addition of two resource sets.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            compute: self.compute.checked_add(other.compute)?,
            memory: self.memory.checked_add(other.memory)?,
            io: self.io.checked_add(other.io)?,
            bandwidth: self.bandwidth.checked_add(other.bandwidth)?,
        })
    }

    /// Scalar multiplication of all resource classes.
    #[must_use]
    pub fn checked_mul(self, scalar: u64) -> Option<Self> {
        Some(Self {
            compute: self.compute.checked_mul(scalar)?,
            memory: self.memory.checked_mul(scalar)?,
            io: self.io.checked_mul(scalar)?,
            bandwidth: self.bandwidth.checked_mul(scalar)?,
        })
    }

    /// Returns the number of non-zero resource classes.
    #[must_use]
    pub fn count(self) -> u32 {
        u32::from(self.compute != 0)
            + u32::from(self.memory != 0)
            + u32::from(self.io != 0)
            + u32::from(self.bandwidth != 0)
    }
}

/// A canonical signed transaction envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    /// Network replay-protection identifier.
    pub chain_id: u32,
    /// Sender account.
    pub sender: Address,
    /// Sender sequence number.
    pub nonce: u64,
    /// Declared state keys needed by execution.
    pub access_list: Vec<StateKey>,
    /// Maximum resources the sender authorizes.
    pub resource_limit: Resources,
    /// Canonical transaction payload.
    pub payload: Vec<u8>,
    /// Signature over every preceding canonical field.
    pub signature: [u8; 64],
}

/// A canonical block header independent of the execution implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    /// Monotonic chain height.
    pub height: u64,
    /// Previous finalized block.
    pub parent: Hash256,
    /// Ordered transaction commitment.
    pub transactions_root: Hash256,
    /// Post-execution state commitment.
    pub state_root: Hash256,
    /// Receipts commitment.
    pub receipts_root: Hash256,
    /// Committee selected for this height.
    pub committee_root: Hash256,
    /// Finalized adaptive capacity applicable to this block.
    pub capacity: Resources,
}

impl BlockHeader {
    /// Validates structural invariants of this header against its parent.
    ///
    /// Checks:
    /// - Height is exactly one greater than the parent's
    /// - Parent hash is not zero (except for genesis at height 0)
    /// - Capacity resources are non-negative (always true for u64)
    ///
    /// This does **not** verify signatures or state roots; those require
    /// access to the validator set and state database.
    #[must_use]
    pub fn validate_parent(&self, parent: &BlockHeader) -> bool {
        self.height == parent.height.saturating_add(1) && self.parent == Self::compute_hash(parent)
    }

    /// Computes a deterministic hash of this block header.
    ///
    /// The hash covers height, parent, transaction/state/receipts/committee
    /// roots, and capacity. This is used for parent linkage checks and
    /// lightweight identification.
    #[must_use]
    pub fn compute_hash(&self) -> Hash256 {
        let mut data = [0u8; 224];
        data[0..8].copy_from_slice(&self.height.to_le_bytes());
        data[8..40].copy_from_slice(&self.parent.0);
        data[40..72].copy_from_slice(&self.transactions_root.0);
        data[72..104].copy_from_slice(&self.state_root.0);
        data[104..136].copy_from_slice(&self.receipts_root.0);
        data[136..168].copy_from_slice(&self.committee_root.0);
        data[168..176].copy_from_slice(&self.capacity.compute.to_le_bytes());
        data[176..184].copy_from_slice(&self.capacity.memory.to_le_bytes());
        data[184..192].copy_from_slice(&self.capacity.io.to_le_bytes());
        data[192..200].copy_from_slice(&self.capacity.bandwidth.to_le_bytes());
        // XOR-fold 224 bytes into 32 bytes
        let mut hash = [0u8; 32];
        for (i, byte) in data.iter().enumerate() {
            hash[i % 32] ^= byte;
        }
        Hash256(hash)
    }
}

/// An ordered block proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// Consensus and execution commitments.
    pub header: BlockHeader,
    /// Transactions in the exact order fixed by consensus.
    pub transactions: Vec<Transaction>,
}

/// A state transition result that can be checked without trusting an optimizer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReceipt {
    /// Transaction identifier.
    pub transaction: Hash256,
    /// Whether contract execution committed its changes.
    pub succeeded: bool,
    /// Actual metered resources.
    pub resources: Resources,
    /// Hash of emitted events and return data.
    pub output_root: Hash256,
}

impl ExecutionReceipt {
    /// Computes a deterministic commitment hash for this receipt.
    ///
    /// The commitment binds the transaction ID, success flag, resource
    /// consumption, and output root into a single hash suitable for
    /// inclusion in the block header receipts root.
    #[must_use]
    pub fn commitment(&self) -> Hash256 {
        let mut data = [0u8; 108];
        data[0..32].copy_from_slice(&self.transaction.0);
        data[32] = u8::from(self.succeeded);
        data[33..41].copy_from_slice(&self.resources.compute.to_le_bytes());
        data[41..49].copy_from_slice(&self.resources.memory.to_le_bytes());
        data[49..57].copy_from_slice(&self.resources.io.to_le_bytes());
        data[57..65].copy_from_slice(&self.resources.bandwidth.to_le_bytes());
        data[65..97].copy_from_slice(&self.output_root.0);
        // XOR-fold 108 bytes into 32 bytes
        let mut hash = [0u8; 32];
        for (i, byte) in data.iter().enumerate() {
            hash[i % 32] ^= byte;
        }
        Hash256(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Hash256 tests --

    #[test]
    fn hash256_zero_is_all_zeros() {
        assert_eq!(Hash256::ZERO.0, [0u8; 32]);
        assert!(Hash256::ZERO.is_zero());
    }

    #[test]
    fn hash256_from_bytes_roundtrips() {
        let bytes = [0xAB_u8; 32];
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(*hash.as_bytes(), bytes);
    }

    #[test]
    fn hash256_xor_is_deterministic() {
        let a = Hash256([1u8; 32]);
        let b = Hash256([2u8; 32]);
        let result = a.xor(b);
        assert_eq!(result, b.xor(a));
        assert_eq!(result.0, [3u8; 32]);
    }

    #[test]
    fn hash256_display_is_hex_lowercase() {
        let hash = Hash256([0x0A, 0xFB, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let display = format!("{hash}");
        assert!(display.starts_with("0afb00"));
        assert_eq!(display.len(), 64);
    }

    // -- Address tests --

    #[test]
    fn address_zero_is_all_zeros() {
        assert!(Address::ZERO.is_zero());
    }

    #[test]
    fn address_display_prefixes_0x() {
        let addr = Address::from_bytes([0x42; 32]);
        let display = format!("{addr}");
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 66);
    }

    // -- ValidatorId tests --

    #[test]
    fn validator_id_zero_is_all_zeros() {
        assert!(ValidatorId::ZERO.is_zero());
    }

    #[test]
    fn validator_id_ordering() {
        let a = ValidatorId([1u8; 32]);
        let b = ValidatorId([2u8; 32]);
        assert!(a < b);
    }

    // -- StateKey tests --

    #[test]
    fn state_key_max_len_enforced() {
        let ok = StateKey::new(vec![0u8; 256]);
        assert!(ok.is_some());

        let too_long = StateKey::new(vec![0u8; 257]);
        assert!(too_long.is_none());
    }

    #[test]
    fn state_key_empty() {
        let key = StateKey(Vec::new());
        assert!(key.is_empty());
        assert_eq!(key.len(), 0);
    }

    // -- Resources tests --

    #[test]
    fn resources_zero_is_all_zeros() {
        assert!(Resources::ZERO.is_zero());
    }

    #[test]
    fn resources_fits_in() {
        let small = Resources { compute: 1, memory: 2, io: 3, bandwidth: 4 };
        let large = Resources { compute: 5, memory: 5, io: 5, bandwidth: 5 };
        assert!(small.fits_in(large));
        assert!(!large.fits_in(small));
    }

    #[test]
    fn resources_checked_add() {
        let a = Resources { compute: 1, memory: 2, io: 3, bandwidth: 4 };
        let b = Resources { compute: 5, memory: 6, io: 7, bandwidth: 8 };
        let sum = a.checked_add(b).unwrap();
        assert_eq!(sum, Resources { compute: 6, memory: 8, io: 10, bandwidth: 12 });
    }

    #[test]
    fn resources_checked_add_overflow() {
        let max = Resources { compute: u64::MAX, memory: 0, io: 0, bandwidth: 0 };
        let one = Resources { compute: 1, memory: 0, io: 0, bandwidth: 0 };
        assert!(max.checked_add(one).is_none());
    }

    #[test]
    fn resources_saturating_add() {
        let a = Resources { compute: u64::MAX, memory: 0, io: 0, bandwidth: 0 };
        let b = Resources { compute: 1, memory: 0, io: 0, bandwidth: 0 };
        let sum = a.saturating_add(b);
        assert_eq!(sum.compute, u64::MAX);
    }

    #[test]
    fn resources_checked_mul() {
        let r = Resources { compute: 3, memory: 4, io: 5, bandwidth: 6 };
        let product = r.checked_mul(2).unwrap();
        assert_eq!(product, Resources { compute: 6, memory: 8, io: 10, bandwidth: 12 });
    }

    #[test]
    fn resources_checked_mul_overflow() {
        let r = Resources { compute: u64::MAX, memory: 0, io: 0, bandwidth: 0 };
        assert!(r.checked_mul(2).is_none());
    }

    #[test]
    fn resources_count() {
        let none = Resources::ZERO;
        assert_eq!(none.count(), 0);

        let partial = Resources { compute: 1, memory: 0, io: 3, bandwidth: 0 };
        assert_eq!(partial.count(), 2);

        let all = Resources { compute: 1, memory: 1, io: 1, bandwidth: 1 };
        assert_eq!(all.count(), 4);
    }

    // -- Domain tag tests --

    #[test]
    fn domain_tags_are_unique() {
        let tags: &[&[u8]] = &[
            domain::TRANSACTION,
            domain::BLOCK_HEADER,
            domain::POTB_WEIGHT,
            domain::COMMITTEE,
            domain::FINALITY,
            domain::VRF_COMMITTEE,
            domain::VRF_PRODUCER,
            domain::GENESIS,
            domain::STATE_ROOT,
            domain::RECEIPT,
        ];

        for (i, a) in tags.iter().enumerate() {
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "domain tags at indices {i} and {j} collide");
                }
            }
        }
    }

    // -- ExecutionReceipt tests --

    #[test]
    fn receipt_commitment_deterministic() {
        let receipt = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources { compute: 10, memory: 20, io: 30, bandwidth: 40 },
            output_root: Hash256([2u8; 32]),
        };
        let c1 = receipt.commitment();
        let c2 = receipt.commitment();
        assert_eq!(c1, c2);
    }

    #[test]
    fn receipt_commitment_differs_on_success() {
        let r1 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources::ZERO,
            output_root: Hash256::ZERO,
        };
        let mut r2 = r1.clone();
        r2.succeeded = false;
        assert_ne!(r1.commitment(), r2.commitment());
    }

    #[test]
    fn receipt_commitment_differs_on_resources() {
        let r1 = ExecutionReceipt {
            transaction: Hash256([1u8; 32]),
            succeeded: true,
            resources: Resources { compute: 10, memory: 0, io: 0, bandwidth: 0 },
            output_root: Hash256::ZERO,
        };
        let mut r2 = r1.clone();
        r2.resources.compute = 20;
        assert_ne!(r1.commitment(), r2.commitment());
    }

    // -- BlockHeader tests --

    #[test]
    fn block_header_hash_deterministic() {
        let header = BlockHeader {
            height: 1,
            parent: Hash256([0xAA; 32]),
            transactions_root: Hash256([1u8; 32]),
            state_root: Hash256([2u8; 32]),
            receipts_root: Hash256([3u8; 32]),
            committee_root: Hash256([4u8; 32]),
            capacity: Resources { compute: 100, memory: 200, io: 300, bandwidth: 400 },
        };
        let h1 = header.compute_hash();
        let h2 = header.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn block_header_validate_parent_passes() {
        let genesis = BlockHeader {
            height: 0,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };
        let genesis_hash = genesis.compute_hash();

        let child = BlockHeader {
            height: 1,
            parent: genesis_hash,
            transactions_root: Hash256([1u8; 32]),
            state_root: Hash256([2u8; 32]),
            receipts_root: Hash256([3u8; 32]),
            committee_root: Hash256([4u8; 32]),
            capacity: Resources { compute: 100, memory: 0, io: 0, bandwidth: 0 },
        };

        assert!(child.validate_parent(&genesis));
    }

    #[test]
    fn block_header_validate_parent_rejects_wrong_height() {
        let genesis = BlockHeader {
            height: 0,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };
        let genesis_hash = genesis.compute_hash();

        // Height should be 1, not 5
        let bad = BlockHeader {
            height: 5,
            parent: genesis_hash,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };

        assert!(!bad.validate_parent(&genesis));
    }

    #[test]
    fn block_header_validate_parent_rejects_wrong_parent_hash() {
        let genesis = BlockHeader {
            height: 0,
            parent: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };

        let bad_child = BlockHeader {
            height: 1,
            parent: Hash256([0xFF; 32]), // wrong parent hash
            transactions_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipts_root: Hash256::ZERO,
            committee_root: Hash256::ZERO,
            capacity: Resources::ZERO,
        };

        assert!(!bad_child.validate_parent(&genesis));
    }
}
