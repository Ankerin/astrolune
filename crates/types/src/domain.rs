// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Protocol domain separators used for domain hashing and signing.
//!
//! Each tag is a unique ASCII string that prevents cross-domain signature or
//! hash reuse. Tags are prefixed with the protocol name and version to avoid
//! collisions with other systems.

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
