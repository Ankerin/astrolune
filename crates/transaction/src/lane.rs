// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Execution lane classification for transactions.

/// Execution lane assigned from the canonical transaction payload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransactionLane {
    /// Account payment operations.
    Payments,
    /// Rust smart-contract deployment and calls.
    Contracts,
    /// Consensus-governed system operations.
    System,
}

impl TransactionLane {
    /// Determines the lane from the transaction payload.
    ///
    /// The current heuristic is simple: empty payload = system, short payload
    /// = payment, otherwise = contract. This will be replaced by a proper
    /// payload-type prefix in the protocol encoding.
    #[must_use]
    pub fn from_payload(payload: &[u8]) -> Self {
        match payload.len() {
            0 => Self::System,
            1..=128 => Self::Payments,
            _ => Self::Contracts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_system_for_empty_payload() {
        assert_eq!(TransactionLane::from_payload(&[]), TransactionLane::System);
    }

    #[test]
    fn lane_payments_for_short_payload() {
        assert_eq!(
            TransactionLane::from_payload(&[0; 64]),
            TransactionLane::Payments
        );
    }

    #[test]
    fn lane_contracts_for_long_payload() {
        assert_eq!(
            TransactionLane::from_payload(&[0; 256]),
            TransactionLane::Contracts
        );
    }
}
