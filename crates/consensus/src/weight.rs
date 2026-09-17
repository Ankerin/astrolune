// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Consensus weight and quorum calculations.

/// Consensus weight derived from finalized `PoTB` state.
///
/// Fixed-point arithmetic is mandatory; floating point must never influence
/// committee selection or quorum calculations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PotbWeight(pub u128);

/// Returns the minimum power that is strictly greater than two thirds.
#[must_use]
pub const fn quorum_power(total_power: u128) -> u128 {
    total_power.saturating_mul(2) / 3 + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_is_strictly_greater_than_two_thirds() {
        assert_eq!(quorum_power(100), 67);
        assert_eq!(quorum_power(3), 3);
        assert_eq!(quorum_power(0), 1);
    }
}
