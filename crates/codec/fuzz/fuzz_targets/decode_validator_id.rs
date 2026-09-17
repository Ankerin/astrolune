// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fuzz target for `ValidatorId` decoding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use codec::CanonicalDecode;
use types::ValidatorId;

fuzz_target!(|data: &[u8]| {
    let _ = ValidatorId::decode(data);
});
