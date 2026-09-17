// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fuzz target for `Resources` decoding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use codec::CanonicalDecode;
use types::Resources;

fuzz_target!(|data: &[u8]| {
    let _ = Resources::decode(data);
});
