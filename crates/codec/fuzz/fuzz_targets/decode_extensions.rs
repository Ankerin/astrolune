// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

#![no_main]

#[path = "../../../../tests/integration/tests/support/extensions.rs"]
mod extensions;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| { extensions::check(bytes); });
