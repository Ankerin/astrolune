// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fuzz target for `Transaction` decoding.
//!
//! Feeds random byte slices into the canonical decoder to ensure it never
//! panics and only returns `DecodeError` variants. Run with:
//!
//! ```sh
//! cargo fuzz run decode_transaction
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use codec::CanonicalDecode;
use types::Transaction;

fuzz_target!(|data: &[u8]| {
    // The decoder must never panic on arbitrary input. It either succeeds
    // or returns a well-defined DecodeError.
    let _ = Transaction::decode(data);
});
