// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

#![no_main]

use consensus::{FinalityCertificate, Vote};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(vote) = Vote::decode(data) {
        assert_eq!(vote.encode().as_slice(), data);
    }
    if let Ok(certificate) = FinalityCertificate::decode(data) {
        assert_eq!(certificate.encode().unwrap(), data);
    }
});
