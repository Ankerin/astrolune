// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Fetch and independently authenticate bounded finalized-state witnesses.

use crate::{CliError, contracts::read_bounded, wallet};
use codec::CanonicalDecode;
use rpc::CertifiedStateProof;
use std::{ffi::OsString, path::Path};
use types::StateKey;

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Wallet(value.to_string())
}

pub(super) fn run(command: &str, args: &[OsString]) -> Result<(), CliError> {
    if !(args.len() == 5 || (command == "state-proof" && args.len() == 6)) {
        return Err(error(
            "usage: cli state-proof|verify-state-proof <genesis> <validators> <key-hex> <minimum-height> <proof-file> [rpc-address]",
        ));
    }
    let genesis = genesis::Genesis::decode(&read_bounded(
        Path::new(&args[0]),
        genesis::MAX_GENESIS_BYTES,
    )?)
    .map_err(error)?;
    let registry = read_bounded(Path::new(&args[1]), genesis::MAX_GENESIS_VALIDATORS * 32)?;
    if registry.is_empty() || !registry.len().is_multiple_of(32) {
        return Err(error(
            "validator registry must contain consecutive 32-byte public keys",
        ));
    }
    let keys: Vec<[u8; 32]> = registry
        .chunks_exact(32)
        .map(|key| key.try_into().expect("exact chunk"))
        .collect();
    let key = parse_key(wallet::text(&args[2])?)?;
    let minimum = wallet::integer(&args[3])?;
    let path = Path::new(&args[4]);
    let proof = if command == "state-proof" {
        wallet::client(args.get(5))?
            .state_proof(&key)
            .map_err(error)?
    } else {
        CertifiedStateProof::from_bytes(&read_bounded(path, CertifiedStateProof::MAX_BYTES)?)
            .map_err(error)?
    };
    let value = proof.verify(&genesis, &keys, &key, minimum).map_err(|_| error("state proof authentication failed for the trusted genesis, registry, key or minimum height"))?;
    if command == "state-proof" {
        wallet::write_new(path, &proof.to_bytes().map_err(error)?)?;
    }
    println!(
        "verified_height: {}",
        proof.header.map_or(0, |header| header.height)
    );
    println!("state_root: {}", proof.root);
    match value {
        None => println!("value: absent"),
        Some(bytes) => {
            print!("value: 0x");
            for byte in bytes {
                print!("{byte:02x}");
            }
            println!();
        }
    }
    Ok(())
}

fn parse_key(text: &str) -> Result<StateKey, CliError> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() > state::MAX_STATE_KEY_BYTES * 2
        || !text.len().is_multiple_of(2)
        || !text.is_ascii()
    {
        return Err(error(
            "state key must contain at most 256 bytes of hexadecimal data",
        ));
    }
    let bytes = text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(error)?;
            u8::from_str_radix(pair, 16).map_err(error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StateKey(bytes))
}
