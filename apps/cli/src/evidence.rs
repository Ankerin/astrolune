// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Independent verification against a supplied trusted fixed genesis registry.

use crate::CliError;
use codec::CanonicalDecode;
use consensus::{
    AuthenticatedCommittee, Committee, CommitteeMember, DoubleVoteEvidence, PotbWeight, Vote,
};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Config(value.to_string())
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(error)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    if bytes.len() > maximum {
        return Err(error("input exceeds its size limit"));
    }
    Ok(bytes)
}
fn context(genesis: &Path, keys: &Path, height: u64) -> Result<AuthenticatedCommittee, CliError> {
    let genesis =
        genesis::Genesis::decode(&read(genesis, genesis::MAX_GENESIS_BYTES)?).map_err(error)?;
    genesis.commitment().map_err(error)?;
    if genesis.committee_size != genesis.validators.len() {
        return Err(error(
            "evidence CLI requires the fixed full-genesis committee profile",
        ));
    }
    let bytes = read(keys, consensus::MAX_COMMITTEE_MEMBERS * 32)?;
    if bytes.len() != genesis.validators.len() * 32 {
        return Err(error("registry length does not match genesis"));
    }
    let keys: Vec<_> = bytes
        .chunks_exact(32)
        .map(|key| <[u8; 32]>::try_from(key).expect("complete key"))
        .collect();
    let committee = Committee {
        height,
        members: genesis
            .validators
            .iter()
            .map(|member| CommitteeMember {
                id: member.id,
                power: PotbWeight(member.weight),
            })
            .collect(),
    };
    AuthenticatedCommittee::new(genesis.chain_id, &committee, &keys).map_err(error)
}

pub(super) fn run(command: &str) -> Result<(), CliError> {
    let args: Vec<OsString> = std::env::args_os().skip(2).collect();
    let proof = match (command, args.as_slice()) {
        ("evidence-create", [genesis, keys, a, b, output]) => {
            let a = Vote::decode(&read(Path::new(a), 186)?).map_err(error)?;
            let b = Vote::decode(&read(Path::new(b), 186)?).map_err(error)?;
            let context = context(Path::new(genesis), Path::new(keys), a.height)?;
            let proof = DoubleVoteEvidence::from_votes(&context, a, b).map_err(error)?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(output)
                .map_err(error)?;
            file.write_all(&proof.encode())
                .and_then(|()| file.sync_all())
                .map_err(error)?;
            proof
        }
        ("evidence-verify", [genesis, keys, path]) => {
            let proof = DoubleVoteEvidence::decode(&read(
                Path::new(path),
                DoubleVoteEvidence::ENCODED_LEN,
            )?)
            .map_err(error)?;
            proof
                .verify(&context(
                    Path::new(genesis),
                    Path::new(keys),
                    proof.height(),
                )?)
                .map_err(error)?;
            proof
        }
        _ => return Err(error("invalid evidence command arguments; run cli help")),
    };
    println!("evidence_id: {}", proof.id());
    println!("offence_id: {}", proof.offence_id());
    println!("validator: {}", proof.voter());
    println!("height: {}", proof.height());
    println!("round: {}", proof.votes().0.round);
    println!("phase: {:?}", proof.votes().0.phase);
    println!("verification: valid double vote (no automatic on-chain penalty)");
    Ok(())
}
