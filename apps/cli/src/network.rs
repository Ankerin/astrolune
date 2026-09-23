// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Explicit reference-network provisioning; existing journals are never overwritten.

use crate::CliError;
use codec::{CanonicalDecode, CanonicalEncode};
use crypto::blake2s::{blake2s, ed25519_public_key};
use genesis::{Allocation, Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use p2p::provisioning::TransportAuthority;
use std::{
    fmt::Write as _,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use types::{Address, Resources, ValidatorId};

fn error(value: impl std::fmt::Display) -> CliError {
    CliError::Config(value.to_string())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(error)?;
    file.write_all(bytes).map_err(error)?;
    file.sync_all().map_err(error)
}

fn daemon_command() -> String {
    let daemon = std::env::current_exe().ok().and_then(|path| {
        path.parent().map(|parent| {
            parent.join(if cfg!(windows) {
                "daemon.exe"
            } else {
                "daemon"
            })
        })
    });
    if let Some(path) = daemon.filter(|path| path.is_file()) {
        let prefix = if cfg!(windows) { "& " } else { "" };
        format!("{prefix}\"{}\"", path.display())
    } else {
        "cargo run -p daemon --".into()
    }
}

pub(crate) fn devnet() -> Result<(), CliError> {
    let mut args = std::env::args_os().skip(2);
    let directory = PathBuf::from(
        args.next()
            .ok_or_else(|| error("usage: cli devnet <new-directory> [validators]"))?,
    );
    let count: u8 = args.next().map_or(Ok(4), |value| {
        value
            .to_str()
            .ok_or_else(|| error("invalid validator count"))?
            .parse()
            .map_err(error)
    })?;
    if args.next().is_some() || !(1..=32).contains(&count) {
        return Err(error("validator count must be 1..32"));
    }
    std::fs::create_dir(&directory).map_err(error)?;
    let authority = TransportAuthority::generate().map_err(error)?;
    let keys: Vec<_> = (1..=count)
        .map(|index| ed25519_public_key(&[index; 32]))
        .collect();
    let mut validators: Vec<_> = keys
        .iter()
        .map(|key| GenesisValidator {
            id: ValidatorId(blake2s(key).0),
            weight: 1,
        })
        .collect();
    validators.sort_by_key(|validator| validator.id);
    let wallet = Address(blake2s(&ed25519_public_key(&[240; 32])).0);
    let genesis = Genesis {
        version: 1,
        chain_id: 42,
        capacity: Resources {
            compute: 1_000_000,
            memory: 1_000_000,
            io: 1_000_000,
            bandwidth: 1_000_000,
        },
        committee_size: usize::from(count),
        rotation_count: 1,
        runtime_version: 1,
        validators,
        allocations: vec![Allocation {
            address: wallet,
            amount: 1_000_000_000,
        }],
    };
    let context = SigningContext {
        chain_id: genesis.chain_id,
        genesis: genesis.commitment().map_err(error)?,
    };
    write_new(&directory.join("genesis.bin"), &genesis.to_bytes())?;
    write_new(&directory.join("validators.bin"), &keys.concat())?;
    write_new(&directory.join("wallet.seed"), &[240; 32])?;
    let mut instructions = String::from(
        "Local reference network. CONSENSUS AND WALLET KEYS ARE PUBLIC TEST FIXTURES.\nNever use these keys or this genesis for valuable funds.\nTransport keys are independent random secrets, valid for one year.\n\nStart each command in a separate terminal from the repository root:\n\n",
    );
    for index in 1..=count {
        let data = directory.join(format!("node-{index}"));
        std::fs::create_dir(&data).map_err(error)?;
        provision_tls(&authority, &data.join("tls"), &format!("node-{index}"))?;
        write_new(&data.join("validator.seed"), &[index; 32])?;
        drop(DurableSigner::create_protected(
            data.join("signing.journal"),
            context,
            [index; 32],
        )?);
        let peers: Vec<_> = (1..=count)
            .filter(|peer| *peer != index)
            .map(|peer| format!("127.0.0.1:{}", 18000 + u16::from(peer)))
            .collect();
        let peer_flag = if peers.is_empty() {
            String::new()
        } else {
            format!(" --peers {}", peers.join(","))
        };
        writeln!(instructions, "{} --run --genesis \"{}\" --validators \"{}\" --validator-key \"{}\" --tls-dir \"{}\" --data-dir \"{}\" --p2p-listen 127.0.0.1:{} --rpc-listen 127.0.0.1:{}{peer_flag}", daemon_command(), directory.join("genesis.bin").display(), directory.join("validators.bin").display(), data.join("validator.seed").display(), data.join("tls").display(), data.display(), 18000 + u16::from(index), 19000 + u16::from(index)).map_err(error)?;
    }
    write_new(&directory.join("START.txt"), instructions.as_bytes())?;
    println!(
        "Created {count} reference validators in {}",
        directory.display()
    );
    println!("Consensus and wallet keys are PUBLIC TEST FIXTURES; TLS keys are random secrets.");
    println!("Funded test wallet: {wallet}");
    println!("Start commands: {}", directory.join("START.txt").display());
    Ok(())
}

fn provision_tls(
    authority: &TransportAuthority,
    directory: &Path,
    name: &str,
) -> Result<(), CliError> {
    let identity = authority.issue(name).map_err(error)?;
    std::fs::create_dir(directory).map_err(error)?;
    write_new(&directory.join("ca.der"), &identity.ca_der)?;
    write_new(&directory.join("cert.der"), &identity.certificate_der)?;
    write_new(&directory.join("key.der"), &identity.private_key_der)
}

pub(crate) fn init_network_tls() -> Result<(), CliError> {
    let mut args = std::env::args_os().skip(2);
    let directory = PathBuf::from(
        args.next()
            .ok_or_else(|| error("usage: cli init-network-tls <new-directory> [peers]"))?,
    );
    let count: u8 = args.next().map_or(Ok(4), |value| {
        value
            .to_str()
            .ok_or_else(|| error("invalid peer count"))?
            .parse()
            .map_err(error)
    })?;
    if args.next().is_some() || !(1..=32).contains(&count) {
        return Err(error("peer count must be 1..32"));
    }
    std::fs::create_dir(&directory).map_err(error)?;
    let authority = TransportAuthority::generate().map_err(error)?;
    for index in 1..=count {
        let name = format!("peer-{index}");
        provision_tls(&authority, &directory.join(&name), &name)?;
    }
    write_new(&directory.join("README.txt"), b"AstroLune mutual TLS identities.\nGive each peer only its own peer-N directory; keep key.der secret.\nStart with --tls-dir <peer-N>. Certificates expire one year after generation.\nThe CA private key is not saved. To add peers or renew, provision a new bundle and coordinate a trust-root replacement on all peers, or use an externally managed CA.\nConsensus seeds and signing journals are unrelated and must be preserved.\n")?;
    println!(
        "Created {count} independent TLS identities in {}",
        directory.display()
    );
    Ok(())
}

pub(crate) fn init_validator() -> Result<(), CliError> {
    let args: Vec<_> = std::env::args_os().skip(2).collect();
    if args.len() != 3 {
        return Err(error(
            "usage: cli init-validator <genesis> <raw-32-byte-seed> <directory>",
        ));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&args[0])
        .map_err(error)?
        .take(genesis::MAX_GENESIS_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(error)?;
    let genesis = Genesis::decode(&bytes).map_err(error)?;
    let mut seed = zeroize::Zeroizing::new(Vec::new());
    std::fs::File::open(&args[1])
        .map_err(error)?
        .take(33)
        .read_to_end(&mut seed)
        .map_err(error)?;
    let seed = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(seed.as_slice())
            .map_err(|_| error("seed must be exactly 32 bytes"))?,
    );
    let id = ValidatorId(blake2s(&ed25519_public_key(&seed)).0);
    if !genesis
        .validators
        .iter()
        .any(|validator| validator.id == id)
    {
        return Err(error("key is absent from genesis"));
    }
    let directory = Path::new(&args[2]);
    std::fs::create_dir_all(directory).map_err(error)?;
    if directory.join("chain.bin").exists() || directory.join("consensus-cache.bin").exists() {
        return Err(error(
            "refusing to provision a journal over existing chain/voting state; restore the original journal",
        ));
    }
    drop(DurableSigner::create_protected(
        directory.join("signing.journal"),
        SigningContext {
            chain_id: genesis.chain_id,
            genesis: genesis.commitment().map_err(error)?,
        },
        *seed,
    )?);
    println!(
        "Protected journal created for {id:?} in {}",
        directory.display()
    );
    Ok(())
}
