// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune` operator and developer command-line entry point.
//!
//! Subcommands:
//! - `status` / `account` - read finalized state through RPC
//! - `keys` / `wallet-address` - derive a public wallet identity
//! - `sign-payment` / `inspect-payment` / `submit` - signed native payments
//! - `verify` — validate a node configuration
//! - `genesis <file>` — verify canonical genesis and derive the initial state root

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;

use config::{NetworkConfig, NodeConfig, SecretRef};

mod evidence;
mod network;
mod wallet;

/// Application error type.
#[derive(Debug)]
enum CliError {
    /// Genesis input or materialization failed.
    Genesis(String),
    /// Configuration validation failure.
    Config(String),
    /// Keystore operation failed.
    Keystore(keystore::KeystoreError),
    /// Wallet input, signing, or RPC operation failed.
    Wallet(String),
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Genesis(msg) => write!(f, "genesis error: {msg}"),
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Keystore(err) => write!(f, "keystore error: {err}"),
            Self::Wallet(msg) => write!(f, "wallet error: {msg}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<keystore::KeystoreError> for CliError {
    fn from(e: keystore::KeystoreError) -> Self {
        Self::Keystore(e)
    }
}

const HELP: &str = "\
AstroLune command-line interface

Usage: cli <command> [options]

Commands:
  status [rpc-address]  Read the node's finalized chain status
  account <address> [rpc-address]  Read finalized balance and next nonce
  wallet-address <seed-file>  Derive public wallet identity (alias: keys)
  sign-payment <chain-id> <seed-file> <recipient> <amount> <nonce> <expires-at> <output>
           Sign a payment offline and save it without overwriting any file
  inspect-payment <file>  Verify and display a signed payment offline
  submit <file> [rpc-address]  Send a saved payment once; acceptance is not finality
  evidence-create <genesis> <validators> <vote-a> <vote-b> <output>  Verify and save a double-vote proof
  evidence-verify <genesis> <validators> <proof>  Independently verify a double-vote proof
  verify   Validate a node configuration
  genesis <file>  Verify binary genesis and derive its initial state root
  devnet <directory> [validators] [--observer]  Create a local test network (default: 4)
  init-validator <genesis> <seed> <directory>  Provision a protected signing journal
  init-network-tls <directory> [peers]  Create independent TLS identities (default: 4)
  help     Show this message
  version  Show version

RPC defaults to ASTROLUNE_RPC_ADDR or 127.0.0.1:17331 (numeric IP:port).
Amounts are integer smallest units; expires-at is the last valid block height.
Seed files contain exactly 32 raw bytes. Never pass seed bytes on the command line.
";

fn main() {
    let result = run();
    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), CliError> {
    match std::env::args().nth(1).as_deref() {
        None | Some("help" | "--help" | "-h") => {
            print!("{HELP}");
            Ok(())
        }
        Some("version" | "--version" | "-V") => {
            println!("cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(
            command @ ("status" | "account" | "keys" | "wallet-address" | "sign-payment"
            | "inspect-payment" | "submit"),
        ) => wallet::run(command, &std::env::args_os().skip(2).collect::<Vec<_>>()),
        Some("verify") => cmd_verify(),
        Some(command @ ("evidence-create" | "evidence-verify")) => evidence::run(command),
        Some("genesis") => cmd_genesis(),
        Some("devnet") => network::devnet(),
        Some("init-validator") => network::init_validator(),
        Some("init-network-tls") => network::init_network_tls(),
        Some(cmd) => {
            eprintln!("unknown command: {cmd}\n\n{HELP}");
            std::process::exit(2);
        }
    }
}

/// Validate bounded genesis input and report commitments without changing state.
fn cmd_genesis() -> Result<(), CliError> {
    use codec::CanonicalDecode;
    use std::io::Read;

    let mut arguments = std::env::args_os().skip(2);
    let path = arguments
        .next()
        .filter(|_| arguments.next().is_none())
        .ok_or_else(|| CliError::Genesis("usage: cli genesis <file>".into()))?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(genesis::MAX_GENESIS_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|error| CliError::Genesis(error.to_string()))?;
    let genesis =
        genesis::Genesis::decode(&bytes).map_err(|error| CliError::Genesis(error.to_string()))?;
    let commitment = genesis
        .commitment()
        .map_err(|error| CliError::Genesis(error.to_string()))?;
    let state = genesis
        .materialize()
        .map_err(|error| CliError::Genesis(error.to_string()))?;
    println!("chain_id: {}", genesis.chain_id);
    println!("genesis_hash: {commitment}");
    println!("state_root: {}", state.root());
    println!("validators: {}", genesis.validators.len());
    println!("allocations: {}", genesis.allocations.len());
    Ok(())
}

/// Validate a node configuration.
fn cmd_verify() -> Result<(), CliError> {
    let data_dir = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "node-data".into());

    let config = NodeConfig {
        chain_id: 7,
        data_dir: PathBuf::from(&data_dir),
        validator_key: Some(
            SecretRef::new("default-key").map_err(|e| CliError::Config(format!("{e:?}")))?,
        ),
        network: NetworkConfig {
            p2p_listen: "127.0.0.1:17330".into(),
            rpc_listen: "127.0.0.1:17331".into(),
            max_peers: 32,
        },
    };

    config
        .validate()
        .map_err(|e| CliError::Config(format!("{e:?}")))?;

    println!("Configuration is valid");
    println!("  chain_id  : {}", config.chain_id);
    println!("  data_dir  : {}", config.data_dir.display());
    println!("  p2p       : {}", config.network.p2p_listen);
    println!("  rpc       : {}", config.network.rpc_listen);
    println!("  max_peers : {}", config.network.max_peers);
    Ok(())
}
