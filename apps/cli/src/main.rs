// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune` operator and developer command-line entry point.
//!
//! Subcommands:
//! - `status` — display chain status summary
//! - `keys` — create a mock keystore and show registered key info
//! - `verify` — validate a node configuration
//! - `genesis <file>` — verify canonical genesis and derive the initial state root

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;

use config::{NetworkConfig, NodeConfig, SecretRef};
use keystore::{KeyPurpose, MockKeystore, Signer};
use types::{Hash256, ValidatorId};

/// Application error type.
#[derive(Debug)]
enum CliError {
    /// Genesis input or materialization failed.
    Genesis(String),
    /// Configuration validation failure.
    Config(String),
    /// Keystore operation failed.
    Keystore(keystore::KeystoreError),
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Genesis(msg) => write!(f, "genesis error: {msg}"),
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Keystore(err) => write!(f, "keystore error: {err}"),
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
  status   Show chain status summary
  keys     Create and query a mock keystore
  verify   Validate a node configuration
  genesis <file>  Verify binary genesis and derive its initial state root
  help     Show this message
  version  Show version
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
        None | Some("--help" | "-h") => {
            print!("{HELP}");
            Ok(())
        }
        Some("--version" | "-V") => {
            println!("cli {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("status") => cmd_status(),
        Some("keys") => cmd_keys(),
        Some("verify") => cmd_verify(),
        Some("genesis") => cmd_genesis(),
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

/// Display a chain status summary.
#[allow(clippy::unnecessary_wraps)]
fn cmd_status() -> Result<(), CliError> {
    let chain_id = parse_chain_id_arg();
    let rpc_addr = parse_rpc_arg();

    println!("AstroLune Node Status");
    println!("====================");
    println!("  chain_id : {chain_id}");
    println!("  rpc      : {rpc_addr}");
    println!("  version  : {}", env!("CARGO_PKG_VERSION"));
    println!("  status   : offline (engineering baseline)");
    Ok(())
}

/// Create a mock keystore and demonstrate key operations.
fn cmd_keys() -> Result<(), CliError> {
    let mut ks = MockKeystore::new();

    let entries = [
        ("validator-primary", [1u8; 32], KeyPurpose::Consensus),
        ("validator-secondary", [2u8; 32], KeyPurpose::Consensus),
        ("p2p-signing", [3u8; 32], KeyPurpose::Network),
    ];

    for (id, bytes, purpose) in &entries {
        ks.insert(*id, ValidatorId::from_bytes(*bytes), *purpose);
    }

    println!("Key Handles");
    println!("===========");

    // Verify each key can be looked up via the Signer trait
    for (id, expected_vid, purpose) in &entries {
        let handle = keystore::KeyHandle {
            id: (*id).into(),
            purpose: *purpose,
        };
        let vid = ks.validator_id(&handle)?;
        assert_eq!(vid, ValidatorId::from_bytes(*expected_vid));

        let purpose_str = match purpose {
            KeyPurpose::Consensus => "consensus",
            KeyPurpose::Network => "network",
            KeyPurpose::Service => "service",
            KeyPurpose::Wallet => "wallet",
        };
        println!("  {id:24} ({purpose_str})");
    }

    // Demonstrate consensus signing
    let handle = keystore::KeyHandle {
        id: "validator-primary".into(),
        purpose: KeyPurpose::Consensus,
    };
    let pos = keystore::SigningPosition {
        height: 1,
        round: 0,
        phase: 0,
    };
    let msg = Hash256::from_bytes([42; 32]);
    let sig = ks.sign_consensus(&handle.clone(), pos, msg)?;
    println!("\n  consensus sig (height=1, round=0): {} bytes", sig.len());

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

/// Parse `chain_id` from environment or default to 7.
fn parse_chain_id_arg() -> u32 {
    std::env::var("ASTROLUNE_CHAIN_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7)
}

/// Parse RPC address from environment or default.
fn parse_rpc_arg() -> String {
    std::env::var("ASTROLUNE_RPC_ADDR").unwrap_or_else(|_| "127.0.0.1:17331".into())
}
