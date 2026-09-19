// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune` node daemon entry point.
//!
//! Demonstrates the node service lifecycle with real components:
//! 1. Load or create cryptographic keys
//! 2. Initialize the block production pipeline
//! 3. Start P2P listener for peer connections
//! 4. Start JSON-RPC server for external clients
//! 5. Run the consensus and execution pipeline
//! 6. Shutdown cleanly

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::too_many_lines)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use config::{NetworkConfig, NodeConfig, SecretRef};
use node::{FullNodeService, NodeService, ProducerConfig};
use rpc::TcpRpcServer;

/// Application error type.
#[derive(Debug)]
enum DaemonError {
    /// Configuration validation failure.
    Config(String),
    /// IO or storage error.
    Io(String),
}

impl core::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for DaemonError {}

const HELP: &str = "\
AstroLune node daemon

Usage: daemon [--help | --version] [--dry-run] [--blocks N]

Options:
  --dry-run    Validate configuration and print startup plan without running
  --blocks N   Produce N blocks then exit (default: run indefinitely)
  --help       Show this message
  --version    Show version
";

fn main() {
    let result = run();
    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), DaemonError> {
    let dry_run = std::env::args().any(|a| a == "--dry-run");
    let max_blocks = parse_max_blocks();

    match std::env::args().nth(1).as_deref() {
        None | Some("--help" | "-h") => {
            print!("{HELP}");
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("daemon {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some(arg) if arg.starts_with('-') && arg != "--dry-run" && arg != "--blocks" => {
            eprintln!("unknown flag: {arg}\n\n{HELP}");
            std::process::exit(2);
        }
        _ => {}
    }

    // Build and validate configuration
    let config = NodeConfig {
        chain_id: 7,
        data_dir: PathBuf::from("node-data"),
        validator_key: Some(
            SecretRef::new("validator-primary")
                .map_err(|e| DaemonError::Config(format!("{e:?}")))?,
        ),
        network: NetworkConfig {
            p2p_listen: "127.0.0.1:17330".into(),
            rpc_listen: "127.0.0.1:17331".into(),
            max_peers: 32,
        },
    };
    config
        .validate()
        .map_err(|e| DaemonError::Config(format!("{e:?}")))?;

    println!("AstroLune Daemon v{}", env!("CARGO_PKG_VERSION"));
    println!("================================");
    println!("chain_id  : {}", config.chain_id);
    println!("data_dir  : {}", config.data_dir.display());
    println!("p2p       : {}", config.network.p2p_listen);
    println!("rpc       : {}", config.network.rpc_listen);
    println!("max_peers : {}", config.network.max_peers);

    if dry_run {
        println!("\n[dry-run] configuration valid, exiting.");
        return Ok(());
    }

    // Initialize the block production pipeline
    let producer_config = ProducerConfig {
        chain_id: config.chain_id,
        ..ProducerConfig::default()
    };
    let mut full_service = FullNodeService::new(producer_config);

    // Set up a single-validator committee for local testing
    let validator_id = types::ValidatorId::from_bytes([1u8; 32]);
    full_service.setup_committee(vec![consensus::CommitteeMember {
        id: validator_id,
        power: consensus::PotbWeight(100),
    }]);

    println!("\nInitialized services:");
    println!("  height   : {}", full_service.height());
    println!(
        "  committee: {} members",
        full_service.committee().map_or(0, |c| c.members.len())
    );

    // Initialize P2P peer manager
    let peer_manager = Arc::new(p2p::PeerManager::with_limit(config.network.max_peers));
    println!(
        "  p2p peers: {}/{} connected",
        peer_manager.peer_count(),
        config.network.max_peers
    );

    // Initialize RPC service
    let rpc_service = rpc::InMemoryRpcService::new(config.chain_id);
    let rpc_service = Arc::new(Mutex::new(rpc_service));

    println!("\nStarting services...");

    // Start P2P listener in background thread
    let p2p_addr = config.network.p2p_listen.clone();
    let p2p_mgr = peer_manager.clone();
    let _p2p_handle = std::thread::Builder::new()
        .name("p2p-listener".into())
        .spawn(
            move || match p2p::TcpPeerListener::bind(&p2p_addr, p2p_mgr) {
                Ok(listener) => {
                    println!("  p2p  : listening on {p2p_addr}");
                    if let Err(e) = listener.run() {
                        eprintln!("  p2p  : listener error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("  p2p  : failed to bind: {e}");
                }
            },
        )
        .map_err(|e| DaemonError::Io(format!("failed to spawn p2p thread: {e}")))?;

    // Start RPC server in background thread
    let rpc_addr = config.network.rpc_listen.clone();
    let rpc_svc = rpc_service.clone();
    let _rpc_handle = std::thread::Builder::new()
        .name("rpc-server".into())
        .spawn(move || match TcpRpcServer::bind(rpc_svc, &rpc_addr) {
            Ok(server) => {
                println!("  rpc  : listening on {rpc_addr}");
                if let Err(e) = server.run() {
                    eprintln!("  rpc  : server error: {e}");
                }
            }
            Err(e) => {
                eprintln!("  rpc  : failed to bind: {e}");
            }
        })
        .map_err(|e| DaemonError::Io(format!("failed to spawn rpc thread: {e}")))?;

    println!("\nAll services started.");
    println!("\nRunning block production pipeline...");

    // Run the block production loop
    let mut blocks_produced = 0u64;
    loop {
        // Check if we've reached the block limit
        if let Some(max) = max_blocks
            && blocks_produced >= max
        {
            println!("\nReached block limit ({max}), shutting down.");
            break;
        }

        // Run one full pipeline cycle: Idle -> Proposing -> Voting -> Executing -> Committing -> Idle
        for _ in 0..5 {
            full_service
                .advance()
                .map_err(|e| DaemonError::Config(format!("{e:?}")))?;
        }

        blocks_produced += 1;
        println!(
            "  block #{} produced at height {}",
            blocks_produced,
            full_service.height() - 1
        );

        // Print state summary
        if let Some(checkpoint) = full_service.storage().checkpoint() {
            println!("    state_root: {:?}", checkpoint.state_root);
        }

        // Brief pause between blocks in demo mode
        if max_blocks.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    println!("\nDaemon shutting down cleanly.");
    Ok(())
}

/// Parses the maximum number of blocks to produce from command line arguments.
fn parse_max_blocks() -> Option<u64> {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if args[i] == "--blocks"
            && let Some(val) = args.get(i + 1)
        {
            return val.parse().ok();
        }
    }
    None
}
