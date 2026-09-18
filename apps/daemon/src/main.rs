// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune` node daemon entry point.
//!
//! Demonstrates the node service lifecycle with real components:
//! 1. Load or create cryptographic keys
//! 2. Open persistent file-backed state storage
//! 3. Start P2P listener for peer connections
//! 4. Start JSON-RPC server for external clients
//! 5. Drive the consensus pipeline
//! 6. Shutdown cleanly

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use config::{NetworkConfig, NodeConfig, SecretRef};
use node::{BasicNodeService, NodeService};
use rpc::TcpRpcServer;
use state::FileBackedState;

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

Usage: daemon [--help | --version] [--dry-run]

Options:
  --dry-run  Validate configuration and print startup plan without running
  --help     Show this message
  --version  Show version
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

    match std::env::args().nth(1).as_deref() {
        None | Some("--help" | "-h") => {
            print!("{HELP}");
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("daemon {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some(arg) if arg.starts_with('-') && arg != "--dry-run" => {
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

    // Initialize persistent state storage
    let state_path = config.data_dir.join("state.dat");
    println!("\nOpening state database at {}...", state_path.display());
    let _state = FileBackedState::open(&state_path)
        .map_err(|e| DaemonError::Io(format!("failed to open state: {e}")))?;
    println!("  state root : {:?}", _state.root());

    // Initialize cryptographic provider
    let keystore = crypto::Ed25519Keystore::new();
    println!("  crypto     : {} keys loaded", keystore.len());

    // Initialize P2P peer manager
    let peer_manager = Arc::new(p2p::PeerManager::with_limit(config.network.max_peers));
    println!("  p2p peers  : {}/{} connected", peer_manager.peer_count(), config.network.max_peers);

    // Initialize RPC service
    let rpc_service = rpc::InMemoryRpcService::new(config.chain_id);
    let rpc_service = Arc::new(Mutex::new(rpc_service));

    println!("\nStarting services...");

    // Start P2P listener in background thread
    let p2p_addr = config.network.p2p_listen.clone();
    let p2p_mgr = peer_manager.clone();
    let _p2p_handle = std::thread::Builder::new()
        .name("p2p-listener".into())
        .spawn(move || {
            match p2p::TcpPeerListener::bind(&p2p_addr, p2p_mgr) {
                Ok(listener) => {
                    println!("  p2p  : listening on {p2p_addr}");
                    if let Err(e) = listener.run() {
                        eprintln!("  p2p  : listener error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("  p2p  : failed to bind: {e}");
                }
            }
        })
        .map_err(|e| DaemonError::Io(format!("failed to spawn p2p thread: {e}")))?;

    // Start RPC server in background thread
    let rpc_addr = config.network.rpc_listen.clone();
    let rpc_svc = rpc_service.clone();
    let _rpc_handle = std::thread::Builder::new()
        .name("rpc-server".into())
        .spawn(move || {
            match TcpRpcServer::bind(rpc_svc, &rpc_addr) {
                Ok(server) => {
                    println!("  rpc  : listening on {rpc_addr}");
                    if let Err(e) = server.run() {
                        eprintln!("  rpc  : server error: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("  rpc  : failed to bind: {e}");
                }
            }
        })
        .map_err(|e| DaemonError::Io(format!("failed to spawn rpc thread: {e}")))?;

    println!("\nAll services started.");

    // Drive the pipeline through one demo cycle
    let mut service = BasicNodeService::new();
    println!("\nRunning pipeline demo...");
    println!("  initial    : {:?}", service.current_state());
    loop {
        service
            .advance()
            .map_err(|e| DaemonError::Config(format!("{e:?}")))?;
        println!("  advanced to: {:?}", service.current_state());
        if service.current_state() == &node::NodeState::Idle {
            break;
        }
    }

    println!("\nDaemon shutting down cleanly.");
    Ok(())
}
