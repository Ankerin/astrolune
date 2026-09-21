// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Local demonstration daemon with durable block and execution-state recovery.

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::sync::{Arc, Mutex};

use node::{FullNodeService, NodeService, ProducerConfig};
use rpc::TcpRpcServer;

mod options;
mod status;

#[derive(Debug)]
enum DaemonError {
    Config(String),
    Io(String),
}

impl core::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Io(msg) => write!(f, "I/O or storage error: {msg}"),
        }
    }
}

impl std::error::Error for DaemonError {}

fn main() {
    if let Err(error) = run() {
        eprintln!("fatal: {error}");
        std::process::exit(match error {
            DaemonError::Config(_) => 2,
            DaemonError::Io(_) => 1,
        });
    }
}

fn run() -> Result<(), DaemonError> {
    let options = match options::parse(std::env::args_os().skip(1))? {
        options::Command::Help => {
            print!("{}", options::HELP);
            return Ok(());
        }
        options::Command::Version => {
            println!("daemon {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        options::Command::Run(options) => options,
    };
    let config = options.config;
    println!(
        "AstroLune local demonstration daemon v{}",
        env!("CARGO_PKG_VERSION")
    );
    println!("chain_id  : {}", config.chain_id);
    println!("data_dir  : {}", config.data_dir.display());
    if options.dry_run {
        println!("[dry-run] configuration valid; no files or listeners opened.");
        return Ok(());
    }

    std::fs::create_dir_all(&config.data_dir).map_err(io_error)?;
    let mut service = FullNodeService::open(
        ProducerConfig {
            chain_id: config.chain_id,
            ..ProducerConfig::default()
        },
        config.data_dir.join("chain.bin"),
    )
    .map_err(io_error)?;
    service.setup_committee(vec![consensus::CommitteeMember {
        id: types::ValidatorId::from_bytes([1; 32]),
        power: consensus::PotbWeight(100),
    }]);
    println!("next_height: {}", service.height());
    if options.max_blocks == Some(0) {
        println!("Recovery complete; no blocks requested.");
        return Ok(());
    }

    let rpc_service = Arc::new(Mutex::new(status::ChainStatus {
        chain_id: config.chain_id,
        checkpoint: service.storage().checkpoint().copied(),
    }));
    start_listeners(&config.network, rpc_service.clone())?;

    let mut produced = 0u64;
    while options.max_blocks.is_none_or(|max| produced < max) {
        let previous_height = service.height();
        for _ in 0..5 {
            service.advance().map_err(io_error)?;
        }
        if service.height()
            != previous_height
                .checked_add(1)
                .ok_or_else(|| io_error("height exhausted"))?
        {
            return Err(io_error("pipeline did not commit a block"));
        }
        let checkpoint = service
            .storage()
            .checkpoint()
            .copied()
            .ok_or_else(|| io_error("committed checkpoint missing"))?;
        rpc_service
            .lock()
            .map_err(|_| io_error("RPC status lock poisoned"))?
            .checkpoint = Some(checkpoint);
        produced += 1;
        println!(
            "block #{produced} committed at height {}",
            checkpoint.height
        );
        println!("state_root: {:?}", checkpoint.state_root);
        if options.max_blocks.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    println!("Stopped after {produced} durable blocks.");
    Ok(())
}

fn start_listeners(
    network: &config::NetworkConfig,
    rpc_service: Arc<Mutex<status::ChainStatus>>,
) -> Result<(), DaemonError> {
    // Bind both sockets before spawning workers or producing any blocks.
    let peer_manager = Arc::new(p2p::PeerManager::with_limit(network.max_peers));
    let peer_listener =
        p2p::TcpPeerListener::bind(&network.p2p_listen, peer_manager).map_err(io_error)?;
    let rpc_server = TcpRpcServer::bind(rpc_service, &network.rpc_listen).map_err(io_error)?;
    println!(
        "p2p       : {}",
        peer_listener.local_addr().map_err(io_error)?
    );
    println!("rpc       : {}", rpc_server.local_addr().map_err(io_error)?);
    let _p2p_handle = std::thread::Builder::new()
        .name("p2p-listener".into())
        .spawn(move || {
            if let Err(error) = peer_listener.run() {
                eprintln!("p2p listener: {error}");
            }
        })
        .map_err(io_error)?;
    let _rpc_handle = std::thread::Builder::new()
        .name("rpc-server".into())
        .spawn(move || {
            if let Err(error) = rpc_server.run() {
                eprintln!("rpc server: {error}");
            }
        })
        .map_err(io_error)?;

    Ok(())
}

fn io_error(error: impl std::fmt::Display) -> DaemonError {
    DaemonError::Io(error.to_string())
}
