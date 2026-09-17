// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! `AstroLune` node daemon entry point.
//!
//! Demonstrates the node service lifecycle:
//! 1. Configure node
//! 2. Start and track pipeline stages
//! 3. Collect telemetry observations
//! 4. Shutdown cleanly

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;

use config::{NetworkConfig, NodeConfig, SecretRef};
use node::{
    AdaptiveCapacityController, BasicNodeService, CapacityController, CapacityObservation,
    NodeService,
};

/// Application error type.
#[derive(Debug)]
enum DaemonError {
    /// Configuration validation failure.
    Config(String),
}

impl core::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
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

    // Simulate node lifecycle
    let capacity = node::DEFAULT_CAPACITY;
    println!("\nStarting node service...");

    let mut service = BasicNodeService::new();

    // Drive the pipeline through all stages
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

    // Simulate capacity observations
    let controller = AdaptiveCapacityController::new(capacity, node::LATENCY_WINDOW);
    println!("\nCollecting capacity observations...");
    for i in 0..4 {
        let obs = CapacityObservation {
            used: types::Resources {
                compute: 400 + i * 100,
                memory: 256,
                io: 64,
                bandwidth: 256,
            },
            within_latency_target: true,
        };
        let new_cap = controller.next_capacity(capacity, &[obs]);
        println!(
            "  observation {i}: compute={} -> capacity={}",
            400 + i * 100,
            new_cap.compute
        );
    }

    println!("\nDaemon shutting down cleanly.");
    Ok(())
}
