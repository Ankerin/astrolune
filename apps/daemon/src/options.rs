// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Strict daemon arguments, parsed before opening files or sockets.

use std::{collections::BTreeSet, ffi::OsString, net::SocketAddr, path::PathBuf};

use config::{NetworkConfig, NodeConfig};

use crate::DaemonError;

pub(crate) const HELP: &str = "\
AstroLune node daemon

Usage: daemon [--help | --version] [--run | --dry-run | --blocks N] [options]

Options:
  --run              Run continuously
  --dry-run          Validate configuration/genesis without writing or listening
  --blocks N         Advance N block heights, then exit (0: recovery only)
  --data-dir PATH    Durable chain directory (default: node-data)
  --genesis PATH     Trusted binary genesis (required on each genesis-chain start)
  --validators PATH  Public keys file; enables certified fixed-committee networking
  --validator-key PATH  Raw 32-byte seed; requires an existing signing.journal
  --observer        Verify and relay finalized blocks without a consensus key
  --tls-dir PATH    Network ca.der, cert.der and PKCS#8 key.der (required for peers)
  --allow-plaintext  Explicit insecure loopback-only development transport
  --peers ADDR,...   Configured peers to poll and reconnect (up to 32)
  --round-timeout-ms N  Initial BFT step deadline (100..60000; default 1000)
  --p2p-listen ADDR  Peer socket address (default: 127.0.0.1:17330)
  --rpc-listen ADDR  RPC socket address (default: 127.0.0.1:17331)
  --help             Show this message
  --version          Show version

Without --validators, finality remains a local demonstration.
";

pub(crate) enum Command {
    Help,
    Version,
    Run(Box<Options>),
}

pub(crate) struct Options {
    pub config: NodeConfig,
    pub dry_run: bool,
    pub max_blocks: Option<u64>,
    pub genesis: Option<PathBuf>,
    pub validators: Option<PathBuf>,
    pub validator_key: Option<PathBuf>,
    pub observer: bool,
    pub tls_dir: Option<PathBuf>,
    pub allow_plaintext: bool,
    pub peers: Vec<SocketAddr>,
    pub round_timeout_ms: u64,
}

pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, DaemonError> {
    let mut args = args.into_iter().peekable();
    if args.peek().is_none() {
        return Ok(Command::Help);
    }
    let mut options = Options {
        config: NodeConfig {
            chain_id: 7,
            data_dir: PathBuf::from("node-data"),
            validator_key: None,
            network: NetworkConfig {
                p2p_listen: "127.0.0.1:17330".into(),
                rpc_listen: "127.0.0.1:17331".into(),
                max_peers: 32,
            },
        },
        dry_run: false,
        max_blocks: None,
        genesis: None,
        validators: None,
        validator_key: None,
        observer: false,
        tls_dir: None,
        allow_plaintext: false,
        peers: Vec::new(),
        round_timeout_ms: 1000,
    };
    let mut seen = BTreeSet::new();
    while let Some(arg) = args.next() {
        let flag = arg.to_str().ok_or_else(|| invalid("non-UTF-8 option"))?;
        if !seen.insert(flag.to_owned()) {
            return Err(invalid(&format!("duplicate option: {flag}")));
        }
        match flag {
            "--help" | "-h" | "--version" | "-V" => {
                if seen.len() != 1 || args.peek().is_some() {
                    return Err(invalid("help and version must be used alone"));
                }
                return Ok(if matches!(flag, "--help" | "-h") {
                    Command::Help
                } else {
                    Command::Version
                });
            }
            "--dry-run" => options.dry_run = true,
            "--allow-plaintext" => options.allow_plaintext = true,
            "--observer" => options.observer = true,
            "--run" => {}
            "--blocks" | "--data-dir" | "--genesis" | "--p2p-listen" | "--rpc-listen"
            | "--validators" | "--validator-key" | "--tls-dir" | "--peers"
            | "--round-timeout-ms" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid(&format!("missing value for {flag}")))?;
                if value.is_empty() || value.to_str().is_some_and(|text| text.starts_with("--")) {
                    return Err(invalid(&format!("missing value for {flag}")));
                }
                if flag == "--data-dir" {
                    options.config.data_dir = PathBuf::from(value);
                    continue;
                }
                if flag == "--genesis" {
                    options.genesis = Some(PathBuf::from(value));
                    continue;
                }
                if flag == "--validators" {
                    options.validators = Some(PathBuf::from(value));
                    continue;
                }
                if flag == "--validator-key" {
                    options.validator_key = Some(PathBuf::from(value));
                    continue;
                }
                if flag == "--tls-dir" {
                    options.tls_dir = Some(PathBuf::from(value));
                    continue;
                }
                let value = value
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 option value"))?;
                parse_value(&mut options, flag, value)?;
            }
            _ => return Err(invalid(&format!("unknown option: {flag}"))),
        }
    }
    if seen.contains("--run") && (options.dry_run || options.max_blocks.is_some()) {
        return Err(invalid(
            "--run cannot be combined with --dry-run or --blocks",
        ));
    }
    validate_network(&options, &seen)?;
    options
        .config
        .validate()
        .map_err(|error| invalid(&format!("{error:?}")))?;
    Ok(Command::Run(Box::new(options)))
}

fn validate_network(options: &Options, seen: &BTreeSet<String>) -> Result<(), DaemonError> {
    if options.validators.is_some() {
        if options.genesis.is_none() || (!options.observer && options.validator_key.is_none()) {
            return Err(invalid(
                "--validators requires --genesis and either --validator-key or --observer",
            ));
        }
        if options.observer
            && (options.validator_key.is_some() || seen.contains("--round-timeout-ms"))
        {
            return Err(invalid(
                "--observer cannot use --validator-key or BFT round deadlines",
            ));
        }
        if options.tls_dir.is_some() == options.allow_plaintext {
            return Err(invalid(
                "choose --tls-dir or explicit loopback-only --allow-plaintext",
            ));
        }
        if options.allow_plaintext {
            let listener: SocketAddr = options
                .config
                .network
                .p2p_listen
                .parse()
                .map_err(|_| invalid("invalid P2P listener"))?;
            if !listener.ip().is_loopback()
                || options.peers.iter().any(|peer| !peer.ip().is_loopback())
            {
                return Err(invalid(
                    "plaintext transport requires loopback listeners and peers",
                ));
            }
        }
    } else if options.validator_key.is_some()
        || options.observer
        || options.tls_dir.is_some()
        || options.allow_plaintext
        || !options.peers.is_empty()
        || seen.contains("--round-timeout-ms")
    {
        return Err(invalid(
            "observer mode, validator keys, TLS, peers, and BFT deadlines require --validators",
        ));
    }
    Ok(())
}

fn parse_value(options: &mut Options, flag: &str, value: &str) -> Result<(), DaemonError> {
    if flag == "--peers" {
        let mut peers = BTreeSet::new();
        for address in value.split(',') {
            let address: SocketAddr = address
                .parse()
                .map_err(|_| invalid("peers require IP addresses and ports"))?;
            if address.port() == 0
                || address.ip().is_unspecified()
                || !peers.insert(address)
                || peers.len() > 32
            {
                return Err(invalid("invalid, duplicate, or excessive peers"));
            }
        }
        options.peers = peers.into_iter().collect();
    } else if flag == "--round-timeout-ms" {
        options.round_timeout_ms = value
            .parse()
            .map_err(|_| invalid("invalid round timeout"))?;
        if !(100..=60_000).contains(&options.round_timeout_ms) {
            return Err(invalid("round timeout must be 100..60000 milliseconds"));
        }
    } else if flag == "--blocks" {
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid("--blocks requires an unsigned integer"));
        }
        options.max_blocks = Some(
            value
                .parse()
                .map_err(|_| invalid("--blocks is out of range"))?,
        );
    } else {
        let address: SocketAddr = value
            .parse()
            .map_err(|_| invalid("listener requires an IP address and port"))?;
        if flag == "--p2p-listen" {
            options.config.network.p2p_listen = address.to_string();
        } else {
            options.config.network.rpc_listen = address.to_string();
        }
    }
    Ok(())
}

fn invalid(message: &str) -> DaemonError {
    DaemonError::Config(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_arguments_fail_before_startup() {
        for args in [
            vec!["--blocks"],
            vec!["--blocks", "invalid"],
            vec!["--blocks", "-1"],
            vec!["--blocks", "18446744073709551616"],
            vec!["--blocks", "+1"],
            vec!["--blocks", "1", "--unknown"],
            vec!["unexpected"],
            vec!["--dry-run", "--dry-run"],
            vec!["--data-dir", "--blocks", "1"],
            vec!["--genesis"],
            vec!["--genesis", "--blocks", "1"],
            vec!["--genesis", "one", "--genesis", "two"],
            vec!["--p2p-listen", "garbage"],
            vec!["--run", "--blocks", "1"],
            vec!["--help", "--blocks", "1"],
            vec!["--blocks", "1", "--blocks", "2"],
        ] {
            assert!(parse(args.iter().map(OsString::from)).is_err(), "{args:?}");
        }
    }

    #[test]
    fn accepts_zero_and_native_paths() {
        let Command::Run(options) =
            parse(["--blocks", "0", "--data-dir", "local chain"].map(OsString::from)).unwrap()
        else {
            panic!("expected run")
        };
        assert_eq!(options.max_blocks, Some(0));
        assert_eq!(options.config.data_dir, PathBuf::from("local chain"));
    }

    #[test]
    fn certified_transport_requires_explicit_secure_configuration() {
        let base = [
            "--validators",
            "keys",
            "--genesis",
            "genesis",
            "--validator-key",
            "seed",
        ];
        for extra in [
            vec![],
            vec!["--tls-dir", "tls", "--allow-plaintext"],
            vec!["--allow-plaintext", "--p2p-listen", "0.0.0.0:1234"],
            vec!["--allow-plaintext", "--peers", "192.0.2.1:1234"],
        ] {
            assert!(
                parse(base.iter().chain(extra.iter()).map(OsString::from)).is_err(),
                "{extra:?}"
            );
        }
        for extra in [vec!["--tls-dir", "tls"], vec!["--allow-plaintext"]] {
            assert!(parse(base.iter().chain(extra.iter()).map(OsString::from)).is_ok());
        }
        assert!(parse(["--tls-dir", "tls"].map(OsString::from)).is_err());
        assert!(parse(["--allow-plaintext"].map(OsString::from)).is_err());
    }

    #[test]
    fn observer_requires_public_network_context_and_forbids_signing_options() {
        let base = [
            "--validators",
            "keys",
            "--genesis",
            "genesis",
            "--tls-dir",
            "tls",
            "--observer",
        ];
        assert!(parse(base.map(OsString::from)).is_ok());
        for extra in [
            vec!["--validator-key", "seed"],
            vec!["--round-timeout-ms", "500"],
        ] {
            assert!(parse(base.iter().chain(extra.iter()).map(OsString::from)).is_err());
        }
        assert!(parse(["--observer", "--allow-plaintext"].map(OsString::from)).is_err());
        assert!(
            parse(["--observer", "--validators", "keys", "--tls-dir", "tls"].map(OsString::from))
                .is_err()
        );
    }
}
