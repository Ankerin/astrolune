// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Certified daemon, bounded peer polling, and committed account RPC.

use crate::{DaemonError, io_error, options::Options};
use codec::{CanonicalDecode, CanonicalEncode};
use node::{
    network::{NetworkNode, NetworkNodeError, StaticNetwork},
    network_wire::{MAX_EXCHANGE_BYTES, SyncRequest},
};
use p2p::exchange::{read_packet, write_packet};
use p2p::tls::{PeerStream, PeerTlsConfig};
use rpc::{RpcError, RpcRequest, RpcResponse, RpcService, TcpRpcServer};
use state::StateDatabase;
use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) fn run(options: &Options, genesis: genesis::Genesis) -> Result<(), DaemonError> {
    let (network, seed) = load_identity(options, genesis)?;
    let transport = PeerTransport(
        options
            .tls_dir
            .as_deref()
            .map(PeerTlsConfig::from_directory)
            .transpose()
            .map_err(io_error)?,
    );
    println!("AstroLune certified reference network (fixed committee / round-robin)");
    println!("chain_id  : {}", network.chain_id());
    println!("genesis_hash: {}", network.genesis_hash());
    println!(
        "transport : {}",
        if transport.0.is_some() {
            "TLS 1.3 / mutual authentication"
        } else {
            "INSECURE loopback plaintext"
        }
    );
    if options.dry_run {
        println!("[dry-run] network configuration valid; no files written or listeners opened.");
        return Ok(());
    }
    let context = keystore::SigningContext {
        chain_id: network.chain_id(),
        genesis: network.genesis_hash(),
    };
    // Deliberate open-only provisioning: losing the journal never creates fresh signing authority.
    let signer = keystore::DurableSigner::open(
        options.config.data_dir.join("signing.journal"),
        context,
        *seed,
    )
    .map_err(io_error)?;
    drop(seed);
    let node = NetworkNode::open(
        network.clone(),
        &options.config.data_dir,
        signer,
        Duration::from_millis(options.round_timeout_ms),
    )
    .map_err(io_error)?;
    println!("next_height: {}", node.request().height);
    if options.max_blocks == Some(0) {
        println!("Certified history and signing recovery complete.");
        return Ok(());
    }
    let initial_height = node.request().height;
    let node = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind(&options.config.network.p2p_listen).map_err(io_error)?;
    listener.set_nonblocking(true).map_err(io_error)?;
    let rpc = Arc::new(Mutex::new(NetworkStatus {
        node: node.clone(),
        chain_id: network.chain_id(),
    }));
    let rpc = TcpRpcServer::bind(rpc, &options.config.network.rpc_listen).map_err(io_error)?;
    println!("p2p       : {}", listener.local_addr().map_err(io_error)?);
    println!("rpc       : {}", rpc.local_addr().map_err(io_error)?);
    std::thread::Builder::new()
        .name("network-rpc".into())
        .spawn(move || {
            if let Err(error) = rpc.run() {
                eprintln!("RPC listener: {error}");
            }
        })
        .map_err(io_error)?;
    let stop = Arc::new(AtomicBool::new(false));
    let workers = spawn_peers(options, &node, &stop, &transport)?;
    let active = Arc::new(AtomicUsize::new(0));
    let result = drive(
        options,
        &node,
        &listener,
        &active,
        initial_height,
        &workers.receiver,
        &transport,
    );
    stop.store(true, Ordering::Release);
    for worker in workers.handles {
        let _ = worker.join();
    }
    result
}

fn load_identity(
    options: &Options,
    genesis: genesis::Genesis,
) -> Result<(StaticNetwork, zeroize::Zeroizing<[u8; 32]>), DaemonError> {
    let registry = read_bounded(
        options
            .validators
            .as_deref()
            .ok_or_else(|| io_error("missing registry"))?,
        32 * 32,
    )?;
    if registry.is_empty() || registry.len() % 32 != 0 {
        return Err(DaemonError::Config(
            "validator registry must contain complete 32-byte public keys".into(),
        ));
    }
    let keys = registry
        .chunks_exact(32)
        .map(|key| <[u8; 32]>::try_from(key).expect("complete key chunk"))
        .collect();
    let network = StaticNetwork::new(genesis, keys).map_err(io_error)?;
    let seed = zeroize::Zeroizing::new(read_bounded(
        options
            .validator_key
            .as_deref()
            .ok_or_else(|| io_error("missing seed path"))?,
        32,
    )?);
    let seed = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(seed.as_slice())
            .map_err(|_| DaemonError::Config("validator seed must be exactly 32 bytes".into()))?,
    );
    let id =
        types::ValidatorId(crypto::blake2s_hash(&crypto::blake2s::ed25519_public_key(&seed)).0);
    if network
        .committee(1)
        .map_err(io_error)?
        .voting_power(id)
        .is_none()
    {
        return Err(DaemonError::Config(
            "validator key is not registered in genesis".into(),
        ));
    }
    Ok((network, seed))
}

struct Workers {
    receiver: mpsc::Receiver<Vec<u8>>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

#[derive(Clone)]
struct PeerTransport(Option<PeerTlsConfig>);

impl PeerTransport {
    fn connect(&self, stream: TcpStream) -> std::io::Result<PeerStream> {
        match &self.0 {
            Some(tls) => tls.connect(stream, IO_TIMEOUT),
            None => PeerStream::plaintext_local(stream, IO_TIMEOUT),
        }
    }

    fn accept(&self, stream: TcpStream) -> std::io::Result<PeerStream> {
        match &self.0 {
            Some(tls) => tls.accept(stream, IO_TIMEOUT),
            None => PeerStream::plaintext_local(stream, IO_TIMEOUT),
        }
    }
}

fn spawn_peers(
    options: &Options,
    node: &Arc<Mutex<NetworkNode>>,
    stop: &Arc<AtomicBool>,
    transport: &PeerTransport,
) -> Result<Workers, DaemonError> {
    let (sender, receiver) = mpsc::sync_channel(4);
    let mut handles = Vec::new();
    for address in &options.peers {
        let address = *address;
        let node = node.clone();
        let stop = stop.clone();
        let sender = sender.clone();
        let transport = transport.clone();
        handles.push(
            std::thread::Builder::new()
                .name(format!("peer-{address}"))
                .spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        let Ok(node) = node.lock() else {
                            break;
                        };
                        let request = node.request();
                        drop(node);
                        let exchange = || -> std::io::Result<Vec<u8>> {
                            let stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)?;
                            let mut stream = transport.connect(stream)?;
                            write_packet(&mut stream, &request.encode(), 48, IO_TIMEOUT)?;
                            read_packet(&mut stream, MAX_EXCHANGE_BYTES, IO_TIMEOUT)
                        };
                        if let Ok(bytes) = exchange() {
                            // A full mailbox drops a redundant snapshot; the next poll retries it.
                            let _ = sender.try_send(bytes);
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                })
                .map_err(io_error)?,
        );
    }
    Ok(Workers { receiver, handles })
}

struct ConnectionSlot(Arc<AtomicUsize>);
impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn drive(
    options: &Options,
    node: &Arc<Mutex<NetworkNode>>,
    listener: &TcpListener,
    active: &Arc<AtomicUsize>,
    initial_height: u64,
    receiver: &mpsc::Receiver<Vec<u8>>,
    transport: &PeerTransport,
) -> Result<(), DaemonError> {
    let mut reported = initial_height;
    loop {
        // The fixed accept budget also prevents a connection flood from starving consensus.
        for _ in 0..8 {
            match listener.accept() {
                Ok((stream, _)) => {
                    if active.load(Ordering::Acquire) >= options.config.network.max_peers {
                        continue;
                    }
                    active.fetch_add(1, Ordering::AcqRel);
                    let slot = ConnectionSlot(active.clone());
                    let node = node.clone();
                    let transport = transport.clone();
                    std::thread::Builder::new()
                        .name("peer-request".into())
                        .spawn(move || {
                            let _slot = slot;
                            let serve = || -> Result<(), DaemonError> {
                                let mut stream = transport.accept(stream).map_err(io_error)?;
                                let bytes =
                                    read_packet(&mut stream, 48, IO_TIMEOUT).map_err(io_error)?;
                                let request = SyncRequest::decode(&bytes).map_err(io_error)?;
                                let response = node
                                    .lock()
                                    .map_err(|_| io_error("node lock poisoned"))?
                                    .respond(request)
                                    .map_err(io_error)?;
                                write_packet(&mut stream, &response, MAX_EXCHANGE_BYTES, IO_TIMEOUT)
                                    .map_err(io_error)
                            };
                            let _ = serve();
                        })
                        .map_err(io_error)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(io_error(error)),
            }
        }
        let mut node = node.lock().map_err(|_| io_error("node lock poisoned"))?;
        for bytes in receiver.try_iter().take(4) {
            match node.receive(&bytes) {
                Ok(_) | Err(NetworkNodeError::Input(_)) => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        node.tick(Instant::now()).map_err(io_error)?;
        let height = node.request().height;
        if height != reported {
            println!("certified block committed at height {}", height - 1);
            println!("state_root: {}", node.storage().state().root());
            reported = height;
        }
        if options
            .max_blocks
            .is_some_and(|count| height.saturating_sub(initial_height) >= count)
        {
            println!(
                "Stopped after {} certified blocks.",
                height - initial_height
            );
            return Ok(());
        }
        drop(node);
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_bounded(path: &std::path::Path, maximum: usize) -> Result<Vec<u8>, DaemonError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(io_error)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > maximum {
        return Err(DaemonError::Config(
            "configuration file exceeds its size bound".into(),
        ));
    }
    Ok(bytes)
}

struct NetworkStatus {
    node: Arc<Mutex<NetworkNode>>,
    chain_id: u32,
}
impl RpcService for NetworkStatus {
    fn handle(&self, request: RpcRequest) -> Result<RpcResponse, RpcError> {
        let mut node = self.node.lock().map_err(|_| RpcError::Unavailable)?;
        match request {
            RpcRequest::ChainStatus => {
                let checkpoint = node.storage().checkpoint().ok_or(RpcError::Unavailable)?;
                Ok(RpcResponse::ChainStatus {
                    chain_id: self.chain_id,
                    finalized_height: checkpoint.height,
                    finalized_block: checkpoint.block,
                })
            }
            RpcRequest::Account(address) => {
                let snapshot = node
                    .storage()
                    .state()
                    .snapshot()
                    .map_err(|_| RpcError::Unavailable)?;
                let account = state::read_account(snapshot.as_ref(), address)
                    .map_err(|_| RpcError::Unavailable)?;
                Ok(RpcResponse::Account(
                    account.map(|account| account.to_bytes()),
                ))
            }
            RpcRequest::SubmitTransaction(bytes) => {
                if bytes.len() > node::network_wire::MAX_TRANSACTION_BYTES {
                    return Err(RpcError::LimitExceeded);
                }
                let tx =
                    types::Transaction::decode(&bytes).map_err(|_| RpcError::InvalidRequest)?;
                node.submit_transaction(tx)
                    .map(RpcResponse::TransactionAccepted)
                    .map_err(|error| match error {
                        NetworkNodeError::Input(_) => RpcError::InvalidRequest,
                        NetworkNodeError::Local(_) => RpcError::Unavailable,
                    })
            }
        }
    }
}
