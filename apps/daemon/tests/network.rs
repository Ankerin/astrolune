// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Real processes exchange signatures, gossip payments, restart, and synchronize over TCP.

use codec::CanonicalEncode;
use crypto::blake2s::{blake2s, ed25519_public_key, ed25519_sign};
use genesis::{Allocation, Genesis, GenesisValidator};
use keystore::{DurableSigner, SigningContext};
use rpc::json::{JsonValue, parse_json};
use std::{
    io::{BufRead, BufReader},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use transaction::{Payment, address_from_public_key, signing_hash};
use types::{AccountState, Address, Resources, Transaction, ValidatorId};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
    genesis: Genesis,
    keys: Vec<[u8; 32]>,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astrolune-network-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let keys: Vec<_> = (1..=4)
            .map(|index| ed25519_public_key(&[index; 32]))
            .collect();
        let mut validators: Vec<_> = keys
            .iter()
            .map(|key| GenesisValidator {
                id: ValidatorId(blake2s(key).0),
                weight: 1,
            })
            .collect();
        validators.sort_by_key(|member| member.id);
        let genesis = Genesis {
            version: 1,
            chain_id: 42,
            committee_size: 4,
            rotation_count: 1,
            runtime_version: 1,
            capacity: Resources {
                compute: 1_000_000,
                memory: 1_000_000,
                io: 1_000_000,
                bandwidth: 1_000_000,
            },
            validators,
            allocations: vec![Allocation {
                address: address_from_public_key(&ed25519_public_key(&[99; 32])),
                amount: 1_000_000,
            }],
        };
        std::fs::write(path.join("genesis.bin"), genesis.to_bytes()).unwrap();
        std::fs::write(path.join("validators.bin"), keys.concat()).unwrap();
        for index in 1..=4 {
            let data = path.join(index.to_string());
            std::fs::create_dir(&data).unwrap();
            std::fs::write(data.join("validator.seed"), [index; 32]).unwrap();
            drop(
                DurableSigner::create_protected(
                    data.join("signing.journal"),
                    SigningContext {
                        chain_id: 42,
                        genesis: genesis.commitment().unwrap(),
                    },
                    [index; 32],
                )
                .unwrap(),
            );
        }
        Self {
            path,
            genesis,
            keys,
        }
    }
    fn start(&self, index: usize, peers: &[String]) -> Process {
        let data = self.path.join(index.to_string());
        let mut child = Process(
            Command::new(env!("CARGO_BIN_EXE_daemon"))
                .arg("--genesis")
                .arg(self.path.join("genesis.bin"))
                .arg("--validators")
                .arg(self.path.join("validators.bin"))
                .arg("--validator-key")
                .arg(data.join("validator.seed"))
                .arg("--data-dir")
                .arg(data)
                .args([
                    "--run",
                    "--p2p-listen",
                    &peers[index - 1],
                    "--rpc-listen",
                    "127.0.0.1:0",
                    "--peers",
                    &peers
                        .iter()
                        .enumerate()
                        .filter(|(seat, _)| *seat != index - 1)
                        .map(|(_, address)| address.clone())
                        .collect::<Vec<_>>()
                        .join(","),
                    "--round-timeout-ms",
                    "500",
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
            String::new(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(address) = line.strip_prefix("rpc       : ") {
                    let _ = sender.send(address.to_owned());
                }
            }
        });
        child.1 = receiver
            .recv_timeout(Duration::from_secs(20))
            .expect("certified daemon starts its RPC listener");
        child
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
struct Process(Child, String);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn call(address: &str, method: &str, params: &str) -> JsonValue {
    let mut stream = TcpStream::connect(address).unwrap();
    let json = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    p2p::exchange::write_packet(&mut stream, json.as_bytes(), 65536, Duration::from_secs(5))
        .unwrap();
    let bytes = p2p::exchange::read_packet(&mut stream, 65536, Duration::from_secs(5)).unwrap();
    parse_json(std::str::from_utf8(&bytes).unwrap()).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap();
        text
    })
}
fn payment() -> Transaction {
    let key = ed25519_public_key(&[99; 32]);
    let sender = address_from_public_key(&key);
    let recipient = Address([77; 32]);
    let mut access_list = vec![state::account_key(sender), state::account_key(recipient)];
    access_list.sort();
    let mut tx = Transaction {
        version: 1,
        chain_id: 42,
        sender,
        nonce: 0,
        expires_at: 1000,
        lane: types::TransactionLane::Payments,
        resource_prices: Resources {
            compute: 1,
            ..Resources::ZERO
        },
        resource_limit: Resources::ZERO,
        access_list,
        payload: Payment {
            public_key: key,
            recipient,
            amount: 123,
        }
        .to_bytes(),
        signature: [0; 64],
    };
    tx.resource_limit = execution::payment_resources(&tx).unwrap();
    tx.signature = ed25519_sign(&[99; 32], signing_hash(&tx).as_bytes());
    tx
}
fn await_payment(processes: &[&Process]) {
    let deadline = Instant::now() + Duration::from_secs(40);
    let expected = JsonValue::String(hex(&AccountState {
        nonce: 0,
        balance: 123,
    }
    .to_bytes()));
    loop {
        if processes.iter().all(|process| {
            call(
                &process.1,
                "account",
                &format!(r#"{{"address":"{}"}}"#, Address([77; 32])),
            )
            .get("result")
                == Some(&expected)
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "payment did not finalize across the network"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn tcp_quorum_payment_restart_and_late_join() {
    let fixture = Fixture::new();
    let mut reservations: Vec<_> = (0..4)
        .map(|_| Some(TcpListener::bind("127.0.0.1:0").unwrap()))
        .collect();
    let peers: Vec<_> = reservations
        .iter()
        .map(|listener| listener.as_ref().unwrap().local_addr().unwrap().to_string())
        .collect();
    let mut processes = Vec::new();
    for index in 1..=3 {
        drop(reservations[index - 1].take());
        processes.push(fixture.start(index, &peers));
    }
    drop(reservations[3].take());
    let tx = payment();
    let submitted = call(
        &processes[0].1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(submitted.get("error").is_none(), "{submitted:?}");
    await_payment(&processes.iter().collect::<Vec<_>>());
    // Cold startup at genesis and independent history verification on process restart.
    let late = fixture.start(4, &peers);
    drop(processes.remove(1));
    let restarted = fixture.start(2, &peers);
    await_payment(&[&processes[0], &processes[1], &late, &restarted]);
    let replay = call(
        &late.1,
        "submit_transaction",
        &format!(r#"{{"data":"{}"}}"#, hex(&tx.to_bytes())),
    );
    assert!(replay.get("error").is_some());
    drop(processes);
    drop(late);
    drop(restarted);
    let network =
        node::network::StaticNetwork::new(fixture.genesis.clone(), fixture.keys.clone()).unwrap();
    let mut heads = Vec::new();
    for index in 1..=4 {
        let data = fixture.path.join(index.to_string());
        let signer = DurableSigner::open(
            data.join("signing.journal"),
            SigningContext {
                chain_id: 42,
                genesis: network.genesis_hash(),
            },
            [index; 32],
        )
        .unwrap();
        let node = node::network::NetworkNode::open(
            network.clone(),
            &data,
            signer,
            Duration::from_millis(500),
        )
        .unwrap();
        let request = node::network_wire::SyncRequest {
            genesis: network.genesis_hash(),
            height: 1,
        };
        let messages = node::network_wire::decode_exchange(
            network.genesis_hash(),
            &node.respond(request).unwrap(),
        )
        .unwrap();
        let node::network_wire::NetworkMessage::Finalized { block, .. } = &messages[0] else {
            panic!("certified block required")
        };
        heads.push(block.header.compute_hash());
    }
    assert!(heads.iter().all(|head| *head == heads[0]));
}

#[test]
fn missing_journal_and_incomplete_network_arguments_fail_without_provisioning() {
    let fixture = Fixture::new();
    let downgrade = Command::new(env!("CARGO_BIN_EXE_daemon"))
        .arg("--genesis")
        .arg(fixture.path.join("genesis.bin"))
        .arg("--data-dir")
        .arg(fixture.path.join("1"))
        .args(["--blocks", "1"])
        .output()
        .unwrap();
    assert!(!downgrade.status.success());
    assert!(!fixture.path.join("1/chain.bin").exists());
    let directory = fixture.path.join("missing");
    std::fs::create_dir(&directory).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_daemon"))
        .arg("--genesis")
        .arg(fixture.path.join("genesis.bin"))
        .arg("--validators")
        .arg(fixture.path.join("validators.bin"))
        .arg("--validator-key")
        .arg(fixture.path.join("1/validator.seed"))
        .arg("--data-dir")
        .arg(&directory)
        .args(["--blocks", "0"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!directory.join("signing.journal").exists());
    assert!(!directory.join("chain.bin").exists());
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_daemon"))
            .args(["--validators", "keys", "--blocks", "0"])
            .output()
            .unwrap()
            .status
            .success()
    );
}
