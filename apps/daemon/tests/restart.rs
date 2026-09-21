// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Daemon process recovery, startup failure, and command-line conformance.

use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use storage::FileBackedStorage;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "astrolune-daemon-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_daemon"));
        command.arg("--data-dir").arg(&self.0);
        command.args(["--p2p-listen", "127.0.0.1:0", "--rpc-listen", "127.0.0.2:0"]);
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn additional_blocks_extend_the_same_archive_after_process_restart() {
    let fixture = Fixture::new();
    let first = fixture.command().args(["--blocks", "3"]).output().unwrap();
    success(&first);
    let path = fixture.0.join("chain.bin");
    let storage = FileBackedStorage::open(&path).unwrap();
    let previous = *storage.checkpoint().unwrap();
    assert_eq!(previous.height, 2);
    drop(storage);
    let second = fixture.command().args(["--blocks", "2"]).output().unwrap();
    success(&second);
    assert!(String::from_utf8_lossy(&second.stdout).contains("next_height: 3"));
    let storage = FileBackedStorage::open(&path).unwrap();
    assert_eq!(storage.checkpoint().unwrap().height, 4);
    assert_eq!(storage.block_count(), 5);
    assert!(storage.get_block(&previous.block).is_some());
    drop(storage);
    let before = fs::read(&path).unwrap();
    success(&fixture.command().args(["--blocks", "0"]).output().unwrap());
    assert_eq!(before, fs::read(&path).unwrap());
}

#[test]
fn dry_run_and_invalid_options_have_no_filesystem_effects() {
    let fixture = Fixture::new();
    success(&fixture.command().arg("--dry-run").output().unwrap());
    assert!(!fixture.0.exists());
    let invalid = fixture
        .command()
        .args(["--blocks", "bad"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!fixture.0.exists());
}

#[test]
fn locked_or_corrupt_archive_fails_without_overwriting_it() {
    let fixture = Fixture::new();
    success(&fixture.command().args(["--blocks", "1"]).output().unwrap());
    let path = fixture.0.join("chain.bin");
    let before = fs::read(&path).unwrap();
    let lock = FileBackedStorage::open(&path).unwrap();
    let output = fixture.command().args(["--blocks", "1"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("locked"));
    assert_eq!(before, fs::read(&path).unwrap());
    drop(lock);
    fs::write(&path, b"corrupt archive").unwrap();
    let output = fixture.command().args(["--blocks", "1"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&path).unwrap(), b"corrupt archive");
}

#[test]
fn listener_failure_prevents_block_production() {
    let fixture = Fixture::new();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_daemon"))
        .arg("--data-dir")
        .arg(&fixture.0)
        .args([
            "--blocks",
            "1",
            "--p2p-listen",
            "127.0.0.1:0",
            "--rpc-listen",
        ])
        .arg(occupied.local_addr().unwrap().to_string())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let storage = FileBackedStorage::open(fixture.0.join("chain.bin")).unwrap();
    assert!(storage.checkpoint().is_none());
}
