// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Producer-to-durable-storage conformance across repeated storage reopen.

use std::fs;
use std::path::PathBuf;

use node::{BlockProducer, ProducerConfig};
use storage::{FileBackedStorage, NodeStorage};
use types::{Address, Resources, Transaction};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        // The test owns this unique temporary directory.
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn produced_blocks_recover_with_identical_bodies_certificates_and_state() {
    let fixture = Fixture(
        std::env::temp_dir().join(format!("astrolune-producer-durable-{}", std::process::id())),
    );
    fs::create_dir(&fixture.0).unwrap();
    let path = fixture.0.join("chain.bin");
    let mut producer =
        BlockProducer::with_account(Address([1; 32]), 0, 1000, ProducerConfig::default());
    for height in 0..4 {
        producer
            .submit_transaction(Transaction {
                chain_id: 7,
                sender: Address([1; 32]),
                nonce: height,
                access_list: vec![],
                resource_limit: Resources::ZERO,
                payload: vec![1, 2, 3],
                signature: [1; 64],
            })
            .unwrap();
        let proposal = producer.produce_block().unwrap();
        let mut storage = FileBackedStorage::open(&path).unwrap();
        let checkpoint = producer
            .commit_block(&proposal, vec![2; 64], &mut storage)
            .unwrap();
        drop(storage);
        let mut storage = FileBackedStorage::open(&path).unwrap();
        assert_eq!(storage.recover().unwrap(), Some(checkpoint));
        assert_eq!(storage.get_block(&checkpoint.block), Some(&proposal.block));
        assert_eq!(
            storage.get_certificate(&checkpoint.block),
            Some([2; 64].as_slice())
        );
        assert_eq!(
            storage.state().export_snapshot(),
            producer.state().export_snapshot()
        );
        assert_eq!(producer.pending_count(), 0);
    }
}
