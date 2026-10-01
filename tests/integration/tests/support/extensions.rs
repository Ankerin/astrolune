// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Shared stable mutation/libFuzzer oracle for the newly implemented wire boundaries.

use contract_sdk::registry::{Lease, MAX_CALL, MAX_LEASE, RegistryCall, transition};
use runtime::{ModuleValidator, WASM_VERSION, WasmCall, WasmRuntime};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};
use types::{Address, Hash256, Resources};

pub fn check(bytes: &[u8]) -> usize {
    use codec::{CanonicalDecode, CanonicalEncode};
    let mut accepted = check_rotation(bytes);
    if let Ok(genesis) = genesis::Genesis::decode(bytes) {
        assert_eq!(genesis.to_bytes(), bytes);
        accepted += 1;
    }
    if let Ok(messages) = node::network_wire::decode_exchange(Hash256([1; 32]), bytes) {
        assert_eq!(
            node::network_wire::encode_exchange(Hash256([1; 32]), &messages).unwrap(),
            bytes
        );
        accepted += 1;
    }
    if let Ok(proof) = crypto::VrfOutput::decode(bytes) {
        assert_eq!(proof.encode().unwrap().as_slice(), bytes);
        let key = crypto::blake2s::ed25519_public_key(&[1; 32]);
        let _ = crypto::vrf::verify_vrf(&key, Hash256([1; 32]), &proof);
        accepted += 1;
    }
    if let Ok(proof) = state::StateValueProof::from_bytes(bytes) {
        assert_eq!(proof.to_bytes().unwrap(), bytes);
        let _ = proof.verify(Hash256::ZERO, &genesis::genesis_key());
        accepted += 1;
    }
    if let Ok(proof) = rpc::CertifiedStateProof::from_bytes(bytes) {
        assert_eq!(proof.to_bytes().unwrap(), bytes);
        accepted += 1;
    }
    if let Ok(proof) = rpc::CertifiedReceiptProof::from_bytes(bytes) {
        assert_eq!(proof.to_bytes().unwrap(), bytes);
        accepted += 1;
    }
    if let Ok(effects) = storage::BlockEffects::from_bytes(bytes) {
        assert_eq!(effects.to_bytes().unwrap(), bytes);
        accepted += 1;
    }
    if let Ok((peers, payload)) = p2p::discovery::decode(bytes, Hash256([1; 32]), 4096) {
        assert_eq!(
            p2p::discovery::encode(Hash256([1; 32]), &peers, payload, 4096).unwrap(),
            bytes
        );
        accepted += 1;
    }
    let _ = Lease::decode(bytes);
    if let Ok(call) = RegistryCall::decode(bytes) {
        let mut encoded = [0; MAX_CALL];
        let length = call.encode(&mut encoded).unwrap();
        assert_eq!(&encoded[..length], bytes);
        let mut output = [0; MAX_LEASE];
        if let Ok(Some(length)) = transition(call, None, [1; 32], 1, &mut output) {
            let lease = Lease::decode(&output[..length]).unwrap();
            assert_eq!(lease.name, call.name);
            assert_eq!(lease.owner, [1; 32]);
            let _ = transition(
                call,
                Some(&output[..length]),
                [2; 32],
                2,
                &mut [0; MAX_LEASE],
            );
        }
        accepted += 1;
    }
    if bytes.starts_with(b"\0asm") && bytes.len() <= 64 * 1024 {
        static ENGINE: OnceLock<WasmRuntime> = OnceLock::new();
        let engine = ENGINE.get_or_init(WasmRuntime::new);
        if let Ok(module) = engine.validate(bytes, WASM_VERSION) {
            let state = BTreeMap::new();
            let access = BTreeSet::new();
            let call = WasmCall {
                input: b"fixture",
                caller: Address([1; 32]),
                height: 1,
                state: &state,
                access: &access,
                limits: Resources {
                    compute: 10_000,
                    memory: 16 * 1024 * 1024,
                    io: 1024,
                    bandwidth: 1024,
                },
            };
            assert_eq!(
                engine.execute_call(&module, call),
                engine.execute_call(&module, call)
            );
            accepted += 1;
        }
    }
    accepted
}

fn check_rotation(bytes: &[u8]) -> usize {
    let mut accepted = 0;
    if let Ok(state) = consensus::rotation::CommitteeState::from_bytes(bytes) {
        assert_eq!(state.to_bytes().unwrap(), bytes);
        accepted += 1;
    }
    if let Ok(contribution) = consensus::rotation::VrfContribution::from_bytes(bytes) {
        assert_eq!(contribution.to_bytes().unwrap(), bytes);
        accepted += 1;
    }
    if let Ok(batch) = consensus::rotation::VrfBatch::from_bytes(bytes) {
        assert_eq!(batch.to_bytes().unwrap(), bytes);
        accepted += 1;
    }
    if let Ok(handoff) = consensus::rotation::CommitteeHandoff::from_bytes(bytes) {
        assert_eq!(handoff.to_bytes().unwrap(), bytes);
        accepted += 1;
    }
    accepted
}
