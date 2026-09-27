// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Vault format, independent randomness, authentication and bounded work parameters.

use keystore::vault::{
    VaultError, WALLET_VAULT_BYTES, decrypt_wallet_seed, encrypt_wallet_seed, generate_wallet_seed,
};

#[test]
fn random_vaults_round_trip_and_authenticate_every_header_class() {
    let password = b"correct horse battery staple";
    let seed = generate_wallet_seed().unwrap();
    assert_ne!(*seed, *generate_wallet_seed().unwrap());
    let first = encrypt_wallet_seed(&seed, password).unwrap();
    let second = encrypt_wallet_seed(&seed, password).unwrap();
    assert_eq!(first.len(), WALLET_VAULT_BYTES);
    assert_ne!(&first[24..64], &second[24..64]);
    assert_ne!(&first[96..], &second[96..]);
    assert_eq!(*decrypt_wallet_seed(&first, password).unwrap(), *seed);
    assert_eq!(
        decrypt_wallet_seed(&first, b"different long password").unwrap_err(),
        VaultError::Authentication
    );
    for offset in [24, 40, 64, 96, 143] {
        let mut changed = first.clone();
        changed[offset] ^= 1;
        assert_eq!(
            decrypt_wallet_seed(&changed, password).unwrap_err(),
            VaultError::Authentication
        );
    }
    for offset in 0..24 {
        let mut changed = first.clone();
        changed[offset] ^= 1;
        assert_eq!(
            decrypt_wallet_seed(&changed, password).unwrap_err(),
            VaultError::InvalidFormat
        );
    }
    for length in 0..first.len() {
        assert_eq!(
            decrypt_wallet_seed(&first[..length], password).unwrap_err(),
            VaultError::InvalidFormat
        );
    }
    let mut trailing = first;
    trailing.push(0);
    assert_eq!(
        decrypt_wallet_seed(&trailing, password).unwrap_err(),
        VaultError::InvalidFormat
    );
    assert_eq!(
        encrypt_wallet_seed(&seed, b"short").unwrap_err(),
        VaultError::InvalidFormat
    );
    assert_eq!(
        encrypt_wallet_seed(&seed, &[1; 1025]).unwrap_err(),
        VaultError::InvalidFormat
    );
}
