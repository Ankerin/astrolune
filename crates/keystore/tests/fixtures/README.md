# Wallet v1 compatibility vector

`wallet-v1.bin` is a 144-byte public test fixture generated with the original
Argon2 0.5.3 and chacha20poly1305 0.10.1 providers. It is not a real wallet.
The seed/public key are RFC 8032 test vector 1. Password:
`astrolune-vault-fixture-v1`. Salt is bytes 0..15; nonce is bytes 16..39.
Argon2id v19 uses 65536 KiB, three iterations, one lane and a 32-byte key.
The first 96 bytes are XChaCha20-Poly1305 associated data.

This fixture prevents a dependency upgrade from silently abandoning previously
created vaults. Never reuse its seed, salt, nonce or password for a real wallet.
