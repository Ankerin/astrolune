<!-- Copyright (c) 2026 Astrolune contributors. SPDX-License-Identifier: MIT -->

# 6. Ecosystem Services

AstroLune DNS, Proxy, Pages, and ID are separate Rust services. They reuse finalized chain data and wallet authorization but remain outside the consensus hot path. Each can be disabled without preventing block validation.

## 6.1 AstroLune DNS

AstroLune DNS maps normalized in-network names to wallet/contract addresses, Pages manifests, or service records. Ownership and updates are authorized on-chain. Resolvers verify finalized registry state and proofs.

Names require a canonical Unicode and normalization policy, reserved-name policy, lease/renewal rules, maximum depth and length, and protection against confusable display. Resolvers do not silently fall back to public DNS for an AstroLune name.

## 6.2 AstroLune Proxy

The Proxy is the client access gateway for AstroLune names and internal services. After DNS resolution it routes bounded requests to Pages or application endpoints. It separates public browser tooling from internal network protocols.

The baseline does **not** claim anonymity. Encryption and relaying alone do not prevent traffic analysis. Onion routing, cover traffic, exit relays, payment, and anti-correlation behavior require a dedicated threat model, specialist review, and explicit product language before implementation.

## 6.3 AstroLune Pages

Pages serves static sites reachable through AstroLune DNS while a user is connected to the Proxy. An on-chain or authenticated manifest binds a name, owner, revision, entry point, content root, and release policy.

Pages verifies immutable asset hashes and applies strict path normalization, MIME handling, content-security policy defaults, response-size limits, and origin isolation. Dynamic server execution is outside Pages.

Pages is not a general-purpose distributed storage or file-sharing feature. Operators or external content origins supply release assets; AstroLune authenticates and addresses them. Designing availability replication may happen later without creating a storage-token economy.

## 6.4 AstroLune ID

AstroLune ID lets an application request wallet authorization without receiving the wallet secret key. The flow is:

1. the backend generates a single-use unpredictable challenge;
2. the application asks the wallet for named scopes;
3. the wallet displays origin, audience, chain, scopes, and expiry;
4. the user approves and the wallet signs canonical domain-separated bytes;
5. the backend verifies address binding, signature, origin, audience, time window, and nonce;
6. the backend atomically consumes the nonce and creates its own short-lived session.

Initial scopes are address disclosure, application-message signing, and transaction submission. Transaction submission always presents the actual transaction for wallet review; an ID proof is not blanket signing authority.

Required protections include origin/audience binding, chain binding, short expiry, one-time nonces, canonical encodings, domain separation, scope minimization, revocation/session termination, phishing-resistant wallet UI, and no secret-key export.

## 6.5 Isolation

Services use dedicated keys and listeners. A DNS, Proxy, Pages, or ID compromise must not expose validator signing keys or gain trusted access to consensus internals. Service requests are rate-limited, authenticated where appropriate, and parsed as untrusted input.
