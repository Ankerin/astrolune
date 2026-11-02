<!-- Copyright (c) 2026 Ankerin. SPDX-License-Identifier: MIT -->

[Documentation](../../README.md)

# Trocto language

Trocto syntax, language and metering profiles, state capabilities, LLVM tooling and native execution.

Start with the [language overview](05-contract-languages.md), then read the [supported syntax and language profile](64-trocto-native-llvm.md#language-profile-2).

The implementation reference also covers [state capabilities](64-trocto-native-llvm.md#state-capabilities-and-metadata), [native isolation](64-trocto-native-llvm.md#native-isolation-and-lifecycle) and [working commands](64-trocto-native-llvm.md#working-commands). Language, metering and genesis runtime profiles have separate version identities.

## Documents

| Number | Document |
| --- | --- |
| 05 | [Trocto Contract Language](05-contract-languages.md) |
| 64 | [Trocto and the Native LLVM Runtime](64-trocto-native-llvm.md) |

## Examples and contract workflow

- [Metered counter](../../../examples/contracts/trocto/metered_counter.tc)
- [Checked payment](../../../examples/contracts/trocto/checked_payment.tc)
- [Address-aware counter](../../../examples/contracts/trocto/address_counter.tc)
- [Contract deployment, calls and source packages](../../contracts/README.md)
- [Runtime and resource metering](../../contracts/03-vm-and-gas.md)
- [Languages index](../README.md)
