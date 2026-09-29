// SPDX-License-Identifier: CC0-1.0

//! Implementation of the "maps" concept defined in BIP-174.
//!
//! > The Partially Signed Bitcoin Transaction (PSBT) format consists of key-value maps.
//! > ...
//! > `<global-map> := <keypair>* 0x00`
//! > `<input-map> := <keypair>* 0x00`
//! > `<output-map> := <keypair>* 0x00`
//! > ...

/// The `global-map`.
pub mod global;
/// The `input-map`.
pub mod input;
/// The `output-map`.
pub mod output;
