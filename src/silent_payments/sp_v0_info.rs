// SPDX-License-Identifier: CC0-1.0

//! BIP-375: Support for silent payments in PSBTs.
//!
//! This module provides a type-safe wrapper for the BIP-375 `PSBT_OUT_SP_V0_INFO` field.

use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1;

/// A silent payment v0 address, as carried by `PSBT_OUT_SP_V0_INFO` (BIP-375).
///
/// Serialized as 66 bytes: the recipient's scan key followed by their spend key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SpV0Info {
    scan_key: CompressedPublicKey,
    spend_key: CompressedPublicKey,
}

impl SpV0Info {
    /// Constructs the field from a recipient's scan and spend keys.
    pub fn new(scan_key: CompressedPublicKey, spend_key: CompressedPublicKey) -> Self {
        Self { scan_key, spend_key }
    }

    /// Constructs the field from its 66-byte encoding: the scan key followed by the spend key.
    pub fn from_byte_array(bytes: &[u8; 66]) -> Result<Self, secp256k1::Error> {
        Ok(Self {
            scan_key: CompressedPublicKey::from_slice(&bytes[..33])?,
            spend_key: CompressedPublicKey::from_slice(&bytes[33..])?,
        })
    }

    /// Returns the recipient's scan key.
    pub fn scan_key(&self) -> CompressedPublicKey { self.scan_key }

    /// Returns the recipient's spend key.
    pub fn spend_key(&self) -> CompressedPublicKey { self.spend_key }
}
