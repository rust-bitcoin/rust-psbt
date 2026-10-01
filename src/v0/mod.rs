// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions Version 0 codec.
//!
//! v0 PSBTs are handled through the explicit decode/encode entry points on [`psbt::Psbt`]
//! implemented at the bottom of this file.

use core::fmt;

use crate::{psbt, DetermineLockTimeError};

/// Reports which v2-only fields will be demoted to unknown key-value pairs by a v0
/// (BIP-174) encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Degraded {
    /// Number of silent payment ECDH shares encoded as unknown global keys (`0x07`).
    pub sp_ecdh_shares: usize,
    /// Number of silent payment DLEQ proofs encoded as unknown global keys from the global map
    /// (`0x08`).
    pub sp_dleq_proofs: usize,
    /// Number of inputs whose silent payment fields were encoded as unknown
    /// per-input keys (`0x1d` / `0x1e`).
    pub sp_dropped_inputs: usize,
    /// Number of outputs whose silent payment fields were encoded as unknown per-output keys
    /// (`0x09` and/or `0x0a` was `Some`).
    pub sp_dropped_outputs: usize,
}

impl Degraded {
    /// Returns `true` if no fields were demoted to unknowns.
    pub fn is_empty(&self) -> bool {
        self.sp_ecdh_shares == 0
            && self.sp_dleq_proofs == 0
            && self.sp_dropped_inputs == 0
            && self.sp_dropped_outputs == 0
    }
}

impl psbt::Psbt {
    /// Computes which v2 fields will be degraded to unknown keys by a v0 encoding.
    pub fn v0_degraded(&self) -> Degraded {
        #[cfg(feature = "silent-payments")]
        {
            Degraded {
                sp_ecdh_shares: self.global.sp_ecdh_shares.len(),
                sp_dleq_proofs: self.global.sp_dleq_proofs.len(),
                sp_dropped_inputs: self
                    .inputs
                    .iter()
                    .filter(|i| !i.sp_ecdh_shares.is_empty() || !i.sp_dleq_proofs.is_empty())
                    .count(),
                sp_dropped_outputs: self
                    .outputs
                    .iter()
                    .filter(|o| o.sp_v0_info.is_some() || o.sp_v0_label.is_some())
                    .count(),
            }
        }
        #[cfg(not(feature = "silent-payments"))]
        {
            Degraded::default()
        }
    }

    /// Deserializes a PSBT v0 (BIP-174) from raw data.
    ///
    /// This only accepts v0 PSBTs, use [`Self::deserialize`] for v2 PSBTs (BIP-370).
    pub fn deserialize_v0(bytes: &[u8]) -> Result<Self, DeserializeV0Error> {
        bitcoin_consensus_encoding::decode_from_slice_with_decoder::<crate::psbt::PsbtV0Decoder>(
            bytes,
        )
        .map_err(DeserializeV0Error)
    }

    /// Consumes this PSBT and locks it as PSBT v0 (BIP-174).
    ///
    /// v2-only fields without v0 equivalents are preserved as unknown key-value pairs when
    /// encoding. Use [`Self::v0_degraded`] to inspect what was demoted to unknowns.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction lock time cannot be determined from the PSBT's
    /// lock time fields.
    pub fn into_psbt_v0(self) -> Result<crate::psbt::PsbtV0, DetermineLockTimeError> {
        crate::psbt::PsbtV0::from_psbt(self)
    }

    /// Deserializes a PSBT v0 (BIP-174) from a base64 encoded string.
    #[cfg(feature = "base64")]
    pub fn deserialize_v0_base64(s: &str) -> Result<Self, ParsePsbtV0Error> {
        use ::bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};

        let data = BASE64_STANDARD.decode(s).map_err(ParsePsbtV0Error::Base64Encoding)?;
        Self::deserialize_v0(&data).map_err(ParsePsbtV0Error::PsbtEncoding)
    }
}

/// Error deserializing a BIP-174 (PSBT v0) PSBT.
#[derive(Debug)]
pub struct DeserializeV0Error(
    bitcoin_consensus_encoding::DecodeError<crate::error::DeserializeError>,
);

impl fmt::Display for DeserializeV0Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "v0 PSBT: {}", self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializeV0Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Error parsing a BIP-174 (PSBT v0) PSBT from a base64 string.
#[cfg(feature = "base64")]
#[derive(Debug)]
pub enum ParsePsbtV0Error {
    /// Error in the v0 PSBT encoding.
    PsbtEncoding(DeserializeV0Error),
    /// Error in the base64 encoding.
    Base64Encoding(::bitcoin::base64::DecodeError),
}

#[cfg(feature = "base64")]
impl fmt::Display for ParsePsbtV0Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParsePsbtV0Error::*;

        match *self {
            PsbtEncoding(ref e) => write!(f, "error in v0 PSBT encoding: {}", e),
            Base64Encoding(ref e) => write!(f, "error in PSBT base64 encoding: {}", e),
        }
    }
}

#[cfg(all(feature = "std", feature = "base64"))]
impl std::error::Error for ParsePsbtV0Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParsePsbtV0Error::*;

        match *self {
            PsbtEncoding(ref e) => Some(e),
            Base64Encoding(ref e) => Some(e),
        }
    }
}
