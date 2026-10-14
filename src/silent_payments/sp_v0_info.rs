// SPDX-License-Identifier: CC0-1.0

//! BIP-375: Support for silent payments in PSBTs.
//!
//! This module provides a type-safe wrapper for the BIP-375 `PSBT_OUT_SP_V0_INFO` field.

use core::fmt;

use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1;
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decoder, DecoderStatus, Encoder2, UnexpectedEofError,
};

use crate::{PsbtDecode, PsbtEncode};

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

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a [`SpV0Info`]: the scan key followed by the spend key (33 byte + 33 byte).
    pub struct SpV0InfoEncoder<'e>(Encoder2<ArrayEncoder<33>, ArrayEncoder<33>>);
}

impl PsbtEncode for SpV0Info {
    type Encoder<'e>
        = SpV0InfoEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        SpV0InfoEncoder::new(Encoder2::new(
            self.scan_key().psbt_encoder(),
            self.spend_key().psbt_encoder(),
        ))
    }
}

/// Decoder for a [`SpV0Info`] value (66 bytes: scan key + spend key).
#[derive(Debug, Default)]
pub struct SpV0InfoDecoder {
    inner: ArrayDecoder<66>,
}

impl Decoder for SpV0InfoDecoder {
    type Output = SpV0Info;
    type Error = SpV0InfoDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(SpV0InfoDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end().map_err(SpV0InfoDecodeError::UnexpectedEof)?;
        SpV0Info::from_byte_array(&bytes).map_err(SpV0InfoDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for SpV0Info {
    type Decoder = SpV0InfoDecoder;
}

/// Error decoding a [`SpV0Info`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpV0InfoDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The bytes did not form valid compressed public keys.
    Invalid(secp256k1::Error),
}

impl fmt::Display for SpV0InfoDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding SP v0 info: {e}"),
            Self::Invalid(e) => write!(f, "invalid SP v0 info: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SpV0InfoDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::Invalid(e) => Some(e),
        }
    }
}

/// Decoder for a silent-payments v0 label value (4-byte little-endian u32).
#[derive(Debug, Default)]
pub struct SpV0LabelDecoder {
    inner: ArrayDecoder<4>,
}

impl Decoder for SpV0LabelDecoder {
    type Output = u32;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}
