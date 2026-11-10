// SPDX-License-Identifier: CC0-1.0

//! PSBT Proof of Reserves commitment (`PSBT_IN_POR_COMMITMENT`).
//!
//! Defined in [BIP-127], each input may carry a proof-of-reserves commitment message.
//! The value is encoded as a UTF-8 byte sequence.
//!
//! [BIP-127]: <https://github.com/bitcoin/bips/blob/master/bip-0127.mediawiki>

use alloc::string::String;
use core::fmt;

use bitcoin_consensus_encoding::{
    ByteVecDecoder, ByteVecDecoderError, BytesEncoder, Decoder, DecoderStatus,
};

use crate::encoding::{PsbtDecode, PsbtEncode};

/// Proof of Reserves commitment message (BIP-127, `PSBT_IN_POR_COMMITMENT = 0x09`).
///
/// A UTF-8 encoded message string used in proof-of-reserves transactions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PorCommitment(pub String);

impl fmt::Display for PorCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a [`PorCommitment`] value (UTF-8 bytes).
    pub struct PorCommitmentEncoder<'e>(BytesEncoder<'e>);
}

impl PsbtEncode for PorCommitment {
    type Encoder<'e>
        = PorCommitmentEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        PorCommitmentEncoder::new(BytesEncoder::without_length_prefix(self.0.as_bytes()))
    }
}

/// Decoder for a [`PorCommitment`] value (UTF-8 bytes).
#[derive(Debug, Default)]
pub struct PorCommitmentDecoder(ByteVecDecoder);

impl Decoder for PorCommitmentDecoder {
    type Output = PorCommitment;
    type Error = PorCommitmentDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes).map_err(PorCommitmentDecodeError::Bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.0.end().map_err(PorCommitmentDecodeError::Bytes)?;
        let s = String::from_utf8(bytes).map_err(PorCommitmentDecodeError::Utf8)?;
        Ok(PorCommitment(s))
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl PsbtDecode for PorCommitment {
    type Decoder = PorCommitmentDecoder;
}

/// Error decoding a [`PorCommitment`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PorCommitmentDecodeError {
    /// Error decoding the raw bytes.
    Bytes(ByteVecDecoderError),
    /// The bytes are not valid UTF-8.
    Utf8(alloc::string::FromUtf8Error),
}

impl fmt::Display for PorCommitmentDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(e) => write!(f, "error decoding por commitment bytes: {e}"),
            Self::Utf8(e) => write!(f, "por commitment is not valid UTF-8: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PorCommitmentDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bytes(e) => Some(e),
            Self::Utf8(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::*;
    use crate::encoding::decode_from_slice;

    #[test]
    fn display() {
        let msg = PorCommitment(String::from("reserve proof"));
        assert_eq!(alloc::format!("{msg}"), "reserve proof");
    }

    #[test]
    fn read_limit_lifecycle() {
        let mut decoder = PorCommitmentDecoder::default();
        assert_eq!(decoder.read_limit(), 1, "fresh decoder should request 1 byte");

        // compact_size(4) || "test"
        let mut bytes: &[u8] = &[0x04];
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.needs_more(), "decoder should need more after prefix");
        assert_eq!(decoder.read_limit(), 4, "after prefix, decoder should request 4 payload bytes");

        let mut bytes: &[u8] = &[0x74, 0x65, 0x73, 0x74];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0, "completed decoder should request no bytes");
    }

    #[test]
    fn decode_rejects_invalid_utf8() {
        // A single 0xFF byte is never valid UTF-8.
        let bytes = [0xffu8];
        // The PSBT encoding of PorCommitment is:
        //   compact_size(len) || data
        let mut encoded = Vec::new();
        // Compact size 1
        encoded.push(1u8);
        encoded.extend_from_slice(&bytes);

        let err = decode_from_slice::<PorCommitment>(&encoded).unwrap_err();
        // The error should be a Parse error containing PorCommitmentDecodeError::Utf8.
        assert!(matches!(
            err,
            bitcoin_consensus_encoding::DecodeError::Parse(PorCommitmentDecodeError::Utf8(_))
        ));
    }
}
