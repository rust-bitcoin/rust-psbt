// SPDX-License-Identifier: CC0-1.0

//! PSBT codecs for MuSig2 types defined in [BIP-373].
//!
//! [BIP-373]: https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki

use core::fmt;

use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decoder, DecoderStatus, UnexpectedEofError,
};
use secp256k1_33 as secp256k1;

use crate::encoding::{PsbtDecode, PsbtEncode};

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for [`secp256k1::musig::PublicNonce`].
    pub struct PublicNonceEncoder<'e>(ArrayEncoder<{ secp256k1::musig::PUBNONCE_SERIALIZED_SIZE }>);
}

impl PsbtEncode for secp256k1::musig::PublicNonce {
    type Encoder<'e>
        = PublicNonceEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        PublicNonceEncoder::new(ArrayEncoder::without_length_prefix(self.serialize()))
    }
}

/// Decoder for [`secp256k1::musig::PublicNonce`].
#[derive(Debug, Default)]
pub struct PublicNonceDecoder {
    inner: ArrayDecoder<{ secp256k1::musig::PUBNONCE_SERIALIZED_SIZE }>,
}

impl Decoder for PublicNonceDecoder {
    type Output = secp256k1::musig::PublicNonce;
    type Error = PublicNonceDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(PublicNonceDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end().map_err(PublicNonceDecodeError::UnexpectedEof)?;
        secp256k1::musig::PublicNonce::from_byte_array(&bytes)
            .map_err(PublicNonceDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for secp256k1::musig::PublicNonce {
    type Decoder = PublicNonceDecoder;
}

/// Error returned by [`PublicNonceDecoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicNonceDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The bytes did not form a valid MuSig2 public nonce.
    Invalid(secp256k1::musig::ParseError),
}

impl fmt::Display for PublicNonceDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding public nonce: {e}"),
            Self::Invalid(e) => write!(f, "invalid public nonce: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PublicNonceDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::Invalid(e) => Some(e),
        }
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for [`secp256k1::musig::PartialSignature`].
    pub struct PartialSignatureEncoder<'e>(ArrayEncoder<{ secp256k1::musig::PART_SIG_SERIALIZED_SIZE }>);
}

impl PsbtEncode for secp256k1::musig::PartialSignature {
    type Encoder<'e>
        = PartialSignatureEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        PartialSignatureEncoder::new(ArrayEncoder::without_length_prefix(self.serialize()))
    }
}

/// Decoder for [`secp256k1::musig::PartialSignature`].
#[derive(Debug, Default)]
pub struct PartialSignatureDecoder {
    inner: ArrayDecoder<{ secp256k1::musig::PART_SIG_SERIALIZED_SIZE }>,
}

impl Decoder for PartialSignatureDecoder {
    type Output = secp256k1::musig::PartialSignature;
    type Error = PartialSignatureDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(PartialSignatureDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end().map_err(PartialSignatureDecodeError::UnexpectedEof)?;
        secp256k1::musig::PartialSignature::from_byte_array(&bytes)
            .map_err(PartialSignatureDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for secp256k1::musig::PartialSignature {
    type Decoder = PartialSignatureDecoder;
}

/// Error returned by [`PartialSignatureDecoder`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartialSignatureDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The bytes did not form a valid MuSig2 partial signature.
    Invalid(secp256k1::musig::ParseError),
}

impl fmt::Display for PartialSignatureDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding partial signature: {e}"),
            Self::Invalid(e) => write!(f, "invalid partial signature: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PartialSignatureDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::Invalid(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{decode_from_slice, encode_to_vec};

    #[test]
    fn public_nonce_roundtrip() {
        let bytes = [0x02u8; secp256k1::musig::PUBNONCE_SERIALIZED_SIZE];
        let nonce = secp256k1::musig::PublicNonce::from_byte_array(&bytes).expect("valid nonce");
        let encoded = encode_to_vec(&nonce);
        let decoded =
            decode_from_slice::<secp256k1::musig::PublicNonce>(&encoded).expect("decoding");
        assert_eq!(nonce, decoded);
    }

    #[test]
    fn public_nonce_read_limit() {
        let mut decoder = PublicNonceDecoder::default();
        assert_eq!(decoder.read_limit(), secp256k1::musig::PUBNONCE_SERIALIZED_SIZE);

        let mut bytes: &[u8] = &[0x02u8; secp256k1::musig::PUBNONCE_SERIALIZED_SIZE];
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    fn partial_signature_roundtrip() {
        let bytes = [0x42u8; secp256k1::musig::PART_SIG_SERIALIZED_SIZE];
        let sig = secp256k1::musig::PartialSignature::from_byte_array(&bytes).expect("valid sig");
        let encoded = encode_to_vec(&sig);
        let decoded =
            decode_from_slice::<secp256k1::musig::PartialSignature>(&encoded).expect("decoding");
        assert_eq!(sig, decoded);
    }

    #[test]
    fn partial_signature_read_limit() {
        let mut decoder = PartialSignatureDecoder::default();
        assert_eq!(decoder.read_limit(), secp256k1::musig::PART_SIG_SERIALIZED_SIZE);

        let mut bytes: &[u8] = &[0x42u8; secp256k1::musig::PART_SIG_SERIALIZED_SIZE];
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }
}
