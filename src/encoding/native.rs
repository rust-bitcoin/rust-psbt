// SPDX-License-Identifier: CC0-1.0

//! This module contains [`PsbtEncode`] implementations for types which live outside of rust-psbt
//! but are not consensus encodable.

use core::fmt;

use bitcoin::bip32::{self, ChildNumber, KeySource, Xpub};
#[cfg(feature = "silent-payments")]
use bitcoin::CompressedPublicKey;
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, BytesEncoder, Decoder, DecoderStatus, Encoder2, UnexpectedEofError,
};

use super::{ExactSliceEncoder, PsbtDecode, PsbtEncode};
#[cfg(feature = "silent-payments")]
use crate::dleq::DleqProof;

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a serialized [`Xpub`].
    pub struct XpubEncoder<'e>(ArrayEncoder<78>);
}

impl PsbtEncode for Xpub {
    type Encoder<'e>
        = XpubEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        XpubEncoder::new(ArrayEncoder::without_length_prefix(self.encode()))
    }
}

/// Decoder for a serialized [`Xpub`].
#[derive(Debug, Default)]
pub struct XpubDecoder {
    inner: ArrayDecoder<78>,
}

impl Decoder for XpubDecoder {
    type Output = Xpub;
    type Error = XpubDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        use XpubDecodeErrorInner as E;

        self.inner.push_bytes(bytes).map_err(|e| XpubDecodeError(E::Eof(e)))
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        use XpubDecodeErrorInner as E;

        let bytes = self.inner.end().map_err(|e| XpubDecodeError(E::Eof(e)))?;
        Xpub::decode(&bytes).map_err(|e| XpubDecodeError(E::Bip32(e)))
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for Xpub {
    type Decoder = XpubDecoder;
}

/// Error decoding an [`Xpub`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XpubDecodeError(pub(super) XpubDecodeErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum XpubDecodeErrorInner {
    /// Not enough bytes were available to decode the 78-byte extended public key.
    Eof(UnexpectedEofError),
    /// The 78 bytes did not form a valid extended public key.
    Bip32(bip32::Error),
}

impl fmt::Display for XpubDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            XpubDecodeErrorInner::Eof(ref e) => write!(f, "failed to decode xpub: {}", e),
            XpubDecodeErrorInner::Bip32(ref e) => write!(f, "invalid xpub: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for XpubDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.0 {
            XpubDecodeErrorInner::Eof(ref e) => Some(e),
            XpubDecodeErrorInner::Bip32(ref e) => Some(e),
        }
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a serialized [`ChildNumber`].
    pub struct ChildNumberEncoder<'e>(ArrayEncoder<4>);
}

impl PsbtEncode for ChildNumber {
    type Encoder<'e>
        = ChildNumberEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ChildNumberEncoder::new(ArrayEncoder::without_length_prefix(u32::from(*self).to_le_bytes()))
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a serialized [`KeySource`].
    pub struct KeySourceEncoder<'e>(Encoder2<BytesEncoder<'e>, ExactSliceEncoder<'e, ChildNumber>>);
}

impl PsbtEncode for KeySource {
    type Encoder<'e>
        = KeySourceEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        KeySourceEncoder::new(Encoder2::new(
            BytesEncoder::without_length_prefix(self.0.as_bytes()),
            <ExactSliceEncoder<'_, ChildNumber>>::without_length_prefix(self.1.as_ref()),
        ))
    }
}

#[cfg(feature = "silent-payments")]
impl PsbtEncode for CompressedPublicKey {
    type Encoder<'e>
        = ArrayEncoder<33>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.to_bytes())
    }
}

#[cfg(feature = "silent-payments")]
impl PsbtEncode for DleqProof {
    type Encoder<'e>
        = BytesEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        BytesEncoder::without_length_prefix(self.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use bitcoin::bip32::Fingerprint;

    use super::*;
    use crate::encoding::{decode_from_slice, encode_to_vec};

    fn sample_xpub() -> Xpub {
        use core::str::FromStr;

        Xpub::from_str(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        )
        .unwrap()
    }

    const XPUB_BYTES: [u8; 78] = [
        0x4, 0x88, 0xb2, 0x1e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x87, 0x3d, 0xff, 0x81,
        0xc0, 0x2f, 0x52, 0x56, 0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e, 0xac, 0x3a, 0x55, 0xa0, 0x49,
        0xde, 0x3d, 0x31, 0x4b, 0xb4, 0x2e, 0xe2, 0x27, 0xff, 0xed, 0x37, 0xd5, 0x8, 0x3, 0x39,
        0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0, 0x2c, 0xc5,
        0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x5, 0xe, 0x2e, 0x8f, 0xf4, 0x9c, 0x85,
        0xc2,
    ];

    #[test]
    fn xpub_roundtrip() {
        let xpub = sample_xpub();
        let bytes = encode_to_vec(&xpub);
        assert_eq!(bytes.len(), 78);
        assert_eq!(decode_from_slice::<Xpub>(&bytes).unwrap(), xpub);
    }

    #[test]
    fn xpub_decode_truncated_is_eof_error() {
        let bytes = encode_to_vec(&sample_xpub());
        let err = decode_from_slice::<Xpub>(&bytes[..77]).unwrap_err();
        assert!(matches!(
            err,
            bitcoin_consensus_encoding::DecodeError::Parse(XpubDecodeError(
                XpubDecodeErrorInner::Eof(_)
            ))
        ));
    }

    #[test]
    fn xpub_decode_invalid_is_bip32_error() {
        let bytes = [0u8; 78];
        let err = decode_from_slice::<Xpub>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            bitcoin_consensus_encoding::DecodeError::Parse(XpubDecodeError(
                XpubDecodeErrorInner::Bip32(_)
            ))
        ));
    }

    #[test]
    fn xpub_decoder_read_limit() {
        let mut decoder = XpubDecoder::default();
        assert_eq!(decoder.read_limit(), 78);

        let mut bytes: &[u8] = &XPUB_BYTES;
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    fn key_source_encode_empty_path() {
        use bitcoin::bip32::DerivationPath;

        let key_source: KeySource =
            (Fingerprint::from([0x42, 0x99, 0x69, 0xf0]), DerivationPath::default());
        let bytes = encode_to_vec(&key_source);
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes, [0x42, 0x99, 0x69, 0xf0]);
    }

    #[test]
    fn key_source_encode_multi_element_path() {
        use bitcoin::bip32::DerivationPath;

        let path: DerivationPath = [
            ChildNumber::from_hardened_idx(84).unwrap(),
            ChildNumber::from_normal_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(2).unwrap(),
        ]
        .into_iter()
        .collect();
        let key_source: KeySource = (Fingerprint::from([0x12, 0x34, 0x56, 0x78]), path);

        let bytes = encode_to_vec(&key_source);
        assert_eq!(bytes.len(), 4 + 3 * 4);
        let mut expected = vec![0x12, 0x34, 0x56, 0x78];
        for n in &key_source.1 {
            expected.extend(u32::from(*n).to_le_bytes());
        }
        assert_eq!(bytes, expected);
    }
}
