// SPDX-License-Identifier: CC0-1.0

//! Tap key origin PSBT field value type.
//!
//! Corresponds to the value format of PSBT key types `PSBT_IN_TAP_BIP32_DERIVATION` (0x16)
//! and `PSBT_OUT_TAP_BIP32_DERIVATION` (0x07) as defined in [BIP-371].
//!
//! [BIP-371]: <https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki>

use alloc::vec::Vec;
use core::fmt;

use bitcoin::bip32::{self, ChildNumber, KeySource};
use bitcoin::hashes::Hash as _;
use bitcoin::taproot::TapLeafHash;
use bitcoin_consensus_encoding::{
    ByteVecDecoder, ByteVecDecoderError, Decoder, DecoderStatus, Encoder2,
};

use crate::encoding::codecs::key_source::KeySourceEncoder;
use crate::encoding::{PrefixedSliceEncoder, PsbtDecode, PsbtEncode};

/// A tap key origin: leaf hashes with a key source.
pub(crate) type TapKeyOrigin = (Vec<TapLeafHash>, KeySource);

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a [`TapKeyOrigin`] value: `count <hash*a> <key source>` where `count` is a
    /// compact-size prefix.
    pub struct LeafHashVecKeySourceEncoder<'e>(
        Encoder2<PrefixedSliceEncoder<'e, TapLeafHash>, KeySourceEncoder<'e>>
    );
}

impl PsbtEncode for TapKeyOrigin {
    type Encoder<'e>
        = LeafHashVecKeySourceEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        LeafHashVecKeySourceEncoder::new(Encoder2::new(
            <PrefixedSliceEncoder<'_, TapLeafHash>>::new(self.0.as_slice()),
            self.1.psbt_encoder(),
        ))
    }
}

/// Decoder for a [`TapKeyOrigin`] value.
///
/// Delegates to [`ByteVecDecoder`] for DoS-resistant buffered reading, then parses
/// the value: `<count> <hash*count> <fingerprint> <derivation path>`.
#[derive(Debug, Default)]
pub struct TapKeyOriginDecoder {
    inner: ByteVecDecoder,
}

impl Decoder for TapKeyOriginDecoder {
    type Output = TapKeyOrigin;
    type Error = TapKeyOriginDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(TapKeyOriginDecodeError::Decode)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let value = self.inner.end().map_err(TapKeyOriginDecodeError::Decode)?;

        if value.is_empty() {
            return Err(TapKeyOriginDecodeError::MissingFingerprint);
        }

        let count = value[0] as usize;
        let hash_end = 1 + count * 32;
        if value.len() < hash_end + 4 {
            return Err(TapKeyOriginDecodeError::MissingFingerprint);
        }
        let leaf_hashes: Vec<TapLeafHash> = value[1..hash_end]
            .chunks_exact(32)
            .map(|chunk| TapLeafHash::from_slice(chunk).expect("32 bytes"))
            .collect();

        let fprint = bip32::Fingerprint::from(
            <[u8; 4]>::try_from(&value[hash_end..hash_end + 4]).expect("4 bytes"),
        );

        let mut dpath: Vec<ChildNumber> = Default::default();
        for chunk in value[hash_end + 4..].chunks_exact(4) {
            let index = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
            dpath.push(ChildNumber::from(index));
        }

        let ks = (fprint, bip32::DerivationPath::from(dpath));
        Ok((leaf_hashes, ks))
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for TapKeyOrigin {
    type Decoder = TapKeyOriginDecoder;
}

/// Error decoding a [`TapKeyOrigin`] value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapKeyOriginDecodeError {
    /// The inner byte-vector decoder encountered an error.
    Decode(ByteVecDecoderError),
    /// The value does not contain a valid fingerprint.
    MissingFingerprint,
}

impl fmt::Display for TapKeyOriginDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "error decoding tap key origin: {e}"),
            Self::MissingFingerprint => write!(f, "tap key origin missing fingerprint"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TapKeyOriginDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            Self::MissingFingerprint => None,
        }
    }
}
