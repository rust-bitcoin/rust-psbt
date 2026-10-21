// SPDX-License-Identifier: CC0-1.0

//! PSBT-specific taproot field types.
//!
//! These are tuples of upstream [`bitcoin`] taproot types that exist only as PSBT field key,
//! value, or key-data types and have no single named upstream representation. They are shared by
//! multiple map types (e.g. input and output).

use alloc::vec::Vec;
use core::fmt;

use bitcoin::bip32::{self, ChildNumber, KeySource};
use bitcoin::hashes::Hash as _;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::ScriptBuf;
use bitcoin_consensus_encoding::{
    ArrayEncoder, ByteVecDecoder, ByteVecDecoderError, BytesEncoder, Decoder, DecoderStatus,
    Encoder2,
};

use crate::encoding::codecs::key_source::KeySourceEncoder;
use crate::encoding::{PrefixedSliceEncoder, PsbtEncode};

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a `(XOnlyPublicKey, TapLeafHash)` composite (32 byte + 32 byte).
    pub struct XOnlyLeafHashPairEncoder<'e>(Encoder2<ArrayEncoder<32>, ArrayEncoder<32>>);
}

impl PsbtEncode for (XOnlyPublicKey, TapLeafHash) {
    type Encoder<'e>
        = XOnlyLeafHashPairEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        XOnlyLeafHashPairEncoder::new(Encoder2::new(self.0.psbt_encoder(), self.1.psbt_encoder()))
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a `(ScriptBuf, LeafVersion)` composite (`script bytes + 1 byte for version tag`).
    pub struct ScriptBufLeafPairEncoder<'e>(Encoder2<BytesEncoder<'e>, ArrayEncoder<1>>);
}

impl PsbtEncode for (ScriptBuf, LeafVersion) {
    type Encoder<'e>
        = ScriptBufLeafPairEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ScriptBufLeafPairEncoder::new(Encoder2::new(self.0.psbt_encoder(), self.1.psbt_encoder()))
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a `(Vec<TapLeafHash>, KeySource)` composite: `count <hash*a> <key source>` where `count` is a compact-size prefix.
    pub struct LeafHashVecKeySourceEncoder<'e>(
        Encoder2<PrefixedSliceEncoder<'e, TapLeafHash>, KeySourceEncoder<'e>>
    );
}

impl PsbtEncode for (Vec<TapLeafHash>, KeySource) {
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

/// Decoder for a tap leaf script value: `(ScriptBuf, LeafVersion)`.
#[derive(Debug, Default)]
pub struct TapLeafScriptDecoder {
    inner: ByteVecDecoder,
}

impl Decoder for TapLeafScriptDecoder {
    type Output = (ScriptBuf, LeafVersion);
    type Error = TapLeafScriptDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(TapLeafScriptDecodeError::ByteVec)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let value = self.inner.end().map_err(TapLeafScriptDecodeError::ByteVec)?;
        if value.is_empty() {
            return Err(TapLeafScriptDecodeError::Empty);
        }
        let last = value.len() - 1;
        let script = ScriptBuf::from_bytes(value[..last].to_vec());
        let ver = LeafVersion::from_consensus(value[last])
            .map_err(|_| TapLeafScriptDecodeError::InvalidLeafVersion)?;
        Ok((script, ver))
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

/// Error decoding a tap leaf script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapLeafScriptDecodeError {
    /// The inner byte-vector decoder encountered an error.
    ByteVec(ByteVecDecoderError),
    /// The value is empty (needs at least a leaf version byte).
    Empty,
    /// The last byte is not a valid leaf version.
    InvalidLeafVersion,
}

impl fmt::Display for TapLeafScriptDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByteVec(e) => write!(f, "error decoding tap leaf script: {e}"),
            Self::Empty => write!(f, "tap leaf script value is empty"),
            Self::InvalidLeafVersion => write!(f, "invalid leaf version in tap leaf script"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TapLeafScriptDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ByteVec(e) => Some(e),
            Self::Empty | Self::InvalidLeafVersion => None,
        }
    }
}

/// Decoder for an output tap key origin value: `(Vec<TapLeafHash>, KeySource)`.
#[derive(Debug, Default)]
pub struct TapKeyOriginDecoder {
    inner: ByteVecDecoder,
}

impl Decoder for TapKeyOriginDecoder {
    type Output = (Vec<TapLeafHash>, KeySource);
    type Error = TapKeyOriginDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(TapKeyOriginDecodeError::ByteVec)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let value = self.inner.end().map_err(TapKeyOriginDecodeError::ByteVec)?;

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

/// Error decoding an output tap key origin value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapKeyOriginDecodeError {
    /// The inner byte-vector decoder encountered an error.
    ByteVec(ByteVecDecoderError),
    /// The value does not contain a valid fingerprint.
    MissingFingerprint,
}

impl fmt::Display for TapKeyOriginDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByteVec(e) => write!(f, "error decoding tap key origin: {e}"),
            Self::MissingFingerprint => write!(f, "tap key origin missing fingerprint"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TapKeyOriginDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ByteVec(e) => Some(e),
            Self::MissingFingerprint => None,
        }
    }
}
