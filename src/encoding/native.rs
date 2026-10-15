// SPDX-License-Identifier: CC0-1.0

//! This module contains [`PsbtEncode`] implementations for types which live outside of rust-psbt
//! but are not consensus encodable.

use alloc::borrow::ToOwned as _;
use alloc::collections::btree_map;
use alloc::vec::Vec;
use core::fmt;
use core::ops::BitOr as _;

use bitcoin::bip32::{self, ChildNumber, KeySource, Xpub};
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash as _};
use bitcoin::key::{PublicKey, XOnlyPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::taproot::{
    self, ControlBlock, LeafVersion, ScriptLeaves, TapLeafHash, TapNodeHash, TapTree,
};
use bitcoin::{ecdsa, CompressedPublicKey, ScriptBuf, Txid, VarInt};
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, ByteVecDecoderError, BytesEncoder,
    CompactSizeDecoder, CompactSizeEncoder, Decoder, DecoderStatus, Encoder, Encoder2, Encoder4,
    EncoderStatus, ExactSizeEncoder, IterEncoder, UnexpectedEofError,
};

use super::{
    BytesKeyValueIter, KeyValueIter, PrefixedSliceEncoder, PsbtDecode, PsbtEncode, SliceEncoder,
};
#[cfg(feature = "silent-payments")]
use crate::consts::{
    PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_IN_SP_DLEQ, PSBT_IN_SP_ECDH_SHARE,
};
use crate::consts::{
    PSBT_GLOBAL_XPUB, PSBT_IN_BIP32_DERIVATION, PSBT_IN_HASH160, PSBT_IN_HASH256,
    PSBT_IN_PARTIAL_SIG, PSBT_IN_RIPEMD160, PSBT_IN_SHA256, PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_LEAF_SCRIPT, PSBT_IN_TAP_SCRIPT_SIG, PSBT_OUT_BIP32_DERIVATION,
    PSBT_OUT_TAP_BIP32_DERIVATION,
};
use crate::encoding::KeyValueEncoder;
use crate::sighash_type::PsbtSighashType;
#[cfg(feature = "silent-payments")]
use crate::silent_payments::{DleqProof, SpV0Info};

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

pub(crate) type XpubKeyValueIter<'e> =
    KeyValueIter<btree_map::Iter<'e, Xpub, KeySource>, PSBT_GLOBAL_XPUB>;

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
    pub struct KeySourceEncoder<'e>(Encoder2<BytesEncoder<'e>, SliceEncoder<'e, ChildNumber>>);
}

impl PsbtEncode for KeySource {
    type Encoder<'e>
        = KeySourceEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        KeySourceEncoder::new(Encoder2::new(
            BytesEncoder::without_length_prefix(self.0.as_bytes()),
            <SliceEncoder<'_, ChildNumber>>::without_length_prefix(self.1.as_ref()),
        ))
    }
}

/// Decoder for a [`KeySource`] value (fingerprint + derivation path).
#[derive(Debug, Default)]
pub struct KeySourceDecoder {
    inner: ByteVecDecoder,
}

impl Decoder for KeySourceDecoder {
    type Output = KeySource;
    type Error = KeySourceDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(KeySourceDecodeError::ByteVec)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        use bitcoin::bip32::{DerivationPath, Fingerprint};

        let bytes = self.inner.end().map_err(KeySourceDecodeError::ByteVec)?;
        if bytes.len() < 4 {
            return Err(KeySourceDecodeError::TooShort(bytes.len()));
        }
        if bytes.len() % 4 != 0 {
            return Err(KeySourceDecodeError::InvalidPathLength(bytes.len()));
        }
        let fingerprint = Fingerprint::from(<[u8; 4]>::try_from(&bytes[..4]).expect("4 bytes"));
        let path = bytes[4..]
            .chunks_exact(4)
            .map(|c| ChildNumber::from(u32::from_le_bytes(c.try_into().expect("4-byte chunks"))))
            .collect::<Vec<_>>();
        Ok((fingerprint, DerivationPath::from(path)))
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for KeySource {
    type Decoder = KeySourceDecoder;
}

/// Error decoding a [`KeySource`] (fingerprint + derivation path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySourceDecodeError {
    /// The inner byte-vector decoder encountered an error.
    ByteVec(ByteVecDecoderError),
    /// The value is shorter than the 4-byte fingerprint.
    TooShort(usize),
    /// The derivation path is not a multiple of 4 bytes.
    InvalidPathLength(usize),
}

impl fmt::Display for KeySourceDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByteVec(e) => write!(f, "error decoding key source: {e}"),
            Self::TooShort(len) =>
                write!(f, "key source too short ({} bytes, need at least 4)", len),
            Self::InvalidPathLength(len) =>
                write!(f, "key source path not aligned ({} bytes, not a multiple of 4)", len),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeySourceDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ByteVec(e) => Some(e),
            Self::TooShort(_) | Self::InvalidPathLength(_) => None,
        }
    }
}

impl PsbtEncode for absolute::Time {
    type Encoder<'e>
        = ArrayEncoder<4>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.to_consensus_u32().to_le_bytes())
    }
}

pub(crate) type MinTimePair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <absolute::Time as PsbtEncode>::Encoder<'e>>;

impl PsbtEncode for absolute::Height {
    type Encoder<'e>
        = ArrayEncoder<4>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.to_consensus_u32().to_le_bytes())
    }
}

pub(crate) type MinHeightPair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <absolute::Height as PsbtEncode>::Encoder<'e>>;

pub(crate) type SighashPair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <PsbtSighashType as PsbtEncode>::Encoder<'e>>;

impl PsbtEncode for XOnlyPublicKey {
    type Encoder<'e>
        = ArrayEncoder<32>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.serialize())
    }
}

pub(crate) type TapInternalKeyPair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <XOnlyPublicKey as PsbtEncode>::Encoder<'e>>;

/// Decoder for an [`XOnlyPublicKey`] value (32 bytes).
#[derive(Debug, Default)]
pub struct XOnlyPublicKeyDecoder {
    inner: ArrayDecoder<32>,
}

impl Decoder for XOnlyPublicKeyDecoder {
    type Output = XOnlyPublicKey;
    type Error = XOnlyPublicKeyDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(XOnlyPublicKeyDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end().map_err(XOnlyPublicKeyDecodeError::UnexpectedEof)?;
        XOnlyPublicKey::from_slice(&bytes).map_err(XOnlyPublicKeyDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for XOnlyPublicKey {
    type Decoder = XOnlyPublicKeyDecoder;
}

/// Error decoding an [`XOnlyPublicKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XOnlyPublicKeyDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The 32 bytes did not form a valid x-only public key.
    Invalid(bitcoin::secp256k1::Error),
}

impl fmt::Display for XOnlyPublicKeyDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding x-only public key: {e}"),
            Self::Invalid(e) => write!(f, "invalid x-only public key: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for XOnlyPublicKeyDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::Invalid(e) => Some(e),
        }
    }
}

/// Decoder for a [`Txid`] value (32 bytes).
#[derive(Debug, Default)]
pub struct TxidDecoder {
    inner: ArrayDecoder<32>,
}

impl Decoder for TxidDecoder {
    type Output = Txid;
    type Error = TxidDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(TxidDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end().map_err(TxidDecodeError::UnexpectedEof)?;
        Txid::from_slice(&bytes).map_err(TxidDecodeError::InvalidHash)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for Txid {
    type Decoder = TxidDecoder;
}

/// Error decoding a [`Txid`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxidDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The 32 bytes did not form a valid txid.
    InvalidHash(bitcoin::hashes::FromSliceError),
}

impl fmt::Display for TxidDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding txid: {e}"),
            Self::InvalidHash(e) => write!(f, "invalid txid: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TxidDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::InvalidHash(e) => Some(e),
        }
    }
}

/// Decoder for a [`TapNodeHash`] value (32 bytes).
#[derive(Debug, Default)]
pub struct TapNodeHashDecoder {
    inner: ArrayDecoder<32>,
}

impl Decoder for TapNodeHashDecoder {
    type Output = TapNodeHash;
    type Error = TapNodeHashDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(TapNodeHashDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end().map_err(TapNodeHashDecodeError::UnexpectedEof)?;
        TapNodeHash::from_slice(&bytes).map_err(TapNodeHashDecodeError::InvalidHash)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for TapNodeHash {
    type Decoder = TapNodeHashDecoder;
}

/// Error decoding a [`TapNodeHash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapNodeHashDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The 32 bytes did not form a valid tap node hash.
    InvalidHash(bitcoin::hashes::FromSliceError),
}

impl fmt::Display for TapNodeHashDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding tap node hash: {e}"),
            Self::InvalidHash(e) => write!(f, "invalid tap node hash: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TapNodeHashDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::InvalidHash(e) => Some(e),
        }
    }
}
#[derive(Debug, Default)]
pub struct TimeDecoder {
    inner: ArrayDecoder<4>,
}

impl Decoder for TimeDecoder {
    type Output = absolute::Time;
    type Error = TimeDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(TimeDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end().map_err(TimeDecodeError::UnexpectedEof)?;
        absolute::Time::from_consensus(u32::from_le_bytes(bytes))
            .map_err(|_| TimeDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for absolute::Time {
    type Decoder = TimeDecoder;
}

/// Error decoding a minimum lock time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The value is not a valid lock time.
    Invalid,
}

impl fmt::Display for TimeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding lock time: {e}"),
            Self::Invalid => write!(f, "invalid lock time value"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TimeDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::Invalid => None,
        }
    }
}

/// Decoder for a minimum lock height value (4 bytes, u32 LE).
#[derive(Debug, Default)]
pub struct HeightDecoder {
    inner: ArrayDecoder<4>,
}

impl Decoder for HeightDecoder {
    type Output = absolute::Height;
    type Error = HeightDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(HeightDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end().map_err(HeightDecodeError::UnexpectedEof)?;
        absolute::Height::from_consensus(u32::from_le_bytes(bytes))
            .map_err(|_| HeightDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for absolute::Height {
    type Decoder = HeightDecoder;
}

/// Error decoding a minimum lock height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeightDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The value is not a valid block height.
    Invalid,
}

impl fmt::Display for HeightDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding lock height: {e}"),
            Self::Invalid => write!(f, "invalid lock height value"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HeightDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::Invalid => None,
        }
    }
}

macro_rules! impl_hash_encoder {
    ($ty:ty, $len:expr) => {
        impl PsbtEncode for $ty {
            type Encoder<'e>
                = ArrayEncoder<$len>
            where
                Self: 'e;

            fn psbt_encoder(&self) -> Self::Encoder<'_> {
                ArrayEncoder::without_length_prefix(*self.as_byte_array())
            }
        }
    };
}

impl_hash_encoder!(Txid, 32);

pub(crate) type PreviousTxidPair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <Txid as PsbtEncode>::Encoder<'e>>;

impl_hash_encoder!(ripemd160::Hash, 20);

pub(crate) type Ripemd160Iter<'e> =
    BytesKeyValueIter<btree_map::Iter<'e, ripemd160::Hash, Vec<u8>>, PSBT_IN_RIPEMD160>;

impl_hash_encoder!(hash160::Hash, 20);

pub(crate) type Hash160Iter<'e> =
    BytesKeyValueIter<btree_map::Iter<'e, hash160::Hash, Vec<u8>>, PSBT_IN_HASH160>;

impl_hash_encoder!(sha256::Hash, 32);

pub(crate) type Sha256Iter<'e> =
    BytesKeyValueIter<btree_map::Iter<'e, sha256::Hash, Vec<u8>>, PSBT_IN_SHA256>;

impl_hash_encoder!(sha256d::Hash, 32);

pub(crate) type Hash256Iter<'e> =
    BytesKeyValueIter<btree_map::Iter<'e, sha256d::Hash, Vec<u8>>, PSBT_IN_HASH256>;

impl_hash_encoder!(TapLeafHash, 32);
impl_hash_encoder!(TapNodeHash, 32);

pub(crate) type TapMerkleRootPair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <TapNodeHash as PsbtEncode>::Encoder<'e>>;

impl PsbtEncode for LeafVersion {
    type Encoder<'e>
        = ArrayEncoder<1>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix([self.to_consensus()])
    }
}

impl PsbtEncode for ScriptBuf {
    type Encoder<'e>
        = BytesEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        BytesEncoder::without_length_prefix(self.as_bytes())
    }
}

pub(crate) type ScriptPair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <ScriptBuf as PsbtEncode>::Encoder<'e>>;

/// Encoder for a [`PublicKey`].
pub enum PublicKeyEncoder {
    /// Compressed form (33 bytes).
    Compressed(ArrayEncoder<33>),
    /// Uncompressed form (65 bytes).
    Uncompressed(ArrayEncoder<65>),
}

impl PublicKeyEncoder {
    fn new(key: &PublicKey) -> Self {
        if key.compressed {
            Self::Compressed(ArrayEncoder::without_length_prefix(key.inner.serialize()))
        } else {
            Self::Uncompressed(ArrayEncoder::without_length_prefix(
                key.inner.serialize_uncompressed(),
            ))
        }
    }
}

impl Encoder for PublicKeyEncoder {
    fn current_chunk(&self) -> &[u8] {
        match self {
            Self::Compressed(e) => e.current_chunk(),
            Self::Uncompressed(e) => e.current_chunk(),
        }
    }

    fn advance(&mut self) -> EncoderStatus {
        match self {
            Self::Compressed(e) => e.advance(),
            Self::Uncompressed(e) => e.advance(),
        }
    }
}

impl ExactSizeEncoder for PublicKeyEncoder {
    fn len(&self) -> usize {
        match self {
            Self::Compressed(e) => e.len(),
            Self::Uncompressed(e) => e.len(),
        }
    }
}

impl PsbtEncode for PublicKey {
    type Encoder<'e> = PublicKeyEncoder;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { PublicKeyEncoder::new(self) }
}

/// Encoder for a [`ecdsa::SerializedSignature`].
pub struct EcdsaSigEncoder(ecdsa::SerializedSignature);

impl EcdsaSigEncoder {
    fn new(sig: ecdsa::SerializedSignature) -> Self { Self(sig) }
}

impl Encoder for EcdsaSigEncoder {
    fn current_chunk(&self) -> &[u8] { &self.0 }

    fn advance(&mut self) -> EncoderStatus { EncoderStatus::Finished }
}

impl ExactSizeEncoder for EcdsaSigEncoder {
    fn len(&self) -> usize { self.0.len() }
}

impl PsbtEncode for ecdsa::Signature {
    type Encoder<'e> = EcdsaSigEncoder;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { EcdsaSigEncoder::new(self.serialize()) }
}

pub(crate) type PartialSigIter<'e> =
    KeyValueIter<btree_map::Iter<'e, PublicKey, ecdsa::Signature>, PSBT_IN_PARTIAL_SIG>;

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

/// Encoder for a [`taproot::serialized_signature::SerializedSignature`].
pub struct TapSigEncoder(taproot::serialized_signature::SerializedSignature);

impl TapSigEncoder {
    fn new(sig: taproot::serialized_signature::SerializedSignature) -> Self { Self(sig) }
}

impl Encoder for TapSigEncoder {
    fn current_chunk(&self) -> &[u8] { &self.0 }

    fn advance(&mut self) -> EncoderStatus { EncoderStatus::Finished }
}

impl ExactSizeEncoder for TapSigEncoder {
    fn len(&self) -> usize { self.0.len() }
}

impl PsbtEncode for taproot::Signature {
    type Encoder<'e> = TapSigEncoder;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { TapSigEncoder::new(self.serialize()) }
}

pub(crate) type TapKeySigPair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <taproot::Signature as PsbtEncode>::Encoder<'e>>;

pub(crate) type TapScriptSigIter<'e> = KeyValueIter<
    btree_map::Iter<'e, (XOnlyPublicKey, TapLeafHash), taproot::Signature>,
    PSBT_IN_TAP_SCRIPT_SIG,
>;

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

/// An encoder for a [`TapTree`] as its leaves: `merkle branch len u8`,
/// `leaf version u8`, then compact-size-prefixed script per leaf, in DFS order.
pub struct TapTreeEncoder<'e> {
    inner: IterEncoder<TapTreeLeafIter<'e>>,
    /// Remaining bytes to be yielded. Decremented on each `advance()`.
    remaining: usize,
}

impl<'e> TapTreeEncoder<'e> {
    fn new(tree: &'e TapTree) -> Self {
        // Per-leaf layout: 1-byte depth, 1-byte
        // version, compact-size-prefixed script.
        let remaining = tree
            .script_leaves()
            .map(|l| l.script().len() + VarInt::from(l.script().len()).size() + 1 + 1)
            .sum();
        Self {
            inner: IterEncoder::new(TapTreeLeafIter { leaves: tree.script_leaves() }),
            remaining,
        }
    }
}

impl Encoder for TapTreeEncoder<'_> {
    fn current_chunk(&self) -> &[u8] { self.inner.current_chunk() }

    fn advance(&mut self) -> EncoderStatus {
        let chunk_len = self.inner.current_chunk().len();
        let status = self.inner.advance();
        self.remaining = self.remaining.saturating_sub(chunk_len);
        status
    }
}

impl ExactSizeEncoder for TapTreeEncoder<'_> {
    fn len(&self) -> usize { self.remaining }
}

/// Yields an owned script's bytes as a single chunk.
struct TapScriptEncoder(ScriptBuf);

impl TapScriptEncoder {
    fn new(script_buf: ScriptBuf) -> Self { Self(script_buf) }
}

impl Encoder for TapScriptEncoder {
    fn current_chunk(&self) -> &[u8] { self.0.as_bytes() }

    fn advance(&mut self) -> EncoderStatus { EncoderStatus::Finished }
}

impl ExactSizeEncoder for TapScriptEncoder {
    fn len(&self) -> usize { self.0.len() }
}

/// An iterator over the leaf encoders of a [`TapTree`].
struct TapTreeLeafIter<'e> {
    leaves: ScriptLeaves<'e>,
}

impl<'e> Iterator for TapTreeLeafIter<'e> {
    type Item = Encoder4<ArrayEncoder<1>, ArrayEncoder<1>, CompactSizeEncoder, TapScriptEncoder>;

    fn next(&mut self) -> Option<Self::Item> {
        let leaf = self.leaves.next()?;
        // `ScriptLeaf::script()` ties its reference to the temporary `ScriptLeaf`,
        // so the script is owned per leaf (one allocation) rather than borrowed.
        let script = leaf.script().to_owned();
        Some(Encoder4::new(
            // TaprootMerkleBranch can only have len at most 128.
            ArrayEncoder::without_length_prefix([leaf.merkle_branch().len() as u8]),
            ArrayEncoder::without_length_prefix([leaf.version().to_consensus()]),
            CompactSizeEncoder::new(leaf.script().len()),
            TapScriptEncoder::new(script),
        ))
    }
}

impl PsbtEncode for TapTree {
    type Encoder<'e>
        = TapTreeEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { TapTreeEncoder::new(self) }
}

pub(crate) type TapTreePair<'e> = KeyValueEncoder<CompactSizeEncoder, TapTreeEncoder<'e>>;

/// Decoder for a [`TapTree`] value.
#[derive(Debug, Default)]
pub struct TapTreeDecoder {
    inner: ByteVecDecoder,
}

impl Decoder for TapTreeDecoder {
    type Output = TapTree;
    type Error = TapTreeDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(TapTreeDecodeError::ByteVec)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let value = self.inner.end().map_err(TapTreeDecodeError::ByteVec)?;
        let mut builder = taproot::TaprootBuilder::new();
        let mut slice = &value[..];
        while let Some((&depth, rest)) = slice.split_first() {
            let (&version, rest) = rest.split_first().ok_or(TapTreeDecodeError::InvalidTree)?;
            let mut cs = CompactSizeDecoder::new();
            let mut remaining = rest;
            cs.push_bytes(&mut remaining).map_err(|_| TapTreeDecodeError::InvalidTree)?;
            let script_len = cs.end().map_err(|_| TapTreeDecodeError::InvalidTree)?;
            let script = ScriptBuf::from_bytes(remaining[..script_len].to_vec());
            let leaf_version = LeafVersion::from_consensus(version)
                .map_err(|_| TapTreeDecodeError::InvalidTree)?;
            builder = builder
                .add_leaf_with_ver(depth, script, leaf_version)
                .map_err(|_| TapTreeDecodeError::InvalidTree)?;
            slice = &remaining[script_len..];
        }
        TapTree::try_from(builder).map_err(|_| TapTreeDecodeError::InvalidTree)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for TapTree {
    type Decoder = TapTreeDecoder;
}

/// Error decoding a [`TapTree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapTreeDecodeError {
    /// The inner byte-vector decoder encountered an error.
    ByteVec(ByteVecDecoderError),
    /// The value is not a valid tap tree.
    InvalidTree,
}

impl fmt::Display for TapTreeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByteVec(e) => write!(f, "error decoding tap tree: {e}"),
            Self::InvalidTree => write!(f, "invalid tap tree encoding"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TapTreeDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ByteVec(e) => Some(e),
            Self::InvalidTree => None,
        }
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

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a serialized [`ControlBlock`] (1 byte parity/version, 32 bytes key, then 32 bytes per merkle node, borrowed without copies).
    pub struct ControlBlockEncoder<'e>(Encoder2<Encoder2<ArrayEncoder<1>, ArrayEncoder<32>>, SliceEncoder<'e, TapNodeHash>>);
}

impl PsbtEncode for ControlBlock {
    type Encoder<'e> = ControlBlockEncoder<'e>;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        // Method form (bitor) chosen over the | operator: parity contributes bit 0 only and
        // LeafVersion::to_consensus is always even (soft invariant enforced by the
        // bitcoin crate), making | vs ^ equivalent and the operator mutation un-killable.
        // The method form removes the mutation entirely.
        let first = self.leaf_version.to_consensus().bitor(i32::from(self.output_key_parity) as u8);
        let head = Encoder2::new(
            ArrayEncoder::without_length_prefix([first]),
            ArrayEncoder::without_length_prefix(self.internal_key.serialize()),
        );
        let nodes =
            <SliceEncoder<'_, TapNodeHash>>::without_length_prefix(self.merkle_branch.as_ref());
        ControlBlockEncoder::new(Encoder2::new(head, nodes))
    }
}

pub(crate) type TapScriptIter<'e> = KeyValueIter<
    btree_map::Iter<'e, ControlBlock, (ScriptBuf, LeafVersion)>,
    PSBT_IN_TAP_LEAF_SCRIPT,
>;

pub(crate) type Bip32DerivationIter<'e> =
    KeyValueIter<btree_map::Iter<'e, PublicKey, KeySource>, PSBT_IN_BIP32_DERIVATION>;

pub(crate) type TapKeyOriginIter<'e> = KeyValueIter<
    btree_map::Iter<'e, XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    PSBT_IN_TAP_BIP32_DERIVATION,
>;

impl PsbtEncode for CompressedPublicKey {
    type Encoder<'e>
        = ArrayEncoder<33>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.to_bytes())
    }
}

/// Decoder for a [`CompressedPublicKey`].
#[derive(Debug, Default)]
pub struct CompressedPublicKeyDecoder {
    inner: ArrayDecoder<33>,
}

impl Decoder for CompressedPublicKeyDecoder {
    type Output = CompressedPublicKey;
    type Error = CompressedPublicKeyDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(CompressedPublicKeyDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end().map_err(CompressedPublicKeyDecodeError::UnexpectedEof)?;
        CompressedPublicKey::from_slice(&bytes).map_err(CompressedPublicKeyDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for CompressedPublicKey {
    type Decoder = CompressedPublicKeyDecoder;
}

/// Error decoding a [`CompressedPublicKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressedPublicKeyDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The 33 bytes did not form a valid compressed public key.
    Invalid(bitcoin::secp256k1::Error),
}

impl fmt::Display for CompressedPublicKeyDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) =>
                write!(f, "unexpected EOF decoding compressed public key: {e}"),
            Self::Invalid(e) => write!(f, "invalid compressed public key: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CompressedPublicKeyDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::Invalid(e) => Some(e),
        }
    }
}

#[cfg(feature = "silent-payments")]
pub(crate) type EcdhKeyValueIter<'e> = KeyValueIter<
    btree_map::Iter<'e, CompressedPublicKey, CompressedPublicKey>,
    PSBT_GLOBAL_SP_ECDH_SHARE,
>;

#[cfg(feature = "silent-payments")]
pub(crate) type EcdhPairIter<'e> = KeyValueIter<
    btree_map::Iter<'e, CompressedPublicKey, CompressedPublicKey>,
    PSBT_IN_SP_ECDH_SHARE,
>;

#[cfg(feature = "silent-payments")]
pub(crate) type SpV0InfoPair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <SpV0Info as PsbtEncode>::Encoder<'e>>;

#[cfg(feature = "silent-payments")]
pub(crate) type SpV0LabelPair<'e> = KeyValueEncoder<CompactSizeEncoder, ArrayEncoder<4>>;

pub(crate) type OutBip32DerivationIter<'e> =
    KeyValueIter<btree_map::Iter<'e, PublicKey, KeySource>, PSBT_OUT_BIP32_DERIVATION>;

pub(crate) type OutTapKeyOriginIter<'e> = KeyValueIter<
    btree_map::Iter<'e, XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    PSBT_OUT_TAP_BIP32_DERIVATION,
>;

/// Decoder for a [`taproot::Signature`] value.
#[derive(Debug, Default)]
pub struct TaprootSignatureDecoder {
    inner: ByteVecDecoder,
}

impl Decoder for TaprootSignatureDecoder {
    type Output = taproot::Signature;
    type Error = TaprootSignatureDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(TaprootSignatureDecodeError::ByteVec)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let value = self.inner.end().map_err(TaprootSignatureDecodeError::ByteVec)?;
        taproot::Signature::from_slice(&value).map_err(TaprootSignatureDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

/// Error decoding a [`taproot::Signature`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaprootSignatureDecodeError {
    /// The inner byte-vector decoder encountered an error.
    ByteVec(ByteVecDecoderError),
    /// The value is not a valid taproot signature.
    Invalid(bitcoin::taproot::SigFromSliceError),
}

impl fmt::Display for TaprootSignatureDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByteVec(e) => write!(f, "error decoding taproot signature: {e}"),
            Self::Invalid(e) => write!(f, "invalid taproot signature: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TaprootSignatureDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ByteVec(e) => Some(e),
            Self::Invalid(e) => Some(e),
        }
    }
}

/// Decoder for an [`ecdsa::Signature`] value.
#[derive(Debug, Default)]
pub struct EcdsaSignatureDecoder {
    inner: ByteVecDecoder,
}

impl Decoder for EcdsaSignatureDecoder {
    type Output = ecdsa::Signature;
    type Error = EcdsaSignatureDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(EcdsaSignatureDecodeError::ByteVec)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let value = self.inner.end().map_err(EcdsaSignatureDecodeError::ByteVec)?;
        ecdsa::Signature::from_slice(&value).map_err(EcdsaSignatureDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

/// Error decoding an [`ecdsa::Signature`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaSignatureDecodeError {
    /// The inner byte-vector decoder encountered an error.
    ByteVec(ByteVecDecoderError),
    /// The value is not a valid ECDSA signature.
    Invalid(ecdsa::Error),
}

impl fmt::Display for EcdsaSignatureDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ByteVec(e) => write!(f, "error decoding ECDSA signature: {e}"),
            Self::Invalid(e) => write!(f, "invalid ECDSA signature: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EcdsaSignatureDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ByteVec(e) => Some(e),
            Self::Invalid(e) => Some(e),
        }
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
        let leaf_hashes: Vec<TapLeafHash> = value[1..hash_end]
            .chunks_exact(32)
            .map(|chunk| TapLeafHash::from_slice(chunk).expect("32 bytes"))
            .collect();

        if value.len() < hash_end + 4 {
            return Err(TapKeyOriginDecodeError::MissingFingerprint);
        }

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

#[cfg(feature = "silent-payments")]
pub(crate) type DleqKeyValueIter<'e> =
    KeyValueIter<btree_map::Iter<'e, CompressedPublicKey, DleqProof>, PSBT_GLOBAL_SP_DLEQ>;

#[cfg(feature = "silent-payments")]
pub(crate) type DleqPairIter<'e> =
    KeyValueIter<btree_map::Iter<'e, CompressedPublicKey, DleqProof>, PSBT_IN_SP_DLEQ>;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use bitcoin::bip32::Fingerprint;

    use super::*;
    use crate::encoding::{decode_from_slice, encode_to_vec};
    use crate::map::SeparatorEncoder;

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

    #[test]
    fn public_key_encoder_len_is_key_size() {
        use core::str::FromStr;

        let pk = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        assert_eq!(pk.psbt_encoder().len(), 33, "compressed public key");

        let pk_uc = PublicKey { compressed: false, inner: pk.inner };
        assert_eq!(pk_uc.psbt_encoder().len(), 65, "uncompressed public key");
    }

    // Exercises `PsbtEncode for bitcoin::ecdsa::SerializedSignature` (the `BytesEncoder` impl).
    // DER is variable-length: strict DER pads a scalar with a leading 0x00 when its high bit is
    // set, so differently-sized signatures must encode to differently-sized values.
    #[test]
    fn serialized_ecdsa_signature_encoded_size_varies_with_der_size() {
        // Builds a `SerializedSignature` (DER bytes + the SIGHASH_ALL byte) from raw DER.
        fn serialized(der: &[u8]) -> bitcoin::ecdsa::Signature {
            let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(der).unwrap();
            ecdsa::Signature { signature: sig, sighash_type: bitcoin::EcdsaSighashType::All }
        }

        // r = 1, s = 1 -> minimal DER (8 bytes), +1 sighash byte = 9.
        let minimal = serialized(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);

        // r, s each 32 bytes, high bits clear -> no padding (70-byte DER), +1 = 71.
        let mid = serialized(&der_with_scalars(&[0x01; 32], &[0x01; 32]));

        // r padded (high bit set), s not -> 71-byte DER, +1 = 72.
        let one_pad = serialized(&der_with_scalars(&[0x80; 32], &[0x01; 32]));

        // r, s both padded -> 72-byte DER, +1 = 73.
        let both_pad = serialized(&der_with_scalars(&[0x80; 32], &[0x80; 32]));

        // Use encoder to check len and remove mutants
        let minimal_enc = EcdsaSigEncoder::new(minimal.serialize());
        let minimal_len = minimal_enc.len();
        let mid_enc = EcdsaSigEncoder::new(mid.serialize());
        let mid_len = mid_enc.len();
        // Use encode_to_vec for the rest to also exercise PsbtEncode interface
        let one_pad_len = encode_to_vec(&one_pad).len();
        let both_pad_len = encode_to_vec(&both_pad).len();

        assert_eq!(minimal_len, 9, "minimal r=s=1 signature");
        assert_eq!(mid_len, 71, "two unpadded 32-byte scalars");
        assert_eq!(one_pad_len, 72, "one padded scalar");
        assert_eq!(both_pad_len, 73, "two padded scalars");

        // The core claim: differently-sized signatures encode to differently-sized values.
        let mut sizes = vec![minimal_len, mid_len, one_pad_len, both_pad_len];
        sizes.sort_unstable();
        sizes.dedup();
        assert_eq!(sizes.len(), 4, "encoded sizes must all be distinct");
    }

    // Encodes two big-endian scalars as strict DER: `0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>`,
    // prepending a 0x00 to either scalar whose high bit is set (strict DER minimal encoding).
    fn der_with_scalars(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let r = padded(r);
        let s = padded(s);
        let mut body = Vec::with_capacity(2 + r.len() + 2 + s.len());
        body.push(0x02);
        body.push(r.len() as u8);
        body.extend_from_slice(&r);
        body.push(0x02);
        body.push(s.len() as u8);
        body.extend_from_slice(&s);
        let mut der = Vec::with_capacity(2 + body.len());
        der.push(0x30);
        der.push(body.len() as u8);
        der.extend_from_slice(&body);
        der
    }

    // Prepends a 0x00 byte iff the scalar's high bit is set, per strict DER.
    fn padded(scalar: &[u8; 32]) -> Vec<u8> {
        if scalar[0] & 0x80 != 0 {
            let mut v = Vec::with_capacity(33);
            v.push(0x00);
            v.extend_from_slice(scalar);
            v
        } else {
            scalar.to_vec()
        }
    }

    #[test]
    fn separator_encoder_len_is_always_1() {
        let mut enc = SeparatorEncoder::new();
        assert_eq!(enc.len(), 1);
        assert!(enc.advance().has_finished());
        // Should not happend in non testing code
        assert_eq!(enc.len(), 1);
    }

    #[test]
    fn leaf_version_matches_serialize() {
        let lv = LeafVersion::TapScript;
        let bytes = encode_to_vec(&lv);
        // Game between byte form used by `(ScriptBuf, LeafVersion)` serialization; LeafVersion
        // itself is only ever encoded as the trailing byte within that tuple.
        assert_eq!(bytes, vec![lv.to_consensus()]);
    }

    // Taproot signatures are fixed-size: 64 bytes for the default sighash (no trailing
    // sighash byte), 65 bytes for any explicit sighash type. Mirrors
    // `serialized_ecdsa_signature_encoded_size_varies_with_der_size` for the schnorr case,
    // pinning both the `ExactSizeEncoder`-reported length and the actual encoded byte length.
    #[test]
    fn taproot_signature_encoded_size_matches_sighash_type() {
        let raw = bitcoin::secp256k1::schnorr::Signature::from_slice(&[0x51; 64]).unwrap();
        let sighashes = [
            (bitcoin::TapSighashType::Default, 64),
            (bitcoin::TapSighashType::All, 65),
            (bitcoin::TapSighashType::None, 65),
            (bitcoin::TapSighashType::Single, 65),
            (bitcoin::TapSighashType::AllPlusAnyoneCanPay, 65),
            (bitcoin::TapSighashType::NonePlusAnyoneCanPay, 65),
            (bitcoin::TapSighashType::SinglePlusAnyoneCanPay, 65),
        ];
        for (sighash_type, expected_len) in sighashes {
            let sig = taproot::Signature { signature: raw, sighash_type };
            assert_eq!(sig.psbt_encoder().len(), expected_len, "encoder len for {sighash_type:?}");
            assert_eq!(encode_to_vec(&sig).len(), expected_len, "encoded len for {sighash_type:?}");
        }
    }

    #[test]
    fn tap_tree_encoder_len_counts_down() {
        use bitcoin::taproot::TaprootBuilder;

        let builder = TaprootBuilder::new()
            .add_leaf(0x00, ScriptBuf::from_bytes(Vec::from([0x51])))
            .expect("leaf");
        let tree = TapTree::try_from(builder).expect("tree");
        let mut encoder = tree.psbt_encoder();
        let mut remaining = encoder.len();
        assert_eq!(remaining, encode_to_vec(&tree).len());
        loop {
            remaining -= encoder.current_chunk().len();
            if encoder.advance().has_finished() {
                break;
            }
            assert_eq!(encoder.len(), remaining, "len counts down on advance");
        }
        assert_eq!(encoder.len(), 0, "nothing remains after finish");
    }

    #[test]
    fn tap_script_encoder_len_is_script_len() {
        let script = ScriptBuf::from_bytes(vec![0x51, 0xac]);
        let encoder = TapScriptEncoder::new(script.clone());
        assert_eq!(encoder.len(), script.len());
    }

    #[test]
    fn tap_tree_leaf_encoder_len_includes_script_len() {
        use bitcoin::taproot::TaprootBuilder;

        let builder = TaprootBuilder::new()
            .add_leaf(0x00, ScriptBuf::from_bytes(vec![0x51, 0x52, 0x53]))
            .expect("leaf");
        let tree = TapTree::try_from(builder).expect("tree");
        let mut iter = TapTreeLeafIter { leaves: tree.script_leaves() };
        let leaf_encoder = iter.next().expect("one leaf");
        // 1 depth byte + 1 version byte + 1 compact-size byte + 3 script bytes.
        assert_eq!(leaf_encoder.len(), 6);
    }

    #[test]
    fn key_source_decoder_read_limit_lifecycle() {
        let mut decoder = KeySourceDecoder::default();
        assert!(decoder.read_limit() > 0);

        // Fingerprint-only value, compact_size(4) + 4 bytes.
        let mut bytes: &[u8] = &[0x04, 0xde, 0xad, 0xbe, 0xef];
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    fn key_source_decoder_fingerprint_only() {
        use bitcoin::bip32::{DerivationPath, Fingerprint};
        let mut decoder = KeySourceDecoder::default();
        // Fingerprint without derivation, compact_size(4) + 4-byte fingerprint.
        let mut bytes: &[u8] = &[0x04, 0xde, 0xad, 0xbe, 0xef];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        let (fingerprint, derivation) = decoder.end().unwrap();
        assert_eq!(fingerprint, Fingerprint::from([0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(derivation, DerivationPath::master());
    }

    #[test]
    fn key_source_decoder_with_path() {
        use bitcoin::bip32::Fingerprint;
        let mut decoder = KeySourceDecoder::default();
        // Fingerprint + one child, compact_size(8) + 4-byte fingerprint + 4-byte child.
        let mut bytes: &[u8] = &[0x08, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x00, 0x00, 0x00];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        let (fingerprint, derivation) = decoder.end().unwrap();
        assert_eq!(fingerprint, Fingerprint::from([0xaa, 0xbb, 0xcc, 0xdd]));
        let children: Vec<ChildNumber> = derivation.into_iter().copied().collect();
        assert_eq!(children.len(), 1);
        assert_eq!(u32::from(children[0]), 1);
    }

    #[test]
    fn key_source_decoder_too_short() {
        let mut decoder = KeySourceDecoder::default();
        // 3 bytes, shorter than the 4-byte fingerprint.
        let mut bytes: &[u8] = &[0x03, 0xde, 0xad, 0xbe];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        let err = decoder.end().unwrap_err();
        assert_eq!(err, KeySourceDecodeError::TooShort(3));
    }

    #[test]
    fn key_source_decoder_invalid_path_length() {
        let mut decoder = KeySourceDecoder::default();
        // Fingerprint + 2 extra bytes, compact_size(6) but path is not 4-byte aligned.
        let mut bytes: &[u8] = &[0x06, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        let err = decoder.end().unwrap_err();
        assert_eq!(err, KeySourceDecodeError::InvalidPathLength(6));
    }
}
