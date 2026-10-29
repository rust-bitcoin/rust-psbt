// SPDX-License-Identifier: CC0-1.0

//! This module contains PSBT codec implementations for types which live upstream and whose PSBT
//! codecs are different from their consensus codecs.

pub mod ecdsa_signature;
pub mod key_source;
pub mod leaf_script;
pub mod taproot_signature;

use alloc::borrow::ToOwned as _;
use core::fmt;
use core::ops::BitOr as _;

use bitcoin::bip32::{self, ChildNumber, Xpub};
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash as _};
use bitcoin::key::{PublicKey, XOnlyPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::taproot::{
    self, ControlBlock, LeafVersion, ScriptLeaves, TapLeafHash, TapNodeHash, TapTree,
};
use bitcoin::{CompressedPublicKey, ScriptBuf, Txid, VarInt};
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, ByteVecDecoderError, BytesEncoder,
    CompactSizeDecoder, CompactSizeEncoder, Decoder, DecoderStatus, Encoder, Encoder2, Encoder4,
    EncoderStatus, ExactSizeEncoder, IterEncoder, UnexpectedEofError,
};

use super::{PsbtDecode, PsbtEncode, SliceEncoder};

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

/// Decoder for a [`ChildNumber`].
#[derive(Debug, Default)]
pub struct ChildNumberDecoder(ArrayDecoder<4>);

impl Decoder for ChildNumberDecoder {
    type Output = ChildNumber;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.0.end()?;
        Ok(ChildNumber::from(u32::from_le_bytes(bytes)))
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl PsbtDecode for ChildNumber {
    type Decoder = ChildNumberDecoder;
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

impl PsbtEncode for absolute::Height {
    type Encoder<'e>
        = ArrayEncoder<4>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.to_consensus_u32().to_le_bytes())
    }
}

impl PsbtEncode for XOnlyPublicKey {
    type Encoder<'e>
        = ArrayEncoder<32>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.serialize())
    }
}

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

impl_hash_encoder!(ripemd160::Hash, 20);

impl_hash_encoder!(hash160::Hash, 20);

impl_hash_encoder!(sha256::Hash, 32);

impl_hash_encoder!(sha256d::Hash, 32);

impl_hash_encoder!(TapLeafHash, 32);
impl_hash_encoder!(TapNodeHash, 32);

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
            Self::UnexpectedEof(e) => {
                write!(f, "unexpected EOF decoding compressed public key: {e}")
            }
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

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

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
        // Game between byte form used by `LeafScript<ScriptBuf>` serialization; LeafVersion
        // itself is only ever encoded as the trailing byte within that value.
        assert_eq!(bytes, vec![lv.to_consensus()]);
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
}
