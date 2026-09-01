// SPDX-License-Identifier: CC0-1.0

//! This module contains [`PsbtEncode`] implementations for types which live outside of rust-psbt
//! but are not consensus encodable.

use alloc::collections::btree_map;
use alloc::vec::Vec;
use core::fmt;
use core::ops::BitOr as _;

use bitcoin::bip32::{self, ChildNumber, KeySource, Xpub};
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash as _};
use bitcoin::key::{PublicKey, XOnlyPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::taproot::{self, ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
#[cfg(feature = "silent-payments")]
use bitcoin::CompressedPublicKey;
use bitcoin::{ecdsa, ScriptBuf, Txid};
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, BytesEncoder, CompactSizeEncoder, Decoder, DecoderStatus, Encoder,
    Encoder2, EncoderStatus, ExactSizeEncoder, UnexpectedEofError,
};

use super::{
    BytesValue, ExactPrefixedSliceEncoder, ExactSliceEncoder, KeyValueIter, PsbtDecode, PsbtEncode,
};
#[cfg(feature = "silent-payments")]
use crate::consts::{
    PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_IN_SP_DLEQ, PSBT_IN_SP_ECDH_SHARE,
};
use crate::consts::{
    PSBT_GLOBAL_XPUB, PSBT_IN_BIP32_DERIVATION, PSBT_IN_HASH160, PSBT_IN_HASH256,
    PSBT_IN_PARTIAL_SIG, PSBT_IN_RIPEMD160, PSBT_IN_SHA256, PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_LEAF_SCRIPT, PSBT_IN_TAP_SCRIPT_SIG, PSBT_SEPARATOR,
};
#[cfg(feature = "silent-payments")]
use crate::dleq::DleqProof;
use crate::encoding::KeyValueEncoder;
use crate::sighash_type::PsbtSighashType;

/// Encoder for the PSBT record separator.
pub struct SeparatorEncoder(ArrayEncoder<1>);

impl Default for SeparatorEncoder {
    fn default() -> Self { Self::new() }
}

impl SeparatorEncoder {
    /// Encoder for the key-value separator
    pub fn new() -> Self { Self(ArrayEncoder::without_length_prefix([PSBT_SEPARATOR])) }
}

impl Encoder for SeparatorEncoder {
    fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }

    fn advance(&mut self) -> EncoderStatus { self.0.advance() }
}

impl ExactSizeEncoder for SeparatorEncoder {
    // Preferred constant over `self.0.len()` because the second generates a mutant variant and the
    // former does not
    fn len(&self) -> usize { 1 }
}

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

impl PsbtEncode for PsbtSighashType {
    type Encoder<'e>
        = ArrayEncoder<4>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.to_u32().to_le_bytes())
    }
}

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
    KeyValueIter<btree_map::Iter<'e, ripemd160::Hash, Vec<u8>>, PSBT_IN_RIPEMD160, BytesValue>;

impl_hash_encoder!(hash160::Hash, 20);

pub(crate) type Hash160Iter<'e> =
    KeyValueIter<btree_map::Iter<'e, hash160::Hash, Vec<u8>>, PSBT_IN_HASH160, BytesValue>;

impl_hash_encoder!(sha256::Hash, 32);

pub(crate) type Sha256Iter<'e> =
    KeyValueIter<btree_map::Iter<'e, sha256::Hash, Vec<u8>>, PSBT_IN_SHA256, BytesValue>;

impl_hash_encoder!(sha256d::Hash, 32);

pub(crate) type Hash256Iter<'e> =
    KeyValueIter<btree_map::Iter<'e, sha256d::Hash, Vec<u8>>, PSBT_IN_HASH256, BytesValue>;

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

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a `(Vec<TapLeafHash>, KeySource)` composite: `count <hash*a> <key source>` where `count` is a compact-size prefix.
    pub struct LeafHashVecKeySourceEncoder<'e>(
        Encoder2<ExactPrefixedSliceEncoder<'e, TapLeafHash>, KeySourceEncoder<'e>>
    );
}

impl PsbtEncode for (Vec<TapLeafHash>, KeySource) {
    type Encoder<'e>
        = LeafHashVecKeySourceEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        LeafHashVecKeySourceEncoder::new(Encoder2::new(
            <ExactPrefixedSliceEncoder<'_, TapLeafHash>>::new(self.0.as_slice()),
            self.1.psbt_encoder(),
        ))
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a serialized [`ControlBlock`] (1 byte parity/version, 32 bytes key, then 32 bytes per merkle node, borrowed without copies).
    pub struct ControlBlockEncoder<'e>(Encoder2<Encoder2<ArrayEncoder<1>, ArrayEncoder<32>>, ExactSliceEncoder<'e, TapNodeHash>>);
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
        let nodes = <ExactSliceEncoder<'_, TapNodeHash>>::without_length_prefix(
            self.merkle_branch.as_ref(),
        );
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
impl PsbtEncode for DleqProof {
    type Encoder<'e>
        = BytesEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        BytesEncoder::without_length_prefix(self.as_bytes())
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
    // Byte-equality gates against the legacy `Serialize::serialize`/consensus path that the
    // current `Map::get_pairs` implementations emit for these field value types.
    use crate::serialize::Serialize;

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
    fn sighash_type_matches_serialize() {
        let v = PsbtSighashType::from_u32(0x01u32);
        assert_eq!(encode_to_vec(&v), v.serialize());
    }

    #[test]
    fn public_key_matches_serialize() {
        use core::str::FromStr;

        let pk = PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        assert_eq!(encode_to_vec(&pk), Serialize::serialize(&pk));

        // Uncompressed key exercises the 65-byte branch of PublicKeyEncoder.
        let pk_uc = PublicKey { compressed: false, inner: pk.inner };
        assert_eq!(encode_to_vec(&pk_uc), Serialize::serialize(&pk_uc));
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
    fn ecdsa_signature_matches_serialize() {
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let der_sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&der).unwrap();
        let sighash_enum: bitcoin::EcdsaSighashType = bitcoin::EcdsaSighashType::All;
        let sig = ecdsa::Signature { signature: der_sig, sighash_type: sighash_enum };
        assert_eq!(encode_to_vec(&sig), Serialize::serialize(&sig));
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
    fn xonly_public_key_matches_serialize() {
        use core::str::FromStr;

        let pk = XOnlyPublicKey::from_str(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();
        assert_eq!(encode_to_vec(&pk), Serialize::serialize(&pk));
    }

    #[test]
    fn hash_types_match_serialize() {
        let rmd = ripemd160::Hash::hash(&[0x42]);
        let h160 = hash160::Hash::hash(&[0x42]);
        let sha = sha256::Hash::hash(&[0x42]);
        let dsha = sha256d::Hash::hash(&[0x42]);
        assert_eq!(encode_to_vec(&rmd), Serialize::serialize(&rmd));
        assert_eq!(encode_to_vec(&h160), Serialize::serialize(&h160));
        assert_eq!(encode_to_vec(&sha), Serialize::serialize(&sha));
        assert_eq!(encode_to_vec(&dsha), Serialize::serialize(&dsha));
    }

    #[test]
    fn leaf_version_matches_serialize() {
        let lv = LeafVersion::TapScript;
        let bytes = encode_to_vec(&lv);
        // Game between byte form used by `(ScriptBuf, LeafVersion)` serialization; LeafVersion
        // itself is only ever encoded as the trailing byte within that tuple.
        assert_eq!(bytes, vec![lv.to_consensus()]);
    }

    #[test]
    fn script_buf_matches_serialize() {
        let script = bitcoin::ScriptBuf::from_bytes(vec::Vec::from([0x76, 0xa9, 0x14, 0xcd, 0xbd]));
        assert_eq!(encode_to_vec(&script), Serialize::serialize(&script));
        assert_eq!(encode_to_vec(&script), script.as_bytes());
    }

    #[test]
    fn taproot_signature_matches_serialize() {
        let raw_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&[0x51; 64]).unwrap();
        // Non-default sighash adds one byte (65 bytes total); default drops to 64 bytes.
        let sig =
            taproot::Signature { signature: raw_sig, sighash_type: bitcoin::TapSighashType::All };
        assert_eq!(encode_to_vec(&sig), Serialize::serialize(&sig));
        let default_sig = taproot::Signature {
            signature: raw_sig,
            sighash_type: bitcoin::TapSighashType::Default,
        };
        assert_eq!(encode_to_vec(&default_sig), Serialize::serialize(&default_sig));
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
    fn control_block_matches_serialize() {
        use bitcoin::taproot::TaprootBuilder;

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let xonly_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&[0x51; 32]).unwrap();
        let builder = TaprootBuilder::new()
            .add_leaf(0x00, bitcoin::ScriptBuf::from_bytes(Vec::from([0x51])))
            .expect("leaf");
        let info = builder.finalize(&secp, xonly_key).expect("finalize succeeds");
        let script_vec = bitcoin::ScriptBuf::from_bytes(Vec::from([0x51]));
        let ctrl = info.control_block(&(script_vec, LeafVersion::TapScript)).expect("gets ctrl");
        assert_eq!(encode_to_vec(&ctrl), Serialize::serialize(&ctrl));
    }

    #[test]
    fn xonly_leaf_hash_pair_matches_serialize() {
        let key_raw = [0x51u8; 32];
        let leaf = TapLeafHash::hash(&[0x51]);
        let xkey = XOnlyPublicKey::from_slice(&key_raw).unwrap();
        let pair = (xkey, leaf);
        assert_eq!(encode_to_vec(&pair), Serialize::serialize(&pair));
    }

    #[test]
    fn scriptbuf_leaf_version_matches_serialize() {
        let script = ScriptBuf::from_bytes(Vec::from([0x51, 0xac]));
        let pair = (script, LeafVersion::TapScript);
        assert_eq!(encode_to_vec(&pair), Serialize::serialize(&pair));
    }

    #[test]
    fn leafhash_vec_keysource_matches_serialize() {
        let hashes = vec![TapLeafHash::hash(&[0x01]), TapLeafHash::hash(&[0x02])];
        let key_source: KeySource =
            (Fingerprint::from([0x12, 0x34, 0x56, 0x78]), Default::default());
        let pair = (hashes, key_source);
        assert_eq!(encode_to_vec(&pair), Serialize::serialize(&pair));
    }
}
