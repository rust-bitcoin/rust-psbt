// SPDX-License-Identifier: CC0-1.0

use alloc::collections::{btree_map, BTreeMap};
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::{self, ChildNumber, DerivationPath, Fingerprint, KeySource, Xpub};
use bitcoin::locktime::absolute;
#[cfg(feature = "silent-payments")]
use bitcoin::CompressedPublicKey;
use bitcoin::{transaction, VarInt};
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, ByteVecDecoderError, CompactSizeDecoderError,
    CompactSizeEncoder, CompactSizeU64Decoder, Decoder, Decoder2Error, DecoderStatus, Encoder,
    EncoderStatus, IterEncoder, UnexpectedEofError,
};

use crate::consts::{
    PSBT_GLOBAL_FALLBACK_LOCKTIME, PSBT_GLOBAL_INPUT_COUNT, PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_PROPRIETARY, PSBT_GLOBAL_TX_MODIFIABLE, PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION, PSBT_GLOBAL_XPUB, PSBT_SEPARATOR,
};
#[cfg(feature = "silent-payments")]
use crate::consts::{PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_SP_ECDH_SHARE};
#[cfg(feature = "silent-payments")]
use crate::dleq::DleqProof;
use crate::encoding::delegates::{
    FallbackLockTimeKeyValueEncoder, FallbackLockTimeValueDecoder, TxVersionKeyValueEncoder,
    TxVersionValueDecoder,
};
#[cfg(feature = "silent-payments")]
use crate::encoding::native::{DleqKeyValueIter, EcdhKeyValueIter};
use crate::encoding::native::{SeparatorEncoder, XpubKeyValueIter};
use crate::encoding::{KeyValueEncoder, PsbtEncode, ValueDecoder};
use crate::error::{write_err, InconsistentKeySourcesError};
use crate::map::Map;
use crate::raw::{ProprietaryKeyValueIter, UnknownKeyValueIter};
use crate::serialize::Serialize;
use crate::version::{Version, VersionDecoderError, VersionKeyValueEncoder, VersionValueDecoder};
use crate::{consts, raw, V2};

/// The Inputs Modifiable Flag, set to 1 to indicate whether inputs can be added or removed.
const INPUTS_MODIFIABLE: u8 = 0x01 << 0;
/// The Outputs Modifiable Flag, set to 1 to indicate whether outputs can be added or removed.
const OUTPUTS_MODIFIABLE: u8 = 0x01 << 1;
/// The Has SIGHASH_SINGLE flag, set to 1 to indicate whether the transaction has a SIGHASH_SINGLE
/// signature who's input and output pairing must be preserved. Essentially indicates that the
/// Constructor must iterate the inputs to determine whether and how to add or remove an input.
const SIGHASH_SINGLE: u8 = 0x01 << 2;

/// The global key-value map.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Global {
    /// The version number of this PSBT.
    pub version: Version,

    /// The version number of the transaction being built.
    pub tx_version: transaction::Version,

    /// The transaction locktime to use if no inputs specify a required locktime.
    pub fallback_lock_time: Option<absolute::LockTime>,

    /// A bitfield for various transaction modification flags.
    pub tx_modifiable_flags: u8,

    /// The number of inputs in this PSBT.
    pub input_count: usize, // Serialized in compact form as a u64 (VarInt).

    /// The number of outputs in this PSBT.
    pub output_count: usize, // Serialized in compact form as a u64 (VarInt).

    /// A map from xpub to the used key fingerprint and derivation path as defined by BIP 32.
    pub xpubs: BTreeMap<Xpub, KeySource>,

    /// BIP-375: Map from scan public key to ECDH share (33 bytes each).
    #[cfg(feature = "silent-payments")]
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub sp_ecdh_shares: BTreeMap<CompressedPublicKey, CompressedPublicKey>,

    /// BIP-375: Map from scan public key to DLEQ proof (64 bytes each).
    #[cfg(feature = "silent-payments")]
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub sp_dleq_proofs: BTreeMap<CompressedPublicKey, DleqProof>,

    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,

    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

impl Global {
    fn new() -> Self {
        Self {
            version: V2,
            // TODO: Is this default correct?
            tx_version: transaction::Version::TWO,
            fallback_lock_time: None,
            tx_modifiable_flags: 0x00,
            input_count: 0,
            output_count: 0,
            xpubs: Default::default(),
            #[cfg(feature = "silent-payments")]
            sp_ecdh_shares: Default::default(),
            #[cfg(feature = "silent-payments")]
            sp_dleq_proofs: Default::default(),
            proprietaries: Default::default(),
            unknowns: Default::default(),
        }
    }

    /// Returns all key-value pairs for this global map in serialization order.
    pub fn pairs(&self) -> Vec<raw::Pair> { Map::get_pairs(self) }

    pub(crate) fn set_inputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags |= INPUTS_MODIFIABLE;
    }

    pub(crate) fn set_outputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags |= OUTPUTS_MODIFIABLE;
    }

    // TODO: Handle SIGHASH_SINGLE correctly.
    #[allow(dead_code)]
    pub(crate) fn set_sighash_single_flag(&mut self) { self.tx_modifiable_flags |= SIGHASH_SINGLE; }

    pub(crate) fn clear_inputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags &= !INPUTS_MODIFIABLE;
    }

    pub(crate) fn clear_outputs_modifiable_flag(&mut self) {
        self.tx_modifiable_flags &= !OUTPUTS_MODIFIABLE;
    }

    // TODO: Handle SIGHASH_SINGLE correctly.
    #[allow(dead_code)]
    pub(crate) fn clear_sighash_single_flag(&mut self) {
        self.tx_modifiable_flags &= !SIGHASH_SINGLE;
    }

    pub(crate) fn is_inputs_modifiable(&self) -> bool {
        self.tx_modifiable_flags & INPUTS_MODIFIABLE > 0
    }

    pub(crate) fn is_outputs_modifiable(&self) -> bool {
        self.tx_modifiable_flags & OUTPUTS_MODIFIABLE > 0
    }

    // TODO: Investigate if we should be using this function?
    #[allow(dead_code)]
    pub(crate) fn has_sighash_single(&self) -> bool {
        self.tx_modifiable_flags & SIGHASH_SINGLE > 0
    }

    /// Combines [`Global`] with `other`.
    ///
    /// In accordance with BIP 174 this function is commutative i.e., `A.combine(B) == B.combine(A)`
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        // Combining different versions of PSBT without explicit conversion is out of scope.
        if self.version != other.version {
            return Err(CombineError::VersionMismatch { this: self.version, that: other.version });
        }

        // No real reason to support this either.
        if self.tx_version != other.tx_version {
            return Err(CombineError::TxVersionMismatch {
                this: self.tx_version,
                that: other.tx_version,
            });
        }

        // BIP 174: The Combiner must remove any duplicate key-value pairs, in accordance with
        //          the specification. It can pick arbitrarily when conflicts occur.

        // Merging xpubs
        for (xpub, (fingerprint1, derivation1)) in other.xpubs {
            match self.xpubs.entry(xpub) {
                btree_map::Entry::Vacant(entry) => {
                    entry.insert((fingerprint1, derivation1));
                }
                btree_map::Entry::Occupied(mut entry) => {
                    // Here in case of the conflict we select the version with algorithm:
                    // 1) if everything is equal we do nothing
                    // 2) report an error if
                    //    - derivation paths are equal and fingerprints are not
                    //    - derivation paths are of the same length, but not equal
                    //    - derivation paths has different length, but the shorter one
                    //      is not the strict suffix of the longer one
                    // 3) choose longest derivation otherwise

                    let (fingerprint2, derivation2) = entry.get().clone();

                    if (derivation1 == derivation2 && fingerprint1 == fingerprint2)
                        || (derivation1.len() < derivation2.len()
                            && derivation1[..]
                                == derivation2[derivation2.len() - derivation1.len()..])
                    {
                        continue;
                    } else if derivation2[..]
                        == derivation1[derivation1.len() - derivation2.len()..]
                    {
                        entry.insert((fingerprint1, derivation1));
                        continue;
                    }
                    return Err(InconsistentKeySourcesError(xpub).into());
                }
            }
        }

        #[cfg(feature = "silent-payments")]
        v2_combine_map!(sp_ecdh_shares, self, other);
        #[cfg(feature = "silent-payments")]
        v2_combine_map!(sp_dleq_proofs, self, other);
        v2_combine_map!(proprietaries, self, other);
        v2_combine_map!(unknowns, self, other);

        Ok(())
    }
}

impl Default for Global {
    fn default() -> Self { Self::new() }
}

type CountValueDecoder = ValueDecoder<CompactSizeU64Decoder>;
type FlagsValueDecoder = ValueDecoder<ArrayDecoder<1>>;

/// The internal state of the global map push decoder.
#[derive(Debug)]
enum DecoderStage {
    /// Checking the next byte for the map separator.
    DecodingSeparator,
    /// Reading the next key from the stream. The caller has already confirmed the
    /// stream does not start with a separator, so this decoder only sees real key data.
    DecodingKey(raw::KeyDecoder),
    /// Decoding a version value.
    DecodingVersion { key: raw::Key, decoder: VersionValueDecoder },
    /// Decoding a transaction version value.
    DecodingTxVersion { key: raw::Key, decoder: TxVersionValueDecoder },
    /// Decoding a lock time value.
    DecodingLockTime { key: raw::Key, decoder: FallbackLockTimeValueDecoder },
    /// Decoding an input count value.
    DecodingInputCount { key: raw::Key, decoder: CountValueDecoder },
    /// Decoding an output count value.
    DecodingOutputCount { key: raw::Key, decoder: CountValueDecoder },
    /// Decoding a single-byte modifiable-flags value.
    DecodingTxModifiable { key: raw::Key, decoder: FlagsValueDecoder },
    /// Decoding an xpub value (fingerprint + path).
    DecodingXpub { key: raw::Key, decoder: ByteVecDecoder },
    /// Decoding a proprietary value.
    DecodingProprietary { key: raw::Key, decoder: ByteVecDecoder },
    /// Decoding an unknown value.
    DecodingUnknown { key: raw::Key, decoder: ByteVecDecoder },
    #[cfg(feature = "silent-payments")]
    /// Decoding an ECDH share for silent payments.
    DecodingSpEcdhShare { key: raw::Key, decoder: ValueDecoder<ArrayDecoder<33>> },
    #[cfg(feature = "silent-payments")]
    /// Decoding a DLEQ proof for silent payments.
    DecodingSpDleqProof { key: raw::Key, decoder: ValueDecoder<ArrayDecoder<64>> },
    /// The end-of-map separator has been reached.
    Done(Global),
    /// The decoder has entered a non-recoverable error state.
    Errored,
}

impl DecoderStage {
    /// Select the appropriate value-decoding stage based on the decoded key.
    fn from_key(key: raw::Key) -> Result<Self, DecodeError> {
        match key.type_value {
            PSBT_GLOBAL_VERSION =>
                Ok(Self::DecodingVersion { key, decoder: VersionValueDecoder::default() }),
            PSBT_GLOBAL_TX_VERSION =>
                Ok(Self::DecodingTxVersion { key, decoder: TxVersionValueDecoder::default() }),
            PSBT_GLOBAL_FALLBACK_LOCKTIME =>
                Ok(Self::DecodingLockTime { key, decoder: FallbackLockTimeValueDecoder::default() }),
            PSBT_GLOBAL_INPUT_COUNT =>
                Ok(Self::DecodingInputCount { key, decoder: CountValueDecoder::default() }),
            PSBT_GLOBAL_OUTPUT_COUNT =>
                Ok(Self::DecodingOutputCount { key, decoder: CountValueDecoder::default() }),
            PSBT_GLOBAL_TX_MODIFIABLE =>
                Ok(Self::DecodingTxModifiable { key, decoder: FlagsValueDecoder::default() }),
            PSBT_GLOBAL_XPUB => Ok(Self::DecodingXpub { key, decoder: ByteVecDecoder::new() }),
            PSBT_GLOBAL_PROPRIETARY =>
                Ok(Self::DecodingProprietary { key, decoder: ByteVecDecoder::new() }),
            #[cfg(feature = "silent-payments")]
            PSBT_GLOBAL_SP_ECDH_SHARE =>
                Ok(Self::DecodingSpEcdhShare { key, decoder: ValueDecoder::default() }),
            #[cfg(feature = "silent-payments")]
            PSBT_GLOBAL_SP_DLEQ =>
                Ok(Self::DecodingSpDleqProof { key, decoder: ValueDecoder::default() }),
            v if v == PSBT_GLOBAL_UNSIGNED_TX =>
                Err(DecodeError::InsertPair(InsertPairError::ExcludedKey { key_type_value: v })),
            _ => Ok(Self::DecodingUnknown { key, decoder: ByteVecDecoder::new() }),
        }
    }
}

/// Decoder for a PSBT global map.
///
/// Uses a push-based state machine. After each key is decoded, a type-specific composite
/// decoder (handling both the compact-size length prefix and the value) is selected based
/// on the key type.
#[derive(Debug)]
pub struct GlobalDecoder {
    stage: DecoderStage,
    /// Required fields.
    version: Option<Version>,
    tx_version: Option<transaction::Version>,
    input_count: Option<u64>,
    output_count: Option<u64>,
    /// Optional / accumulating fields.
    fallback_lock_time: Option<absolute::LockTime>,
    tx_modifiable_flags: Option<u8>,
    xpubs: BTreeMap<Xpub, (Fingerprint, DerivationPath)>,
    #[cfg(feature = "silent-payments")]
    sp_ecdh_shares: BTreeMap<CompressedPublicKey, CompressedPublicKey>,
    #[cfg(feature = "silent-payments")]
    sp_dleq_proofs: BTreeMap<CompressedPublicKey, DleqProof>,
    proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

impl Default for GlobalDecoder {
    fn default() -> Self {
        Self {
            stage: DecoderStage::DecodingSeparator,
            version: None,
            tx_version: None,
            input_count: None,
            output_count: None,
            fallback_lock_time: None,
            tx_modifiable_flags: None,
            xpubs: BTreeMap::default(),
            #[cfg(feature = "silent-payments")]
            sp_ecdh_shares: BTreeMap::default(),
            #[cfg(feature = "silent-payments")]
            sp_dleq_proofs: BTreeMap::default(),
            proprietaries: BTreeMap::default(),
            unknowns: BTreeMap::default(),
        }
    }
}

impl Decoder for GlobalDecoder {
    type Output = Global;
    type Error = DecodeError;

    #[allow(clippy::too_many_lines)] // State machine, necessary complexity.
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        if matches!(&self.stage, DecoderStage::Done(_)) {
            return Ok(DecoderStatus::Ready);
        }

        loop {
            // DecodingSeparator: check for separator or transition to key decode.
            if matches!(&self.stage, DecoderStage::DecodingSeparator) {
                match bytes.split_first() {
                    Some((&PSBT_SEPARATOR, rest)) => {
                        *bytes = rest;
                        let version = self.version.take().ok_or(DecodeError::MissingVersion)?;
                        let tx_version =
                            self.tx_version.take().ok_or(DecodeError::MissingTxVersion)?;
                        let tx_modifiable_flags = self.tx_modifiable_flags.take().unwrap_or(0_u8);

                        let ic = self.input_count.take().ok_or(DecodeError::MissingInputCount)?;
                        let input_count =
                            usize::try_from(ic).map_err(|_| DecodeError::InputCountOverflow(ic))?;

                        let oc = self.output_count.take().ok_or(DecodeError::MissingOutputCount)?;
                        let output_count = usize::try_from(oc)
                            .map_err(|_| DecodeError::OutputCountOverflow(oc))?;

                        #[cfg(feature = "silent-payments")]
                        {
                            let has_ecdh = !self.sp_ecdh_shares.is_empty();
                            let has_dleq = !self.sp_dleq_proofs.is_empty();
                            if has_ecdh != has_dleq {
                                return Err(DecodeError::FieldMismatch);
                            }
                        }

                        self.stage = DecoderStage::Done(Global {
                            tx_version,
                            fallback_lock_time: self.fallback_lock_time.take(),
                            input_count,
                            output_count,
                            tx_modifiable_flags,
                            version,
                            #[cfg(feature = "silent-payments")]
                            sp_ecdh_shares: core::mem::take(&mut self.sp_ecdh_shares),
                            #[cfg(feature = "silent-payments")]
                            sp_dleq_proofs: core::mem::take(&mut self.sp_dleq_proofs),
                            xpubs: core::mem::take(&mut self.xpubs),
                            proprietaries: core::mem::take(&mut self.proprietaries),
                            unknowns: core::mem::take(&mut self.unknowns),
                        });
                        return Ok(DecoderStatus::Ready);
                    }
                    Some((_, _)) => {
                        // Not a separator, fall through to push these bytes into a fresh decoder.
                        self.stage = DecoderStage::DecodingKey(raw::KeyDecoder::default());
                    }
                    None => return Ok(DecoderStatus::NeedsMore),
                }
            }

            // Push bytes into the active stage decoder.
            let status = match &mut self.stage {
                DecoderStage::DecodingKey(d) =>
                    d.push_bytes(bytes).map_err(DecodeError::KeyDecode)?,
                DecoderStage::DecodingVersion { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) => match e {
                            VersionDecoderError::UnexpectedEof(e) =>
                                DecodeError::ValueDecode(ValueDecodeError::Version(e)),
                            VersionDecoderError::UnsupportedVersion(e) =>
                                DecodeError::InsertPair(InsertPairError::WrongVersion(e.version())),
                        },
                    })?,
                DecoderStage::DecodingTxVersion { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::TxVersion(e)),
                    })?,
                DecoderStage::DecodingLockTime { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LockTime(e)),
                    })?,
                DecoderStage::DecodingTxModifiable { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::ModifiableFlags(e)),
                    })?,
                DecoderStage::DecodingInputCount { ref mut decoder, .. }
                | DecoderStage::DecodingOutputCount { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::Count(e)),
                    })?,
                DecoderStage::DecodingXpub { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::XpubValue(e)))?,
                DecoderStage::DecodingProprietary { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::ProprietaryValue(e)))?,
                DecoderStage::DecodingUnknown { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::UnknownValue(e)))?,
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpEcdhShare { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::SpEcdh(e)),
                    })?,
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpDleqProof { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::SpDleq(e)),
                    })?,
                DecoderStage::Done(_) => return Ok(DecoderStatus::Ready),
                DecoderStage::DecodingSeparator | DecoderStage::Errored =>
                    panic!("call to push_bytes() in unexpected stage"),
            };

            if status.needs_more() {
                return Ok(DecoderStatus::NeedsMore);
            }

            // State transition.
            let old = core::mem::replace(&mut self.stage, DecoderStage::Errored);
            match old {
                DecoderStage::DecodingKey(decoder) => match decoder.end() {
                    Ok(key) => {
                        self.stage = DecoderStage::from_key(key)?;
                    }
                    Err(e) => return Err(DecodeError::KeyDecode(e)),
                },
                DecoderStage::DecodingVersion { key, decoder } => {
                    let (value_len, version) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) => match e {
                            VersionDecoderError::UnexpectedEof(e) =>
                                DecodeError::ValueDecode(ValueDecodeError::Version(e)),
                            VersionDecoderError::UnsupportedVersion(e) =>
                                DecodeError::InsertPair(InsertPairError::WrongVersion(e.version())),
                        },
                    })?;
                    if value_len != 4 {
                        return Err(DecodeError::InsertPair(InsertPairError::ValueWrongLength(
                            value_len as usize,
                            4,
                        )));
                    }
                    if version != V2 {
                        return Err(DecodeError::InsertPair(InsertPairError::WrongVersion(
                            version.to_u32(),
                        )));
                    }
                    if self.version.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.version = Some(version);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTxVersion { key, decoder } => {
                    let (_, v) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::TxVersion(e)),
                    })?;
                    if self.tx_version.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.tx_version = Some(v);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingLockTime { key, decoder } => {
                    let (_, lt) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LockTime(e)),
                    })?;
                    if self.fallback_lock_time.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.fallback_lock_time = Some(lt);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingInputCount { key, decoder } => {
                    let (_, count) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::Count(e)),
                    })?;
                    if self.input_count.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.input_count = Some(count);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingOutputCount { key, decoder } => {
                    let (_, count) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::Count(e)),
                    })?;
                    if self.output_count.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.output_count = Some(count);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTxModifiable { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::ModifiableFlags(e)),
                    })?;
                    if self.tx_modifiable_flags.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.tx_modifiable_flags = Some(bytes[0]);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingXpub { key, decoder } => {
                    let value = decoder
                        .end()
                        .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::XpubValue(e)))?;
                    let xpub = Xpub::decode(&key.key)
                        .map_err(|e| DecodeError::InsertPair(InsertPairError::Bip32(e)))?;
                    if value.is_empty() {
                        return Err(DecodeError::InsertPair(InsertPairError::XpubValueEmpty));
                    }
                    if value.len() < 4 {
                        return Err(DecodeError::InsertPair(InsertPairError::XpubValueTooShort(
                            value.len(),
                        )));
                    }
                    if value.len() % 4 != 0 {
                        return Err(DecodeError::InsertPair(InsertPairError::XpubInvalidPath(
                            value.len(),
                        )));
                    }
                    let fingerprint = Fingerprint::from(
                        <[u8; 4]>::try_from(&value[..4]).expect("4 bytes checked above"),
                    );
                    let path = value[4..]
                        .chunks_exact(4)
                        .map(|c| {
                            ChildNumber::from(u32::from_le_bytes(
                                c.try_into().expect("4-byte chunks"),
                            ))
                        })
                        .collect::<Vec<_>>();
                    let derivation = DerivationPath::from(path);
                    if self.xpubs.insert(xpub, (fingerprint, derivation)).is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingProprietary { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::ProprietaryValue(e))
                    })?;
                    let pk = raw::ProprietaryKey::try_from(key.clone()).map_err(|_| {
                        DecodeError::InsertPair(InsertPairError::InvalidProprietaryKey)
                    })?;
                    match self.proprietaries.entry(pk) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) => {
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(
                                key,
                            )));
                        }
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingUnknown { key, decoder } => {
                    let value = decoder
                        .end()
                        .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::UnknownValue(e)))?;
                    match self.unknowns.entry(key) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(k) => {
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(
                                k.key().clone(),
                            )));
                        }
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpEcdhShare { key, decoder } => {
                    let (value_len, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::SpEcdh(e)),
                    })?;
                    if value_len != 33 {
                        return Err(DecodeError::InsertPair(InsertPairError::ValueWrongLength(
                            value_len as usize,
                            33,
                        )));
                    }
                    if key.key.is_empty() {
                        return Err(DecodeError::InsertPair(InsertPairError::InvalidKeyDataEmpty(
                            key,
                        )));
                    }
                    let scan_key = CompressedPublicKey::from_slice(&key.key)
                        .map_err(|_| InsertPairError::KeyWrongLength(key.key.len(), 33))?;
                    let share = CompressedPublicKey::from_slice(&bytes)
                        .map_err(|_| InsertPairError::ValueWrongLength(bytes.len(), 33))?;
                    match self.sp_ecdh_shares.entry(scan_key) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(share);
                        }
                        btree_map::Entry::Occupied(_) => {
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(
                                key,
                            )));
                        }
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpDleqProof { key, decoder } => {
                    let (value_len, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::SpDleq(e)),
                    })?;
                    if value_len != 64 {
                        return Err(DecodeError::InsertPair(InsertPairError::ValueWrongLength(
                            value_len as usize,
                            64,
                        )));
                    }
                    if key.key.is_empty() {
                        return Err(DecodeError::InsertPair(InsertPairError::InvalidKeyDataEmpty(
                            key,
                        )));
                    }
                    let scan_key = CompressedPublicKey::from_slice(&key.key)
                        .map_err(|_| InsertPairError::KeyWrongLength(key.key.len(), 33))?;
                    let proof = DleqProof::try_from(bytes.as_slice())
                        .map_err(|_| InsertPairError::ValueWrongLength(bytes.len(), 64))?;
                    match self.sp_dleq_proofs.entry(scan_key) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(proof);
                        }
                        btree_map::Entry::Occupied(_) => {
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(
                                key,
                            )));
                        }
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::Done(global) => {
                    self.stage = DecoderStage::Done(global);
                    return Ok(DecoderStatus::Ready);
                }
                DecoderStage::Errored => unreachable!("checked above"),
                DecoderStage::DecodingSeparator => unreachable!("handled before transition"),
            }
        }
    }

    fn end(self) -> Result<Global, Self::Error> {
        match self.stage {
            DecoderStage::Done(global) => Ok(global),
            _ => Err(DecodeError::EarlyEnd),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            DecoderStage::DecodingSeparator => 1,
            DecoderStage::DecodingKey(d) => d.read_limit(),
            DecoderStage::DecodingVersion { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingTxVersion { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingLockTime { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingInputCount { decoder, .. }
            | DecoderStage::DecodingOutputCount { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingTxModifiable { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingXpub { decoder, .. }
            | DecoderStage::DecodingProprietary { decoder, .. }
            | DecoderStage::DecodingUnknown { decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            DecoderStage::DecodingSpEcdhShare { decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            DecoderStage::DecodingSpDleqProof { decoder, .. } => decoder.read_limit(),
            DecoderStage::Done(_) | DecoderStage::Errored => 0,
        }
    }
}

type CountPair = KeyValueEncoder<CompactSizeEncoder, CompactSizeEncoder>;
type FlagsPair = KeyValueEncoder<CompactSizeEncoder, ArrayEncoder<1>>;

/// State of the global map encoder, one key-value pair group per variant.
enum State<'e> {
    Version(VersionKeyValueEncoder<'e>),
    TxVersion(TxVersionKeyValueEncoder<'e>),
    FallbackLockTime(FallbackLockTimeKeyValueEncoder<'e>),
    InputCount(CountPair),
    OutputCount(CountPair),
    Flags(FlagsPair),
    Xpubs(IterEncoder<XpubKeyValueIter<'e>>),
    #[cfg(feature = "silent-payments")]
    Ecdh(IterEncoder<EcdhKeyValueIter<'e>>),
    #[cfg(feature = "silent-payments")]
    Dleq(IterEncoder<DleqKeyValueIter<'e>>),
    Proprietaries(IterEncoder<ProprietaryKeyValueIter<'e>>),
    Unknowns(IterEncoder<UnknownKeyValueIter<'e>>),
    Separator(SeparatorEncoder),
}

/// Encoder for the PSBT global map.
pub struct GlobalMapEncoder<'e> {
    global: &'e Global,
    state: State<'e>,
}

impl<'e> GlobalMapEncoder<'e> {
    fn new(global: &'e Global) -> Self {
        let state = State::Version(KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_GLOBAL_VERSION),
            global.version.psbt_encoder(),
        ));
        Self { global, state }
    }

    /// Constructs the next state in field order after the current one, if any.
    fn next_state(&self) -> Option<State<'e>> {
        match &self.state {
            State::Version(_) => Some(State::TxVersion(self.tx_version_key_value())),
            State::TxVersion(_) =>
                if self.global.fallback_lock_time.is_some() {
                    Some(State::FallbackLockTime(self.fallback_key_value()))
                } else {
                    Some(State::InputCount(self.input_count_key_value()))
                },
            State::FallbackLockTime(_) => Some(State::InputCount(self.input_count_key_value())),
            State::InputCount(_) => Some(State::OutputCount(self.output_count_key_value())),
            State::OutputCount(_) => Some(State::Flags(self.flags_key_value())),
            State::Flags(_) => Some(State::Xpubs(self.xpub_iter())),
            State::Xpubs(_) => self.first_collection_after_xpubs(),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(_) => Some(State::Dleq(self.dleq_iter())),
            #[cfg(feature = "silent-payments")]
            State::Dleq(_) => Some(State::Proprietaries(self.proprietary_iter())),
            State::Proprietaries(_) => Some(State::Unknowns(self.unknown_iter())),
            State::Unknowns(_) => Some(State::Separator(SeparatorEncoder::new())),
            State::Separator(_) => None,
        }
    }

    fn tx_version_key_value(&self) -> TxVersionKeyValueEncoder<'e> {
        KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_GLOBAL_TX_VERSION),
            self.global.tx_version.psbt_encoder(),
        )
    }

    fn fallback_key_value(&self) -> FallbackLockTimeKeyValueEncoder<'e> {
        let lock_time = self.global.fallback_lock_time.as_ref().expect("checked by caller");
        KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_GLOBAL_FALLBACK_LOCKTIME),
            lock_time.psbt_encoder(),
        )
    }

    fn input_count_key_value(&self) -> CountPair {
        KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_GLOBAL_INPUT_COUNT),
            CompactSizeEncoder::new(self.global.input_count),
        )
    }

    fn output_count_key_value(&self) -> CountPair {
        KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_GLOBAL_OUTPUT_COUNT),
            CompactSizeEncoder::new(self.global.output_count),
        )
    }

    fn flags_key_value(&self) -> FlagsPair {
        KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_GLOBAL_TX_MODIFIABLE),
            ArrayEncoder::without_length_prefix([self.global.tx_modifiable_flags]),
        )
    }

    fn xpub_iter(&self) -> IterEncoder<XpubKeyValueIter<'e>> {
        IterEncoder::new(XpubKeyValueIter::new(self.global.xpubs.iter()))
    }

    #[cfg(feature = "silent-payments")]
    fn ecdh_iter(&self) -> IterEncoder<EcdhKeyValueIter<'e>> {
        IterEncoder::new(EcdhKeyValueIter::new(self.global.sp_ecdh_shares.iter()))
    }

    #[cfg(feature = "silent-payments")]
    fn dleq_iter(&self) -> IterEncoder<DleqKeyValueIter<'e>> {
        IterEncoder::new(DleqKeyValueIter::new(self.global.sp_dleq_proofs.iter()))
    }

    fn proprietary_iter(&self) -> IterEncoder<ProprietaryKeyValueIter<'e>> {
        IterEncoder::new(ProprietaryKeyValueIter(self.global.proprietaries.iter()))
    }

    fn unknown_iter(&self) -> IterEncoder<UnknownKeyValueIter<'e>> {
        IterEncoder::new(UnknownKeyValueIter(self.global.unknowns.iter()))
    }

    /// Returns the first collection state after the xpubs group.
    fn first_collection_after_xpubs(&self) -> Option<State<'e>> {
        #[cfg(feature = "silent-payments")]
        {
            Some(State::Ecdh(self.ecdh_iter()))
        }
        #[cfg(not(feature = "silent-payments"))]
        {
            Some(State::Proprietaries(self.proprietary_iter()))
        }
    }
}

impl Encoder for GlobalMapEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match &self.state {
            State::Version(e) => e.current_chunk(),
            State::TxVersion(e) => e.current_chunk(),
            State::FallbackLockTime(e) => e.current_chunk(),
            State::InputCount(e) => e.current_chunk(),
            State::OutputCount(e) => e.current_chunk(),
            State::Flags(e) => e.current_chunk(),
            State::Xpubs(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::Dleq(e) => e.current_chunk(),
            State::Proprietaries(e) => e.current_chunk(),
            State::Unknowns(e) => e.current_chunk(),
            State::Separator(e) => e.current_chunk(),
        }
    }

    fn advance(&mut self) -> EncoderStatus {
        let finished = match &mut self.state {
            State::Version(e) => e.advance().has_finished(),
            State::TxVersion(e) => e.advance().has_finished(),
            State::FallbackLockTime(e) => e.advance().has_finished(),
            State::InputCount(e) => e.advance().has_finished(),
            State::OutputCount(e) => e.advance().has_finished(),
            State::Flags(e) => e.advance().has_finished(),
            State::Xpubs(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::Dleq(e) => e.advance().has_finished(),
            State::Proprietaries(e) => e.advance().has_finished(),
            State::Unknowns(e) => e.advance().has_finished(),
            State::Separator(e) => e.advance().has_finished(),
        };

        if finished {
            loop {
                match self.next_state() {
                    Some(next) => self.state = next,
                    None => return EncoderStatus::Finished,
                }
                // Hop past any empty groups (e.g. an empty collection iterator).
                if !self.current_chunk().is_empty() {
                    return EncoderStatus::HasMore;
                }
            }
        }
        EncoderStatus::HasMore
    }
}

impl PsbtEncode for Global {
    type Encoder<'e> = GlobalMapEncoder<'e>;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        // `<global-map> := <keypair>* <PSBT_SEPARATOR>`
        GlobalMapEncoder::new(self)
    }
}

impl Map for Global {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_VERSION, key: vec![] },
            value: self.version.serialize(),
        });

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_TX_VERSION, key: vec![] },
            value: self.tx_version.serialize(),
        });

        v2_impl_psbt_get_pair! {
            rv.push(self.fallback_lock_time, PSBT_GLOBAL_FALLBACK_LOCKTIME)
        }

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_INPUT_COUNT, key: vec![] },
            value: VarInt::from(self.input_count).serialize(),
        });

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_OUTPUT_COUNT, key: vec![] },
            value: VarInt::from(self.output_count).serialize(),
        });

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_GLOBAL_TX_MODIFIABLE, key: vec![] },
            value: vec![self.tx_modifiable_flags],
        });

        for (xpub, (fingerprint, derivation)) in &self.xpubs {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_GLOBAL_XPUB, key: xpub.encode().to_vec() },
                value: {
                    let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                    ret.extend(fingerprint.as_bytes());
                    derivation.into_iter().for_each(|n| ret.extend(&u32::from(*n).to_le_bytes()));
                    ret
                },
            });
        }

        #[cfg(feature = "silent-payments")]
        for (scan_key, ecdh_share) in &self.sp_ecdh_shares {
            rv.push(raw::Pair {
                key: raw::Key {
                    type_value: PSBT_GLOBAL_SP_ECDH_SHARE,
                    key: scan_key.to_bytes().to_vec(),
                },
                value: ecdh_share.to_bytes().to_vec(),
            });
        }

        #[cfg(feature = "silent-payments")]
        for (scan_key, dleq_proof) in &self.sp_dleq_proofs {
            rv.push(raw::Pair {
                key: raw::Key {
                    type_value: PSBT_GLOBAL_SP_DLEQ,
                    key: scan_key.to_bytes().to_vec(),
                },
                value: dleq_proof.as_bytes().to_vec(),
            });
        }

        for (key, value) in self.proprietaries.iter() {
            rv.push(raw::Pair { key: key.to_key(), value: value.clone() });
        }

        for (key, value) in self.unknowns.iter() {
            rv.push(raw::Pair { key: key.clone(), value: value.clone() });
        }

        rv
    }
}

/// Error decoding a PSBT value (compact-size length prefix + payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueDecodeError {
    /// Error decoding the value's length prefix.
    LengthPrefix(CompactSizeDecoderError),
    /// Error decoding the PSBT version value.
    Version(UnexpectedEofError),
    /// Error decoding the transaction modifiable flags value.
    ModifiableFlags(UnexpectedEofError),
    /// Error decoding a count (VarInt) value.
    Count(CompactSizeDecoderError),
    /// Error decoding a transaction version value.
    TxVersion(bitcoin::transaction::VersionDecoderError),
    /// Error decoding a lock time value.
    LockTime(bitcoin::locktime::absolute::LockTimeDecoderError),
    /// Error decoding an xpub value.
    XpubValue(ByteVecDecoderError),
    /// Error decoding a proprietary value.
    ProprietaryValue(ByteVecDecoderError),
    /// Error decoding an unknown value.
    UnknownValue(ByteVecDecoderError),
    /// Error decoding a silent payments ECDH share value.
    #[cfg(feature = "silent-payments")]
    SpEcdh(UnexpectedEofError),
    /// Error decoding a silent payments DLEQ proof value.
    #[cfg(feature = "silent-payments")]
    SpDleq(UnexpectedEofError),
}

impl fmt::Display for ValueDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthPrefix(ref e) => write_err!(f, "error decoding value length prefix"; e),
            Self::Version(ref e) => write_err!(f, "error decoding PSBT version"; e),
            Self::ModifiableFlags(ref e) => write_err!(f, "error decoding modifiable flags"; e),
            Self::Count(ref e) => write_err!(f, "error decoding count"; e),
            Self::TxVersion(ref e) => write_err!(f, "error decoding transaction version"; e),
            Self::LockTime(ref e) => write_err!(f, "error decoding lock time"; e),
            Self::XpubValue(ref e) => write_err!(f, "error decoding xpub value"; e),
            Self::ProprietaryValue(ref e) => write_err!(f, "error decoding proprietary value"; e),
            Self::UnknownValue(ref e) => write_err!(f, "error decoding unknown value"; e),
            #[cfg(feature = "silent-payments")]
            Self::SpEcdh(ref e) => write_err!(f, "error decoding SP ECDH share"; e),
            #[cfg(feature = "silent-payments")]
            Self::SpDleq(ref e) => write_err!(f, "error decoding SP DLEQ proof"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValueDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LengthPrefix(ref e) => Some(e),
            Self::Version(ref e) => Some(e),
            Self::ModifiableFlags(ref e) => Some(e),
            Self::Count(ref e) => Some(e),
            Self::TxVersion(ref e) => Some(e),
            Self::LockTime(ref e) => Some(e),
            Self::XpubValue(ref e) => Some(e),
            Self::ProprietaryValue(ref e) => Some(e),
            Self::UnknownValue(ref e) => Some(e),
            #[cfg(feature = "silent-payments")]
            Self::SpEcdh(ref e) => Some(e),
            #[cfg(feature = "silent-payments")]
            Self::SpDleq(ref e) => Some(e),
        }
    }
}

/// An error while decoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Error inserting a key-value pair.
    InsertPair(InsertPairError),
    /// Error decoding a key from the stream.
    KeyDecode(raw::KeyDecodeError),
    /// Error decoding a value.
    ValueDecode(ValueDecodeError),
    /// Called `end()` before the end-of-map separator was reached.
    EarlyEnd,
    /// Serialized PSBT is missing the version number.
    MissingVersion,
    /// Serialized PSBT is missing the transaction version number.
    MissingTxVersion,
    /// Serialized PSBT is missing the input count.
    MissingInputCount,
    /// Input count overflows word size for current architecture.
    InputCountOverflow(u64),
    /// Serialized PSBT is missing the output count.
    MissingOutputCount,
    /// Output count overflows word size for current architecture.
    OutputCountOverflow(u64),
    /// ECDH shares and DLEQ proofs must both be present or both absent.
    FieldMismatch,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsertPair(ref e) => write_err!(f, "error inserting a pair"; e),
            Self::KeyDecode(ref e) => write_err!(f, "error decoding key"; e),
            Self::ValueDecode(ref e) => write_err!(f, "error decoding value"; e),
            Self::EarlyEnd => write!(f, "called end() before completing global map decode"),
            Self::MissingVersion => write!(f, "serialized PSBT is missing the version number"),
            Self::MissingTxVersion => {
                write!(f, "serialized PSBT is missing the transaction version number")
            }
            Self::MissingInputCount => write!(f, "serialized PSBT is missing the input count"),
            Self::InputCountOverflow(count) => {
                write!(f, "input count overflows word size for current architecture: {}", count)
            }
            Self::MissingOutputCount => write!(f, "serialized PSBT is missing the output count"),
            Self::OutputCountOverflow(count) => {
                write!(f, "output count overflows word size for current architecture: {}", count)
            }
            Self::FieldMismatch => {
                write!(f, "ECDH shares and DLEQ proofs must both be present or both absent")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InsertPair(ref e) => Some(e),
            Self::KeyDecode(ref e) => Some(e),
            Self::ValueDecode(ref e) => Some(e),
            Self::MissingVersion
            | Self::MissingTxVersion
            | Self::MissingInputCount
            | Self::InputCountOverflow(_)
            | Self::MissingOutputCount
            | Self::OutputCountOverflow(_)
            | Self::FieldMismatch
            | Self::EarlyEnd => None,
        }
    }
}

impl From<InsertPairError> for DecodeError {
    fn from(e: InsertPairError) -> Self { Self::InsertPair(e) }
}

/// Error inserting a key-value pair.
#[derive(Debug)]
pub enum InsertPairError {
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// Key should contain data.
    InvalidKeyDataEmpty(raw::Key),
    /// Key should not contain data.
    InvalidKeyDataNotEmpty(raw::Key),
    /// Value was not the correct length (got, want).
    // TODO: Use struct instead of tuple.
    ValueWrongLength(usize, usize),
    /// PSBT_GLOBAL_VERSION: PSBT v2 expects the version to be 2.
    WrongVersion(u32),
    /// PSBT_GLOBAL_XPUB: Must contain 4 bytes for the xpub fingerprint.
    XpubInvalidFingerprint,
    /// PSBT_GLOBAL_XPUB: value must contain at least 4 bytes for the xpub fingerprint.
    XpubValueTooShort(usize),
    /// PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints.
    XpubInvalidPath(usize),
    /// PSBT_GLOBAL_XPUB: value must not be empty.
    XpubValueEmpty,
    /// PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type.
    Bip32(bip32::Error),
    /// PSBT_GLOBAL_XPUB: xpubs must be unique.
    DuplicateXpub(KeySource),
    /// PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key.
    InvalidProprietaryKey,
    /// Key must be excluded from this version of PSBT (see consts.rs for u8 values).
    ExcludedKey {
        /// Key type value we found.
        key_type_value: u64,
    },
    /// Key was not the correct length (got, expected).
    KeyWrongLength(usize, usize),
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Self::InvalidKeyDataEmpty(ref key) => write!(f, "key should contain data: {}", key),
            Self::InvalidKeyDataNotEmpty(ref key) =>
                write!(f, "key should not contain data: {}", key),
            Self::ValueWrongLength(got, want) => {
                write!(f, "value (keyvalue pair) wrong length (got, want) {} {}", got, want)
            }
            Self::WrongVersion(v) => {
                write!(f, "PSBT_GLOBAL_VERSION: PSBT v2 expects the version to be 2, found: {}", v)
            }
            Self::XpubInvalidFingerprint => {
                write!(f, "PSBT_GLOBAL_XPUB: xpub fingerprint must be 4 bytes")
            }
            Self::XpubInvalidPath(len) => write!(
                f,
                "PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints: {}",
                len
            ),
            Self::XpubValueTooShort(got) => write!(
                f,
                "PSBT_GLOBAL_XPUB: value must contain at least 4 bytes for the xpub fingerprint, got: {}",
                got
            ),
            Self::Bip32(ref e) =>
                write_err!(f, "PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type"; e),
            Self::DuplicateXpub((fingerprint, ref derivation_path)) => write!(
                f,
                "PSBT_GLOBAL_XPUB: xpubs must be unique ({}, {})",
                fingerprint, derivation_path
            ),
            Self::XpubValueEmpty => write!(f, "PSBT_GLOBAL_XPUB: keypair value must not be empty"),
            Self::InvalidProprietaryKey =>
                write!(f, "PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key"),
            Self::ExcludedKey { key_type_value } => write!(
                f,
                "found a keypair type that is explicitly excluded: {}",
                consts::psbt_global_key_type_value_to_str(*key_type_value)
            ),
            Self::KeyWrongLength(got, expected) => {
                write!(f, "key wrong length (got: {}, expected: {})", got, expected)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bip32(ref e) => Some(e),
            Self::DuplicateKey(_)
            | Self::InvalidKeyDataEmpty(_)
            | Self::InvalidKeyDataNotEmpty(_)
            | Self::ValueWrongLength(..)
            | Self::WrongVersion(_)
            | Self::XpubInvalidFingerprint
            | Self::XpubInvalidPath(_)
            | Self::XpubValueTooShort(_)
            | Self::DuplicateXpub(_)
            | Self::XpubValueEmpty
            | Self::InvalidProprietaryKey
            | Self::ExcludedKey { .. }
            | Self::KeyWrongLength(..) => None,
        }
    }
}

impl From<bip32::Error> for InsertPairError {
    fn from(e: bip32::Error) -> Self { Self::Bip32(e) }
}

/// Error combining two global maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// The version numbers are not the same.
    VersionMismatch {
        /// Attempted to combine a PSBT with `this` version.
        this: Version,
        /// Into a PSBT with `that` version.
        that: Version,
    },
    /// The transaction version numbers are not the same.
    TxVersionMismatch {
        /// Attempted to combine a PSBT with `this` tx version.
        this: transaction::Version,
        /// Into a PSBT with `that` tx version.
        that: transaction::Version,
    },
    /// Xpubs have inconsistent key sources.
    InconsistentKeySources(InconsistentKeySourcesError),
}

impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionMismatch { ref this, ref that } => {
                write!(f, "combine two PSBTs with different versions: {:?} {:?}", this, that)
            }
            Self::TxVersionMismatch { ref this, ref that } => {
                write!(f, "combine two PSBTs with different tx versions: {:?} {:?}", this, that)
            }
            Self::InconsistentKeySources(ref e) => {
                write_err!(f, "combine with inconsistent key sources"; e)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InconsistentKeySources(ref e) => Some(e),
            Self::VersionMismatch { .. } | Self::TxVersionMismatch { .. } => None,
        }
    }
}

impl From<InconsistentKeySourcesError> for CombineError {
    fn from(e: InconsistentKeySourcesError) -> Self { Self::InconsistentKeySources(e) }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::encoding::encode_to_vec;
    use crate::map::Map;

    fn sample_xpub() -> Xpub {
        Xpub::from_str(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        )
        .unwrap()
    }

    // Asserts the native pull-based encoder produces exactly `Map::serialize_map`'s bytes and
    // that the map round-trips through the Read-based `Global::decode`.
    fn check_global(global: &Global) {
        let encoded = encode_to_vec(global);
        assert_eq!(encoded, Map::serialize_map(global));
        assert_eq!(encoded.last(), Some(&PSBT_SEPARATOR), "global map must end with separator");

        let mut slice: &[u8] = &encoded;
        let mut decoder = GlobalDecoder::default();
        decoder.push_bytes(&mut slice).unwrap();
        let decoded = decoder.end().unwrap();
        assert_eq!(decoded, global.clone());
    }

    #[test]
    fn pairs_matches_serialize_map() {
        let global = Global::default();

        let mut from_pairs = Vec::new();
        for pair in global.pairs() {
            from_pairs.extend(pair.serialize());
        }
        from_pairs.push(PSBT_SEPARATOR);

        assert_eq!(from_pairs, Map::serialize_map(&global));
    }

    #[test]
    fn encode_default() {
        let global = Global::default();
        check_global(&global);
    }

    #[test]
    fn encode_nonempty() {
        let global = Global::default();
        let bytes = encode_to_vec(&global);
        assert!(!bytes.is_empty());
        assert!(bytes.len() > 1, "map must have at least one keypair before separator");
        assert_eq!(bytes.last(), Some(&PSBT_SEPARATOR), "global map must end with separator");
    }

    #[test]
    fn read_limit_lifecycle() {
        let global = Global::default();
        let bytes = crate::encoding::encode_to_vec(&global);

        let mut decoder = GlobalDecoder::default();
        assert_eq!(decoder.read_limit(), 1, "fresh decoder should request bytes");

        let mut remaining = &bytes[..];
        assert!(decoder.push_bytes(&mut remaining).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0, "completed decoder should request no bytes");
    }

    #[test]
    fn encode_fallback_locktime() {
        let global = Global {
            fallback_lock_time: Some(absolute::LockTime::from_consensus(500)),
            ..Default::default()
        };

        check_global(&global);
    }

    #[test]
    fn encode_xpubs() {
        let mut global = Global::default();
        let key_source: KeySource =
            (Fingerprint::from([0x42, 0x99, 0x69, 0xf0]), DerivationPath::default());
        global.xpubs.insert(sample_xpub(), key_source);

        check_global(&global);
    }

    #[test]
    fn encode_proprietaries_and_unknowns() {
        let mut global = Global::default();
        global.proprietaries.insert(
            raw::ProprietaryKey { prefix: b"test".to_vec(), subtype: 0x42, key: vec![1, 2, 3] },
            vec![0xde, 0xad],
        );
        global
            .unknowns
            .insert(raw::Key { type_value: 0x51, key: vec![0xaa, 0xbb] }, vec![0xcc, 0xdd]);

        check_global(&global);
    }

    #[test]
    #[cfg(feature = "silent-payments")]
    fn encode_silent_payments() {
        use core::str::FromStr;

        use crate::dleq::DleqProof;

        let mut global = Global::default();
        let compressed = bitcoin::CompressedPublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();

        global.sp_ecdh_shares.insert(compressed, compressed);
        global.sp_dleq_proofs.insert(compressed, DleqProof([0x42; 64]));

        check_global(&global);
    }

    #[test]
    fn read_limit_expands_for_newtype_decoders() {
        // ValueDecoder always wraps a CompactSizeU64Decoder so read_limit > 1.
        assert!(ValueDecoder::<ArrayDecoder<4>>::default().read_limit() > 1);
        assert!(ValueDecoder::<ArrayDecoder<1>>::default().read_limit() > 1);
        assert!(CountValueDecoder::default().read_limit() > 1);
    }

    #[test]
    fn excluded_key_type_is_rejected() {
        // PSBT_GLOBAL_UNSIGNED_TX (0x00) should not be accepted as a valid global key.
        let key = raw::Key { type_value: 0x00, key: vec![] };
        let err = DecoderStage::from_key(key).unwrap_err();
        match err {
            DecodeError::InsertPair(InsertPairError::ExcludedKey { key_type_value: v }) =>
                assert_eq!(v, 0x00),
            _ => panic!("expected ExcludedKey, got {:?}", err),
        }
    }

    #[test]
    fn xpub_value_too_short() {
        // An xpub value must be at least 4 bytes (fingerprint).
        let mut decoder = GlobalDecoder::default();
        let key_type = crate::consts::PSBT_GLOBAL_XPUB;
        let xpub = sample_xpub();
        let encoded = crate::encoding::encode_to_vec(&xpub);
        // Key: compact_size(len) | key_type | xpub_bytes
        let key_body = [&[key_type as u8][..], &encoded].concat();
        let mut data = vec![];
        // key-len compact size
        data.push(key_body.len() as u8);
        data.extend_from_slice(&key_body);
        // value-len compact size: 3 bytes (too short)
        data.push(0x03);
        data.extend_from_slice(&[0xde, 0xad, 0xbe]);
        // separator
        data.push(PSBT_SEPARATOR);
        let res = decoder.push_bytes(&mut data.as_slice());
        assert!(
            matches!(res, Err(DecodeError::InsertPair(InsertPairError::XpubValueTooShort(3)))),
            "expected XpubValueTooShort(3), got {:?}",
            res,
        );
    }
}
