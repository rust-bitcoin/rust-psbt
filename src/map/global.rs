// SPDX-License-Identifier: CC0-1.0

use alloc::collections::{btree_map, BTreeMap};
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::{DerivationPath, Fingerprint, KeySource, Xpub};
use bitcoin::locktime::absolute;
use bitcoin::transaction;
#[cfg(feature = "silent-payments")]
use bitcoin::CompressedPublicKey;
use bitcoin_consensus_encoding::{
    ArrayEncoder, ByteVecDecoder, CompactSizeEncoder, Decoder, DecoderStatus, Encoder,
    EncoderStatus, IterEncoder,
};

use super::framing::{KeyValueEncoder, KeyValueIter, ValueDecoder, ValueDecoderError};
use super::{
    Count, Key, KeyDecoder, ProprietaryKey, ProprietaryKeyValueIter, SeparatorEncoder,
    UnknownKeyValueIter,
};
use crate::consts::{
    PSBT_GLOBAL_FALLBACK_LOCKTIME, PSBT_GLOBAL_INPUT_COUNT, PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_PROPRIETARY, PSBT_GLOBAL_TX_MODIFIABLE, PSBT_GLOBAL_TX_VERSION,
    PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION, PSBT_GLOBAL_XPUB, PSBT_SEPARATOR,
};
#[cfg(feature = "silent-payments")]
use crate::consts::{PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_SP_ECDH_SHARE};
use crate::encoding::codecs::KeySourceDecoder;
use crate::encoding::PsbtEncode;
use crate::error::write_err;
use crate::map::error::{GlobalDecodeError, KeyDecodeError, XpubDecodeError};
#[cfg(feature = "silent-payments")]
use crate::silent_payments::DleqProof;
use crate::tx_modifiable_flags::TxModifiableFlags;
use crate::version::{Version, VersionDecoderError, VersionEncoder};
use crate::{InconsistentKeySourcesError, V2};

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
    pub tx_modifiable_flags: TxModifiableFlags,
    /// The number of inputs in this PSBT.
    pub input_count: usize,
    /// The number of outputs in this PSBT.
    pub output_count: usize,
    /// A map from xpub to the used key fingerprint and derivation path as defined by BIP 32.
    pub xpubs: BTreeMap<Xpub, KeySource>,
    /// BIP-375: Map from scan public key to ECDH share.
    #[cfg(feature = "silent-payments")]
    #[cfg_attr(feature = "serde", serde(with = "crate::map::serde::btreemap_as_seq"))]
    pub sp_ecdh_shares: BTreeMap<CompressedPublicKey, CompressedPublicKey>,
    /// BIP-375: Map from scan public key to DLEQ proof.
    #[cfg(feature = "silent-payments")]
    #[cfg_attr(feature = "serde", serde(with = "crate::map::serde::btreemap_as_seq"))]
    pub sp_dleq_proofs: BTreeMap<CompressedPublicKey, DleqProof>,
    /// Global proprietary key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::map::serde::btreemap_as_seq_byte_values"))]
    pub proprietaries: BTreeMap<ProprietaryKey, Vec<u8>>,
    /// Unknown global key-value pairs.
    #[cfg_attr(feature = "serde", serde(with = "crate::map::serde::btreemap_as_seq_byte_values"))]
    pub unknowns: BTreeMap<Key, Vec<u8>>,
}

impl Global {
    fn new() -> Self {
        Self {
            version: V2,
            // TODO: Is this default correct?
            tx_version: transaction::Version::TWO,
            fallback_lock_time: None,
            tx_modifiable_flags: TxModifiableFlags::new(),
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
                    return Err(CombineError::InconsistentKeySources(InconsistentKeySourcesError(
                        xpub,
                    )));
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

/// The internal state of the global map push decoder.
#[derive(Debug, Default)]
enum DecoderStage {
    /// Checking the next byte for the map separator.
    #[default]
    DecodingSeparator,
    /// Reading the next key from the stream. The caller has already confirmed the
    /// stream does not start with a separator, so this decoder only sees real key data.
    DecodingKey(KeyDecoder),
    /// Decoding a version value.
    DecodingVersion { key: Key, decoder: VersionValueDecoder },
    /// Decoding a transaction version value.
    DecodingTxVersion { key: Key, decoder: TxVersionValueDecoder },
    /// Decoding a lock time value.
    DecodingLockTime { key: Key, decoder: FallbackLockTimeValueDecoder },
    /// Decoding an input count value.
    DecodingInputCount { key: Key, decoder: CountValueDecoder },
    /// Decoding an output count value.
    DecodingOutputCount { key: Key, decoder: CountValueDecoder },
    /// Decoding a single-byte modifiable-flags value.
    DecodingTxModifiable { key: Key, decoder: FlagsValueDecoder },
    /// Decoding an xpub value (fingerprint + path).
    DecodingXpub { key: Key, decoder: KeySourceDecoder },
    /// Decoding a proprietary value.
    DecodingProprietary { key: Key, decoder: ByteVecDecoder },
    /// Decoding an unknown value.
    DecodingUnknown { key: Key, decoder: ByteVecDecoder },
    #[cfg(feature = "silent-payments")]
    /// Decoding an ECDH share for silent payments.
    DecodingSpEcdhShare { key: Key, decoder: ValueDecoder<CompressedPublicKey> },
    #[cfg(feature = "silent-payments")]
    /// Decoding a DLEQ proof for silent payments.
    DecodingSpDleqProof { key: Key, decoder: ValueDecoder<DleqProof> },
    /// The end-of-map separator has been reached.
    Done(Global),
    /// The decoder has entered a non-recoverable error state.
    Errored,
}

impl DecoderStage {
    /// Select the appropriate value-decoding stage based on the decoded key.
    fn from_key(key: Key) -> Result<Self, GlobalDecodeError> {
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
            PSBT_GLOBAL_XPUB =>
                Ok(Self::DecodingXpub { key, decoder: KeySourceDecoder::default() }),
            PSBT_GLOBAL_PROPRIETARY =>
                Ok(Self::DecodingProprietary { key, decoder: ByteVecDecoder::new() }),
            #[cfg(feature = "silent-payments")]
            PSBT_GLOBAL_SP_ECDH_SHARE =>
                Ok(Self::DecodingSpEcdhShare { key, decoder: ValueDecoder::default() }),
            #[cfg(feature = "silent-payments")]
            PSBT_GLOBAL_SP_DLEQ =>
                Ok(Self::DecodingSpDleqProof { key, decoder: ValueDecoder::default() }),
            v if v == PSBT_GLOBAL_UNSIGNED_TX =>
                Err(GlobalDecodeError::KeyDecode(KeyDecodeError::ExcludedKey { key_type_value: v })),
            _ => Ok(Self::DecodingUnknown { key, decoder: ByteVecDecoder::new() }),
        }
    }
}

/// Decoder for a PSBT global map.
///
/// Uses a push-based state machine. After each key is decoded, a type-specific composite
/// decoder (handling both the compact-size length prefix and the value) is selected based
/// on the key type.
#[derive(Debug, Default)]
pub struct GlobalDecoder {
    stage: DecoderStage,
    /// Required fields.
    version: Option<Version>,
    tx_version: Option<transaction::Version>,
    input_count: Option<usize>,
    output_count: Option<usize>,
    /// Optional / accumulating fields.
    fallback_lock_time: Option<absolute::LockTime>,
    tx_modifiable_flags: Option<TxModifiableFlags>,
    xpubs: BTreeMap<Xpub, (Fingerprint, DerivationPath)>,
    #[cfg(feature = "silent-payments")]
    sp_ecdh_shares: BTreeMap<CompressedPublicKey, CompressedPublicKey>,
    #[cfg(feature = "silent-payments")]
    sp_dleq_proofs: BTreeMap<CompressedPublicKey, DleqProof>,
    proprietaries: BTreeMap<ProprietaryKey, Vec<u8>>,
    unknowns: BTreeMap<Key, Vec<u8>>,
}

impl Decoder for GlobalDecoder {
    type Output = Global;
    type Error = GlobalDecodeError;

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
                        let version =
                            self.version.take().ok_or(GlobalDecodeError::MissingVersion)?;
                        let tx_version =
                            self.tx_version.take().ok_or(GlobalDecodeError::MissingTxVersion)?;
                        let tx_modifiable_flags =
                            self.tx_modifiable_flags.take().unwrap_or_default();

                        let input_count =
                            self.input_count.take().ok_or(GlobalDecodeError::MissingInputCount)?;

                        let output_count = self
                            .output_count
                            .take()
                            .ok_or(GlobalDecodeError::MissingOutputCount)?;

                        #[cfg(feature = "silent-payments")]
                        {
                            let has_ecdh = !self.sp_ecdh_shares.is_empty();
                            let has_dleq = !self.sp_dleq_proofs.is_empty();
                            if has_ecdh != has_dleq {
                                return Err(GlobalDecodeError::SpFieldMismatch);
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
                        self.stage = DecoderStage::DecodingKey(KeyDecoder::default());
                    }
                    None => return Ok(DecoderStatus::NeedsMore),
                }
            }

            // Push bytes into the active stage decoder.
            let status = match &mut self.stage {
                DecoderStage::DecodingKey(d) =>
                    d.push_bytes(bytes).map_err(GlobalDecodeError::KeyDecode)?,
                DecoderStage::DecodingVersion { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(GlobalDecodeError::Version)?,
                DecoderStage::DecodingTxVersion { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(GlobalDecodeError::TxVersion)?,
                DecoderStage::DecodingLockTime { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(GlobalDecodeError::LockTime)?,
                DecoderStage::DecodingTxModifiable { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(GlobalDecodeError::ModifiableFlags)?,
                DecoderStage::DecodingInputCount { ref mut decoder, .. }
                | DecoderStage::DecodingOutputCount { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(GlobalDecodeError::Count)?,
                DecoderStage::DecodingXpub { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| GlobalDecodeError::Xpub(XpubDecodeError::KeySource(e)))?,
                DecoderStage::DecodingProprietary { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(GlobalDecodeError::ProprietaryValue)?,
                DecoderStage::DecodingUnknown { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(GlobalDecodeError::UnknownValue)?,
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpEcdhShare { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(GlobalDecodeError::SpEcdh)?,
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpDleqProof { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(GlobalDecodeError::SpDleq)?,
                DecoderStage::Done(_) => return Ok(DecoderStatus::Ready),
                DecoderStage::DecodingSeparator | DecoderStage::Errored => {
                    panic!("call to push_bytes() in unexpected stage")
                }
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
                    Err(e) => return Err(GlobalDecodeError::KeyDecode(e)),
                },
                DecoderStage::DecodingVersion { key, decoder } => {
                    let version = decoder.end().map_err(|e| {
                        if let ValueDecoderError::Inner(VersionDecoderError::UnsupportedVersion(
                            v,
                        )) = &e
                        {
                            return GlobalDecodeError::WrongVersion(v.version());
                        }
                        GlobalDecodeError::Version(e)
                    })?;
                    if version != V2 {
                        return Err(GlobalDecodeError::WrongVersion(version.to_u32()));
                    }
                    if self.version.is_some() {
                        return Err(GlobalDecodeError::DuplicateKey(key));
                    }
                    self.version = Some(version);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTxVersion { key, decoder } => {
                    let v = decoder.end().map_err(GlobalDecodeError::TxVersion)?;
                    if self.tx_version.is_some() {
                        return Err(GlobalDecodeError::DuplicateKey(key));
                    }
                    self.tx_version = Some(v);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingLockTime { key, decoder } => {
                    let lt = decoder.end().map_err(GlobalDecodeError::LockTime)?;
                    if self.fallback_lock_time.is_some() {
                        return Err(GlobalDecodeError::DuplicateKey(key));
                    }
                    self.fallback_lock_time = Some(lt);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingInputCount { key, decoder } => {
                    let count = decoder.end().map_err(GlobalDecodeError::Count)?;
                    if self.input_count.is_some() {
                        return Err(GlobalDecodeError::DuplicateKey(key));
                    }
                    self.input_count = Some(count.0);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingOutputCount { key, decoder } => {
                    let count = decoder.end().map_err(GlobalDecodeError::Count)?;
                    if self.output_count.is_some() {
                        return Err(GlobalDecodeError::DuplicateKey(key));
                    }
                    self.output_count = Some(count.0);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTxModifiable { key, decoder } => {
                    let flags = decoder.end().map_err(GlobalDecodeError::ModifiableFlags)?;
                    if self.tx_modifiable_flags.is_some() {
                        return Err(GlobalDecodeError::DuplicateKey(key));
                    }
                    self.tx_modifiable_flags = Some(flags);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingXpub { key, decoder } => {
                    let key_source = decoder
                        .end()
                        .map_err(|e| GlobalDecodeError::Xpub(XpubDecodeError::KeySource(e)))?;
                    let xpub = Xpub::decode(&key.key)
                        .map_err(|e| GlobalDecodeError::Xpub(XpubDecodeError::Key(e)))?;
                    if self.xpubs.insert(xpub, key_source).is_some() {
                        return Err(GlobalDecodeError::DuplicateKey(key));
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingProprietary { key, decoder } => {
                    let value = decoder.end().map_err(GlobalDecodeError::ProprietaryValue)?;
                    let pk = ProprietaryKey::try_from(key).map_err(|_| {
                        GlobalDecodeError::KeyDecode(KeyDecodeError::InvalidProprietaryKey)
                    })?;
                    match self.proprietaries.entry(pk) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(e) => {
                            return Err(GlobalDecodeError::DuplicateKey(e.key().to_key()));
                        }
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingUnknown { key, decoder } => {
                    let value = decoder.end().map_err(GlobalDecodeError::UnknownValue)?;
                    match self.unknowns.entry(key) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(k) => {
                            return Err(GlobalDecodeError::DuplicateKey(k.key().clone()));
                        }
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpEcdhShare { key, decoder } => {
                    let share = decoder.end().map_err(GlobalDecodeError::SpEcdh)?;
                    if key.key.is_empty() {
                        return Err(GlobalDecodeError::KeyDecode(KeyDecodeError::InvalidKeyData(
                            key,
                        )));
                    }
                    let scan_key = CompressedPublicKey::from_slice(&key.key).map_err(|_| {
                        GlobalDecodeError::KeyDecode(KeyDecodeError::InvalidKeyData(key.clone()))
                    })?;
                    match self.sp_ecdh_shares.entry(scan_key) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(share);
                        }
                        btree_map::Entry::Occupied(_) => {
                            return Err(GlobalDecodeError::DuplicateKey(key));
                        }
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpDleqProof { key, decoder } => {
                    let proof = decoder.end().map_err(GlobalDecodeError::SpDleq)?;
                    if key.key.is_empty() {
                        return Err(GlobalDecodeError::KeyDecode(KeyDecodeError::InvalidKeyData(
                            key,
                        )));
                    }
                    let scan_key = CompressedPublicKey::from_slice(&key.key).map_err(|_| {
                        GlobalDecodeError::KeyDecode(KeyDecodeError::InvalidKeyData(key.clone()))
                    })?;
                    match self.sp_dleq_proofs.entry(scan_key) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(proof);
                        }
                        btree_map::Entry::Occupied(_) => {
                            return Err(GlobalDecodeError::DuplicateKey(key));
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
            _ => Err(GlobalDecodeError::EarlyEnd),
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
            DecoderStage::DecodingXpub { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingProprietary { decoder, .. }
            | DecoderStage::DecodingUnknown { decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            DecoderStage::DecodingSpEcdhShare { decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            DecoderStage::DecodingSpDleqProof { decoder, .. } => decoder.read_limit(),
            DecoderStage::Done(_) | DecoderStage::Errored => 0,
        }
    }
}

/// State of the global map encoder, one key-value pair group per variant.
enum State<'e> {
    Version(VersionKeyValueEncoder<'e>),
    TxVersion(TxVersionPair<'e>),
    FallbackLockTime(FallbackLockTimePair<'e>),
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

    fn tx_version_key_value(&self) -> TxVersionPair<'e> {
        KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_GLOBAL_TX_VERSION),
            self.global.tx_version.psbt_encoder(),
        )
    }

    fn fallback_key_value(&self) -> FallbackLockTimePair<'e> {
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
            self.global.tx_modifiable_flags.psbt_encoder(),
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

/// Encoder for an input or output count key-value pair (PSBT_GLOBAL_INPUT_COUNT / PSBT_GLOBAL_OUTPUT_COUNT).
pub(crate) type CountPair = KeyValueEncoder<CompactSizeEncoder, CompactSizeEncoder>;
/// Encoder for the tx modifiable flags key-value pair (PSBT_GLOBAL_TX_MODIFIABLE).
pub(crate) type FlagsPair = KeyValueEncoder<CompactSizeEncoder, ArrayEncoder<1>>;
/// Decoder for a count value (PSBT_GLOBAL_INPUT_COUNT / PSBT_GLOBAL_OUTPUT_COUNT).
pub(crate) type CountValueDecoder = ValueDecoder<Count>;
/// Decoder for the tx modifiable flags value (PSBT_GLOBAL_TX_MODIFIABLE).
pub(crate) type FlagsValueDecoder = ValueDecoder<TxModifiableFlags>;
/// Encoder for the version key-value pair (PSBT_GLOBAL_VERSION).
pub(crate) type VersionKeyValueEncoder<'e> =
    KeyValueEncoder<CompactSizeEncoder, VersionEncoder<'e>>;
/// Decoder for the version value (PSBT_GLOBAL_VERSION).
pub(crate) type VersionValueDecoder = ValueDecoder<Version>;
/// Iterator yielding xpub key-value encoders (PSBT_GLOBAL_XPUB).
pub(crate) type XpubKeyValueIter<'e> =
    KeyValueIter<btree_map::Iter<'e, Xpub, KeySource>, PSBT_GLOBAL_XPUB>;
/// Encoder for the fallback locktime key-value pair (PSBT_GLOBAL_FALLBACK_LOCKTIME).
pub(crate) type FallbackLockTimePair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <absolute::LockTime as PsbtEncode>::Encoder<'e>>;
/// Decoder for the fallback locktime value (PSBT_GLOBAL_FALLBACK_LOCKTIME).
pub(crate) type FallbackLockTimeValueDecoder = ValueDecoder<absolute::LockTime>;
/// Encoder for the transaction version key-value pair (PSBT_GLOBAL_TX_VERSION).
pub(crate) type TxVersionPair<'e> =
    KeyValueEncoder<CompactSizeEncoder, <bitcoin::transaction::Version as PsbtEncode>::Encoder<'e>>;
/// Decoder for the transaction version value (PSBT_GLOBAL_TX_VERSION).
pub(crate) type TxVersionValueDecoder = ValueDecoder<bitcoin::transaction::Version>;
/// Iterator yielding ECDH share key-value encoders (PSBT_GLOBAL_SP_ECDH_SHARE).
#[cfg(feature = "silent-payments")]
pub(crate) type EcdhKeyValueIter<'e> = KeyValueIter<
    btree_map::Iter<'e, CompressedPublicKey, CompressedPublicKey>,
    PSBT_GLOBAL_SP_ECDH_SHARE,
>;
/// Iterator yielding DLEQ proof key-value encoders (PSBT_GLOBAL_SP_DLEQ).
#[cfg(feature = "silent-payments")]
pub(crate) type DleqKeyValueIter<'e> =
    KeyValueIter<btree_map::Iter<'e, CompressedPublicKey, DleqProof>, PSBT_GLOBAL_SP_DLEQ>;

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::str::FromStr;

    use super::*;
    use crate::encoding::encode_to_vec;

    fn sample_xpub() -> Xpub {
        Xpub::from_str(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        )
        .unwrap()
    }

    // Asserts the encoder round-trips
    fn check_global(global: &Global) {
        let encoded = encode_to_vec(global);
        assert_eq!(encoded.last(), Some(&PSBT_SEPARATOR), "global map must end with separator");

        let mut slice: &[u8] = &encoded;
        let mut decoder = GlobalDecoder::default();
        decoder.push_bytes(&mut slice).unwrap();
        let decoded = decoder.end().unwrap();
        assert_eq!(decoded, global.clone());
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
            ProprietaryKey { prefix: b"test".to_vec(), subtype: 0x42, key: vec![1, 2, 3] },
            vec![0xde, 0xad],
        );
        global.unknowns.insert(Key { type_value: 0x51, key: vec![0xaa, 0xbb] }, vec![0xcc, 0xdd]);

        check_global(&global);
    }

    #[test]
    #[cfg(feature = "silent-payments")]
    fn encode_silent_payments() {
        use core::str::FromStr;

        use crate::silent_payments::DleqProof;

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
        // ValueDecoder wraps a decoder with non-trivial read_limit.
        assert!(ValueDecoder::<Count>::default().read_limit() > 1);
        assert!(FlagsValueDecoder::default().read_limit() > 1);
        assert!(CountValueDecoder::default().read_limit() > 1);
    }

    #[test]
    fn excluded_key_type_is_rejected() {
        // PSBT_GLOBAL_UNSIGNED_TX (0x00) should not be accepted as a valid global key.
        let key = Key { type_value: 0x00, key: vec![] };
        let err = DecoderStage::from_key(key).unwrap_err();
        match err {
            GlobalDecodeError::KeyDecode(KeyDecodeError::ExcludedKey { key_type_value: v }) => {
                assert_eq!(v, 0x00)
            }
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
            matches!(res, Err(GlobalDecodeError::Xpub(_))),
            "expected Xpub error for xpub value too short, got {:?}",
            res,
        );
    }
}
