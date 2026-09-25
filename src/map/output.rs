// SPDX-License-Identifier: CC0-1.0

use alloc::collections::{btree_map, BTreeMap};
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::KeySource;
use bitcoin::key::{PublicKey, XOnlyPublicKey};
use bitcoin::taproot::{TapLeafHash, TapTree};
use bitcoin::{Amount, ScriptBuf, TxOut};
use bitcoin_consensus_encoding::{
    ByteVecDecoder, CompactSizeEncoder, Decoder, DecoderStatus, Encoder, EncoderStatus,
    ExactVecDecoderWith, IterEncoder,
};

use crate::consts::{
    PSBT_OUT_AMOUNT, PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_PROPRIETARY, PSBT_OUT_REDEEM_SCRIPT,
    PSBT_OUT_SCRIPT, PSBT_OUT_TAP_BIP32_DERIVATION, PSBT_OUT_TAP_INTERNAL_KEY, PSBT_OUT_TAP_TREE,
    PSBT_OUT_WITNESS_SCRIPT,
};
#[cfg(feature = "silent-payments")]
use crate::consts::{PSBT_OUT_SP_V0_INFO, PSBT_OUT_SP_V0_LABEL};
use crate::encoding::delegates::AmountPair;
use crate::encoding::native::{
    OutBip32DerivationIter, OutTapKeyOriginIter, ScriptPair, SeparatorEncoder, TapInternalKeyPair,
    TapTreePair,
};
#[cfg(feature = "silent-payments")]
use crate::encoding::native::{SpV0InfoPair, SpV0LabelPair};
use crate::encoding::{KeyValueEncoder, PsbtEncode};
use crate::error::write_err;
use crate::map::Map;
use crate::raw::{ProprietaryKeyValueIter, UnknownKeyValueIter};
use crate::serialize::Serialize;
use crate::{raw, serialize};

/// A key-value map for an output of the corresponding index in the unsigned
/// transaction.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    /// The output's amount (serialized as satoshis).
    pub amount: Amount,

    /// The script for this output, also known as the scriptPubKey.
    pub script_pubkey: ScriptBuf,

    /// The redeem script for this output.
    pub redeem_script: Option<ScriptBuf>,
    /// The witness script for this output.
    pub witness_script: Option<ScriptBuf>,
    /// A map from public keys needed to spend this output to their
    /// corresponding master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivations: BTreeMap<PublicKey, KeySource>,
    /// The internal pubkey.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot Output tree.
    pub tap_tree: Option<TapTree>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,

    /// BIP-375: Silent payment v0 address info (66 bytes: scan_key || spend_key).
    #[cfg(feature = "silent-payments")]
    pub sp_v0_info: Option<Vec<u8>>,

    /// BIP-375: Silent payment v0 label (4-byte little-endian u32).
    #[cfg(feature = "silent-payments")]
    pub sp_v0_label: Option<u32>,

    /// Proprietary key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this output.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

impl Output {
    /// Creates a new [`Output`] using `utxo`.
    pub fn new(utxo: TxOut) -> Self {
        Self {
            amount: utxo.value,
            script_pubkey: utxo.script_pubkey,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: BTreeMap::new(),
            tap_internal_key: None,
            tap_tree: None,
            tap_key_origins: BTreeMap::new(),
            #[cfg(feature = "silent-payments")]
            sp_v0_info: None,
            #[cfg(feature = "silent-payments")]
            sp_v0_label: None,
            proprietaries: BTreeMap::new(),
            unknowns: BTreeMap::new(),
        }
    }

    /// Returns all key-value pairs for this output map in serialization order.
    pub fn pairs(&self) -> Vec<raw::Pair> { Map::get_pairs(self) }

    /// Creates the [`TxOut`] associated with this `Output`.
    pub(crate) fn tx_out(&self) -> TxOut {
        TxOut { value: self.amount, script_pubkey: self.script_pubkey.clone() }
    }

    /// Checks this output against the BIP-370 and BIP-375 rules for an output map.
    ///
    /// BIP-370 requires `PSBT_OUT_SCRIPT`. BIP-375 relaxes that for a silent payment
    /// output whose script has not been derived yet, where `PSBT_OUT_SP_V0_INFO` stands
    /// in for it, and requires the info whenever a label is present.
    ///
    /// This is the single definition of that rule. Decoding applies it to every output it
    /// parses, and the Constructor role applies it to every output it is handed.
    pub fn validate(&self) -> Result<(), ValidationError> {
        #[cfg(not(feature = "silent-payments"))]
        if self.script_pubkey.is_empty() {
            return Err(ValidationError::MissingScriptPubkey);
        }

        #[cfg(feature = "silent-payments")]
        if self.script_pubkey.is_empty() && self.sp_v0_info.is_none() {
            return Err(ValidationError::MissingScriptPubkey);
        }

        #[cfg(feature = "silent-payments")]
        if self.sp_v0_label.is_some() && self.sp_v0_info.is_none() {
            return Err(ValidationError::LabelWithoutInfo);
        }

        Ok(())
    }

    /// Combines this [`Output`] with `other` `Output` (as described by BIP 174).
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        if self.amount != other.amount {
            return Err(CombineError::AmountMismatch { this: self.amount, that: other.amount });
        }

        if self.script_pubkey != other.script_pubkey {
            return Err(CombineError::ScriptPubkeyMismatch {
                this: self.script_pubkey.clone(),
                that: other.script_pubkey,
            });
        }

        v2_combine_option!(redeem_script, self, other);
        v2_combine_option!(witness_script, self, other);
        v2_combine_map!(bip32_derivations, self, other);
        v2_combine_option!(tap_internal_key, self, other);
        v2_combine_option!(tap_tree, self, other);
        v2_combine_map!(tap_key_origins, self, other);
        #[cfg(feature = "silent-payments")]
        v2_combine_option!(sp_v0_info, self, other);
        #[cfg(feature = "silent-payments")]
        v2_combine_option!(sp_v0_label, self, other);
        v2_combine_map!(proprietaries, self, other);
        v2_combine_map!(unknowns, self, other);

        Ok(())
    }
}

/// Push-based decoder for a single PSBT output map.
#[derive(Debug)]
pub struct OutputDecoder {
    stage: DecoderStage,
    amount: Option<Amount>,
    script_pubkey: Option<ScriptBuf>,
    redeem_script: Option<ScriptBuf>,
    witness_script: Option<ScriptBuf>,
    bip32_derivations: BTreeMap<PublicKey, KeySource>,
    tap_internal_key: Option<XOnlyPublicKey>,
    tap_tree: Option<TapTree>,
    tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    #[cfg(feature = "silent-payments")]
    sp_v0_info: Option<Vec<u8>>,
    #[cfg(feature = "silent-payments")]
    sp_v0_label: Option<u32>,
    proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum DecoderStage {
    DecodingSeparator,
    DecodingKey(raw::KeyDecoder),
    DecodingValue { key: raw::Key, decoder: ByteVecDecoder },
    Done(Output),
    Errored,
}

impl DecoderStage {
    fn from_key(key: raw::Key) -> Result<Self, DecodeError> {
        Ok(Self::DecodingValue { key, decoder: ByteVecDecoder::new() })
    }
}

impl Default for OutputDecoder {
    fn default() -> Self {
        Self {
            stage: DecoderStage::DecodingSeparator,
            amount: None,
            script_pubkey: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: BTreeMap::default(),
            tap_internal_key: None,
            tap_tree: None,
            tap_key_origins: BTreeMap::default(),
            #[cfg(feature = "silent-payments")]
            sp_v0_info: None,
            #[cfg(feature = "silent-payments")]
            sp_v0_label: None,
            proprietaries: BTreeMap::default(),
            unknowns: BTreeMap::default(),
        }
    }
}

impl crate::encoding::PsbtDecode for Output {
    type Decoder = OutputDecoder;
}

impl Decoder for OutputDecoder {
    type Output = Output;
    type Error = DecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        use crate::consts::PSBT_SEPARATOR;

        if matches!(&self.stage, DecoderStage::Done(_)) {
            return Ok(DecoderStatus::Ready);
        }

        loop {
            if matches!(&self.stage, DecoderStage::DecodingSeparator) {
                match bytes.split_first() {
                    Some((&PSBT_SEPARATOR, rest)) => {
                        *bytes = rest;
                        let amount = self.amount.take().ok_or(DecodeError::MissingValue)?;
                        let script_pubkey = self.script_pubkey.take().unwrap_or_default();
                        self.stage = DecoderStage::Done(Output {
                            amount,
                            script_pubkey,
                            redeem_script: self.redeem_script.take(),
                            witness_script: self.witness_script.take(),
                            bip32_derivations: core::mem::take(&mut self.bip32_derivations),
                            tap_internal_key: self.tap_internal_key.take(),
                            tap_tree: self.tap_tree.take(),
                            tap_key_origins: core::mem::take(&mut self.tap_key_origins),
                            #[cfg(feature = "silent-payments")]
                            sp_v0_info: self.sp_v0_info.take(),
                            #[cfg(feature = "silent-payments")]
                            sp_v0_label: self.sp_v0_label.take(),
                            proprietaries: core::mem::take(&mut self.proprietaries),
                            unknowns: core::mem::take(&mut self.unknowns),
                        });
                        return Ok(DecoderStatus::Ready);
                    }
                    Some((_, _)) => {
                        self.stage = DecoderStage::DecodingKey(raw::KeyDecoder::default());
                    }
                    None => return Ok(DecoderStatus::NeedsMore),
                }
            }

            let status = match &mut self.stage {
                DecoderStage::DecodingKey(d) =>
                    d.push_bytes(bytes).map_err(DecodeError::KeyDecode)?,
                DecoderStage::DecodingValue { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|_| {
                        DecodeError::DeserPair(serialize::Error::ConsensusEncoding(
                            bitcoin::consensus::encode::Error::ParseFailed("value decode"),
                        ))
                    })?,
                DecoderStage::Done(_) => return Ok(DecoderStatus::Ready),
                DecoderStage::DecodingSeparator | DecoderStage::Errored =>
                    panic!("push_bytes in unexpected stage"),
            };

            if status.needs_more() {
                return Ok(DecoderStatus::NeedsMore);
            }

            let old = core::mem::replace(&mut self.stage, DecoderStage::Errored);
            match old {
                DecoderStage::DecodingKey(decoder) => {
                    let key = decoder.end().map_err(DecodeError::KeyDecode)?;
                    self.stage = DecoderStage::from_key(key)?;
                }
                DecoderStage::DecodingValue { key, decoder } => {
                    let value = decoder.end().map_err(|_| {
                        DecodeError::DeserPair(serialize::Error::ConsensusEncoding(
                            bitcoin::consensus::encode::Error::ParseFailed("value decode"),
                        ))
                    })?;
                    self.insert_value(key, value)?;
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::Done(output) => {
                    self.stage = DecoderStage::Done(output);
                    return Ok(DecoderStatus::Ready);
                }
                DecoderStage::Errored => unreachable!(),
                DecoderStage::DecodingSeparator => unreachable!(),
            }
        }
    }

    fn end(self) -> Result<Output, Self::Error> {
        match self.stage {
            DecoderStage::Done(output) => {
                output.validate()?;
                Ok(output)
            }
            _ => Err(DecodeError::DeserPair(serialize::Error::ConsensusEncoding(
                bitcoin::consensus::encode::Error::ParseFailed("unexpected end"),
            ))),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            DecoderStage::DecodingSeparator => 1,
            DecoderStage::DecodingKey(d) => d.read_limit(),
            DecoderStage::DecodingValue { decoder, .. } => decoder.read_limit(),
            DecoderStage::Done(_) | DecoderStage::Errored => 0,
        }
    }
}

impl OutputDecoder {
    fn insert_value(&mut self, key: raw::Key, value: Vec<u8>) -> Result<(), DecodeError> {
        use crate::serialize::Deserialize;
        match key.type_value {
            PSBT_OUT_AMOUNT => {
                if self.amount.is_some() {
                    return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                }
                self.amount =
                    Some(Deserialize::deserialize(&value).map_err(DecodeError::DeserPair)?);
            }
            PSBT_OUT_SCRIPT => {
                if self.script_pubkey.is_some() {
                    return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                }
                self.script_pubkey =
                    Some(Deserialize::deserialize(&value).map_err(DecodeError::DeserPair)?);
            }
            PSBT_OUT_REDEEM_SCRIPT => {
                if self.redeem_script.is_some() {
                    return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                }
                self.redeem_script =
                    Some(Deserialize::deserialize(&value).map_err(DecodeError::DeserPair)?);
            }
            PSBT_OUT_WITNESS_SCRIPT => {
                if self.witness_script.is_some() {
                    return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                }
                self.witness_script =
                    Some(Deserialize::deserialize(&value).map_err(DecodeError::DeserPair)?);
            }
            PSBT_OUT_BIP32_DERIVATION => {
                let pk: PublicKey =
                    Deserialize::deserialize(&key.key).map_err(DecodeError::DeserPair)?;
                let ks: KeySource =
                    Deserialize::deserialize(&value).map_err(DecodeError::DeserPair)?;
                match self.bip32_derivations.entry(pk) {
                    btree_map::Entry::Vacant(e) => {
                        e.insert(ks);
                    }
                    btree_map::Entry::Occupied(_) =>
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                }
            }
            PSBT_OUT_PROPRIETARY => {
                let pk =
                    raw::ProprietaryKey::try_from(key.clone()).map_err(InsertPairError::Deser)?;
                match self.proprietaries.entry(pk) {
                    btree_map::Entry::Vacant(e) => {
                        e.insert(value);
                    }
                    btree_map::Entry::Occupied(_) =>
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                }
            }
            PSBT_OUT_TAP_INTERNAL_KEY => {
                if self.tap_internal_key.is_some() {
                    return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                }
                self.tap_internal_key =
                    Some(Deserialize::deserialize(&value).map_err(DecodeError::DeserPair)?);
            }
            PSBT_OUT_TAP_TREE => {
                if self.tap_tree.is_some() {
                    return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                }
                self.tap_tree =
                    Some(Deserialize::deserialize(&value).map_err(DecodeError::DeserPair)?);
            }
            PSBT_OUT_TAP_BIP32_DERIVATION => {
                let xonly: XOnlyPublicKey =
                    Deserialize::deserialize(&key.key).map_err(DecodeError::DeserPair)?;
                let (leaf_hashes, ks): (Vec<TapLeafHash>, KeySource) =
                    Deserialize::deserialize(&value).map_err(DecodeError::DeserPair)?;
                match self.tap_key_origins.entry(xonly) {
                    btree_map::Entry::Vacant(e) => {
                        e.insert((leaf_hashes, ks));
                    }
                    btree_map::Entry::Occupied(_) =>
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                }
            }
            #[cfg(feature = "silent-payments")]
            PSBT_OUT_SP_V0_INFO => {
                if self.sp_v0_info.is_some() {
                    return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                }
                if !key.key.is_empty() {
                    return Err(DecodeError::InsertPair(InsertPairError::InvalidKeyDataNotEmpty(
                        key,
                    )));
                }
                if value.len() != 66 {
                    return Err(DecodeError::InsertPair(InsertPairError::ValueWrongLength(
                        value.len(),
                        66,
                    )));
                }
                self.sp_v0_info = Some(value);
            }
            #[cfg(feature = "silent-payments")]
            PSBT_OUT_SP_V0_LABEL => {
                if self.sp_v0_label.is_some() {
                    return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                }
                if !key.key.is_empty() {
                    return Err(DecodeError::InsertPair(InsertPairError::InvalidKeyDataNotEmpty(
                        key,
                    )));
                }
                if value.len() != 4 {
                    return Err(DecodeError::InsertPair(InsertPairError::ValueWrongLength(
                        value.len(),
                        4,
                    )));
                }
                let label = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                self.sp_v0_label = Some(label);
            }
            _ => match self.unknowns.entry(key) {
                btree_map::Entry::Vacant(e) => {
                    e.insert(value);
                }
                btree_map::Entry::Occupied(k) =>
                    return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(
                        k.key().clone(),
                    ))),
            },
        }
        Ok(())
    }
}

/// Decodes a sequence of output maps, one per output.
pub(crate) type OutputsDecoder = ExactVecDecoderWith<OutputDecoder>;

/// State of the output map encoder, one key-value pair per variant.
enum EncoderState<'e> {
    Amount(AmountPair<'e>),
    Script(ScriptPair<'e>),
    RedeemScript(ScriptPair<'e>),
    WitnessScript(ScriptPair<'e>),
    Bip32Derivations(IterEncoder<OutBip32DerivationIter<'e>>),
    TapInternalKey(TapInternalKeyPair<'e>),
    TapTree(TapTreePair<'e>),
    TapKeyOrigins(IterEncoder<OutTapKeyOriginIter<'e>>),
    #[cfg(feature = "silent-payments")]
    SpV0Info(SpV0InfoPair<'e>),
    #[cfg(feature = "silent-payments")]
    SpV0Label(SpV0LabelPair<'e>),
    Proprietaries(IterEncoder<ProprietaryKeyValueIter<'e>>),
    Unknowns(IterEncoder<UnknownKeyValueIter<'e>>),
    Separator(SeparatorEncoder),
}

/// Encoder for a PSBT output map.
///
/// Walks the map's fields in canonical order without materializing raw `Pair` buffers.
pub struct OutputMapEncoder<'e> {
    output: &'e Output,
    state: EncoderState<'e>,
}

impl<'e> OutputMapEncoder<'e> {
    fn new(output: &'e Output) -> Self {
        let state = EncoderState::Amount(KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_OUT_AMOUNT),
            output.amount.psbt_encoder(),
        ));
        Self { output, state }
    }

    /// Constructs the next state in field order after the current one, if any.
    fn next_state(&self) -> Option<EncoderState<'e>> {
        match &self.state {
            EncoderState::Amount(_) => self.script_state(),
            EncoderState::Script(_) => self.redeem_script_state(),
            EncoderState::RedeemScript(_) => self.witness_script_state(),
            EncoderState::WitnessScript(_) => Some(self.bip32_derivations_state()),
            EncoderState::Bip32Derivations(_) => self.tap_internal_key_state(),
            EncoderState::TapInternalKey(_) => self.tap_tree_state(),
            EncoderState::TapTree(_) => Some(self.tap_key_origins_state()),
            EncoderState::TapKeyOrigins(_) => self.after_tap_key_origins(),
            #[cfg(feature = "silent-payments")]
            EncoderState::SpV0Info(_) => self.sp_v0_label_state(),
            #[cfg(feature = "silent-payments")]
            EncoderState::SpV0Label(_) => Some(self.proprietaries_state()),
            EncoderState::Proprietaries(_) => Some(self.unknowns_state()),
            EncoderState::Unknowns(_) => Some(EncoderState::Separator(SeparatorEncoder::new())),
            EncoderState::Separator(_) => None,
        }
    }

    /// The first state after `tap_key_origins`, cfg-gated on silent payments.
    fn after_tap_key_origins(&self) -> Option<EncoderState<'e>> {
        #[cfg(feature = "silent-payments")]
        {
            self.sp_v0_info_state()
        }
        #[cfg(not(feature = "silent-payments"))]
        {
            Some(self.proprietaries_state())
        }
    }

    fn script_state(&self) -> Option<EncoderState<'e>> {
        // BIP-375 represents an underived silent payment output by omitting the script, so
        // encoding one has to leave the field out rather than write it empty.
        #[cfg(feature = "silent-payments")]
        let omit_script = self.output.sp_v0_info.is_some() && self.output.script_pubkey.is_empty();
        #[cfg(not(feature = "silent-payments"))]
        let omit_script = false;

        if omit_script {
            return self.redeem_script_state();
        }
        Some(EncoderState::Script(KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_OUT_SCRIPT),
            self.output.script_pubkey.psbt_encoder(),
        )))
    }

    fn redeem_script_state(&self) -> Option<EncoderState<'e>> {
        match &self.output.redeem_script {
            Some(script) => Some(EncoderState::RedeemScript(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_REDEEM_SCRIPT),
                script.psbt_encoder(),
            ))),
            None => self.witness_script_state(),
        }
    }

    fn witness_script_state(&self) -> Option<EncoderState<'e>> {
        match &self.output.witness_script {
            Some(script) => Some(EncoderState::WitnessScript(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_WITNESS_SCRIPT),
                script.psbt_encoder(),
            ))),
            None => Some(self.bip32_derivations_state()),
        }
    }

    fn bip32_derivations_state(&self) -> EncoderState<'e> {
        EncoderState::Bip32Derivations(IterEncoder::new(OutBip32DerivationIter::new(
            self.output.bip32_derivations.iter(),
        )))
    }

    fn tap_internal_key_state(&self) -> Option<EncoderState<'e>> {
        match &self.output.tap_internal_key {
            Some(key) => Some(EncoderState::TapInternalKey(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_TAP_INTERNAL_KEY),
                key.psbt_encoder(),
            ))),
            None => self.tap_tree_state(),
        }
    }

    fn tap_tree_state(&self) -> Option<EncoderState<'e>> {
        match &self.output.tap_tree {
            Some(tree) => Some(EncoderState::TapTree(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_TAP_TREE),
                tree.psbt_encoder(),
            ))),
            None => Some(self.tap_key_origins_state()),
        }
    }

    fn tap_key_origins_state(&self) -> EncoderState<'e> {
        EncoderState::TapKeyOrigins(IterEncoder::new(OutTapKeyOriginIter::new(
            self.output.tap_key_origins.iter(),
        )))
    }

    #[cfg(feature = "silent-payments")]
    fn sp_v0_info_state(&self) -> Option<EncoderState<'e>> {
        // Importing inside method to avoid linting issues because feature is disabled
        use bitcoin_consensus_encoding::BytesEncoder;

        match &self.output.sp_v0_info {
            Some(info) => Some(EncoderState::SpV0Info(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_SP_V0_INFO),
                BytesEncoder::without_length_prefix(info.as_slice()),
            ))),
            None => self.sp_v0_label_state(),
        }
    }

    #[cfg(feature = "silent-payments")]
    fn sp_v0_label_state(&self) -> Option<EncoderState<'e>> {
        use bitcoin_consensus_encoding::ArrayEncoder;

        match &self.output.sp_v0_label {
            Some(label) => Some(EncoderState::SpV0Label(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_SP_V0_LABEL),
                ArrayEncoder::without_length_prefix(label.to_le_bytes()),
            ))),
            None => Some(self.proprietaries_state()),
        }
    }

    fn proprietaries_state(&self) -> EncoderState<'e> {
        EncoderState::Proprietaries(IterEncoder::new(ProprietaryKeyValueIter(
            self.output.proprietaries.iter(),
        )))
    }

    fn unknowns_state(&self) -> EncoderState<'e> {
        EncoderState::Unknowns(IterEncoder::new(UnknownKeyValueIter(self.output.unknowns.iter())))
    }
}

impl Encoder for OutputMapEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match &self.state {
            EncoderState::Amount(e) => e.current_chunk(),
            EncoderState::Script(e) => e.current_chunk(),
            EncoderState::RedeemScript(e) => e.current_chunk(),
            EncoderState::WitnessScript(e) => e.current_chunk(),
            EncoderState::Bip32Derivations(e) => e.current_chunk(),
            EncoderState::TapInternalKey(e) => e.current_chunk(),
            EncoderState::TapTree(e) => e.current_chunk(),
            EncoderState::TapKeyOrigins(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            EncoderState::SpV0Info(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            EncoderState::SpV0Label(e) => e.current_chunk(),
            EncoderState::Proprietaries(e) => e.current_chunk(),
            EncoderState::Unknowns(e) => e.current_chunk(),
            EncoderState::Separator(e) => e.current_chunk(),
        }
    }

    fn advance(&mut self) -> EncoderStatus {
        let finished = match &mut self.state {
            EncoderState::Amount(e) => e.advance().has_finished(),
            EncoderState::Script(e) => e.advance().has_finished(),
            EncoderState::RedeemScript(e) => e.advance().has_finished(),
            EncoderState::WitnessScript(e) => e.advance().has_finished(),
            EncoderState::Bip32Derivations(e) => e.advance().has_finished(),
            EncoderState::TapInternalKey(e) => e.advance().has_finished(),
            EncoderState::TapTree(e) => e.advance().has_finished(),
            EncoderState::TapKeyOrigins(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            EncoderState::SpV0Info(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            EncoderState::SpV0Label(e) => e.advance().has_finished(),
            EncoderState::Proprietaries(e) => e.advance().has_finished(),
            EncoderState::Unknowns(e) => e.advance().has_finished(),
            EncoderState::Separator(e) => e.advance().has_finished(),
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

impl PsbtEncode for Output {
    type Encoder<'e> = OutputMapEncoder<'e>;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        // `<output-map> := <keypair>* 0x00`
        OutputMapEncoder::new(self)
    }
}

impl Map for Output {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_OUT_AMOUNT, key: vec![] },
            value: self.amount.serialize(),
        });

        // BIP-375 represents an underived silent payment output by omitting the script, so
        // encoding one has to leave the field out rather than write it empty. Whether that
        // state is legal in the first place is decided by `validate`, not here.
        #[cfg(feature = "silent-payments")]
        let omit_script = self.sp_v0_info.is_some() && self.script_pubkey.is_empty();
        #[cfg(not(feature = "silent-payments"))]
        let omit_script = false;

        if !omit_script {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_OUT_SCRIPT, key: vec![] },
                value: self.script_pubkey.serialize(),
            });
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_OUT_REDEEM_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_OUT_WITNESS_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivations, PSBT_OUT_BIP32_DERIVATION)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_OUT_TAP_INTERNAL_KEY)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_tree, PSBT_OUT_TAP_TREE)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_OUT_TAP_BIP32_DERIVATION)
        }

        #[cfg(feature = "silent-payments")]
        if let Some(sp_info) = &self.sp_v0_info {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_OUT_SP_V0_INFO, key: vec![] },
                value: sp_info.clone(),
            });
        }

        #[cfg(feature = "silent-payments")]
        if let Some(label) = self.sp_v0_label {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_OUT_SP_V0_LABEL, key: vec![] },
                value: label.to_le_bytes().to_vec(),
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

/// Enables building an [`Output`] using the standard builder pattern.
// This is only provided for uniformity with the `InputBuilder`.
pub struct OutputBuilder(Output);

impl OutputBuilder {
    /// Creates a new builder that can be used to build an [`Output`] around `utxo`.
    pub fn new(utxo: TxOut) -> Self { Self(Output::new(utxo)) }

    /// Build the [`Output`].
    pub fn build(self) -> Output { self.0 }
}

/// An error while checking an [`Output`] against the BIP-370 and BIP-375 output rules.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// Output is missing a script pubkey.
    MissingScriptPubkey,
    /// Output has a `sp_v0_label` without a `sp_v0_info`.
    LabelWithoutInfo,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingScriptPubkey => write!(f, "output is missing a script pubkey"),
            Self::LabelWithoutInfo => write!(f, "output has a sp_v0_label without a sp_v0_info"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {}

/// An error while decoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Error inserting a key-value pair.
    InsertPair(InsertPairError),
    /// Error deserializing a pair.
    DeserPair(serialize::Error),
    /// Error decoding a raw PSBT key.
    KeyDecode(raw::KeyDecodeError),
    /// Encoded output is missing a value.
    MissingValue,
    /// Encoded output is missing a script pubkey.
    MissingScriptPubkey,
    /// Encoded output is missing a sp_v0_info.
    LabelWithoutInfo,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsertPair(ref e) => write_err!(f, "error inserting a pair"; e),
            Self::DeserPair(ref e) => write_err!(f, "error deserializing a pair"; e),
            Self::KeyDecode(ref e) => write_err!(f, "error decoding key"; e),
            Self::MissingValue => write!(f, "encoded output is missing a value"),
            Self::MissingScriptPubkey => write!(f, "encoded output is missing a script pubkey"),
            Self::LabelWithoutInfo => write!(f, "output has a sp_v0_label without a sp_v0_info"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InsertPair(ref e) => Some(e),
            Self::DeserPair(ref e) => Some(e),
            Self::KeyDecode(ref e) => Some(e),
            Self::MissingValue | Self::MissingScriptPubkey | Self::LabelWithoutInfo => None,
        }
    }
}

impl From<InsertPairError> for DecodeError {
    fn from(e: InsertPairError) -> Self { Self::InsertPair(e) }
}

impl From<ValidationError> for DecodeError {
    fn from(e: ValidationError) -> Self {
        match e {
            ValidationError::MissingScriptPubkey => Self::MissingScriptPubkey,
            ValidationError::LabelWithoutInfo => Self::LabelWithoutInfo,
        }
    }
}

/// Error inserting a key-value pair.
#[derive(Debug)]
pub enum InsertPairError {
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(raw::Key),
    /// Error deserializing raw value.
    Deser(serialize::Error),
    /// Key should contain data.
    InvalidKeyDataEmpty(raw::Key),
    /// Key should not contain data.
    InvalidKeyDataNotEmpty(raw::Key),
    /// Value was not the correct length (got, expected).
    ValueWrongLength(usize, usize),
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Self::Deser(ref e) => write_err!(f, "error deserializing raw value"; e),
            Self::InvalidKeyDataEmpty(ref key) => write!(f, "key should contain data: {}", key),
            Self::InvalidKeyDataNotEmpty(ref key) =>
                write!(f, "key should not contain data: {}", key),
            Self::ValueWrongLength(got, expected) => {
                write!(f, "value wrong length (got: {}, expected: {})", got, expected)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Deser(ref e) => Some(e),
            Self::DuplicateKey(_)
            | Self::InvalidKeyDataEmpty(_)
            | Self::InvalidKeyDataNotEmpty(_)
            | Self::ValueWrongLength(..) => None,
        }
    }
}

impl From<serialize::Error> for InsertPairError {
    fn from(e: serialize::Error) -> Self { Self::Deser(e) }
}

/// Error combining two output maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// The amounts are not the same.
    AmountMismatch {
        /// Attempted to combine a PSBT with `this` previous txid.
        this: Amount,
        /// Into a PSBT with `that` previous txid.
        that: Amount,
    },
    /// The script_pubkeys are not the same.
    ScriptPubkeyMismatch {
        /// Attempted to combine a PSBT with `this` script_pubkey.
        this: ScriptBuf,
        /// Into a PSBT with `that` script_pubkey.
        that: ScriptBuf,
    },
}

impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmountMismatch { ref this, ref that } => {
                write!(f, "combine two PSBTs with different amounts: {} {}", this, that)
            }
            Self::ScriptPubkeyMismatch { ref this, ref that } => {
                write!(f, "combine two PSBTs with different script_pubkeys: {:x} {:x}", this, that)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AmountMismatch { .. } | Self::ScriptPubkeyMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {

    use super::*;

    fn tx_out() -> TxOut {
        // Arbitrary script, may not even be a valid scriptPubkey.
        let script = ScriptBuf::from_hex("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
            .expect("failed to parse script form hex");
        let value = Amount::from_sat(123_456_789);
        TxOut { value, script_pubkey: script }
    }

    #[test]
    fn serialize_roundtrip() {
        let output = Output::new(tx_out());

        let ser = output.serialize_map();

        let decoded = crate::encoding::decode_from_slice::<Output>(&ser).expect("failed to decode");

        assert_eq!(decoded, output);
    }

    #[test]
    fn pairs_matches_serialize_map() {
        let output = Output::new(tx_out());

        let mut from_pairs = Vec::new();
        for pair in output.pairs() {
            from_pairs.extend(pair.serialize());
        }
        from_pairs.push(crate::consts::PSBT_SEPARATOR);

        assert_eq!(from_pairs, output.serialize_map());
    }

    // Asserts the native pull-based encoder produces exactly `Map::serialize_map`'s bytes.
    #[test]
    fn encoder_matches_serialize_map() {
        let output = Output::new(tx_out());

        let encoded = crate::encoding::encode_to_vec(&output);
        assert_eq!(encoded, Map::serialize_map(&output));
    }

    #[test]
    fn encode_nonempty() {
        let output = Output::new(tx_out());
        let bytes = crate::encoding::encode_to_vec(&output);
        assert!(!bytes.is_empty());
        assert!(bytes.len() > 1, "map must have at least one keypair before separator");
        assert_eq!(
            bytes.last(),
            Some(&crate::consts::PSBT_SEPARATOR),
            "output map must end with separator"
        );
    }

    #[test]
    fn read_limit_lifecycle() {
        let output = Output::new(tx_out());
        let bytes = crate::encoding::encode_to_vec(&output);

        let mut decoder = OutputDecoder::default();
        assert_eq!(decoder.read_limit(), 1, "fresh decoder should request bytes");

        let mut remaining = &bytes[..];
        assert!(decoder.push_bytes(&mut remaining).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0, "completed decoder should request no bytes");
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn silent_payment_output_script_pair() {
        let ordinary = Output::new(tx_out());
        let has_script = |output: &Output| {
            output.pairs().iter().any(|pair| pair.key.type_value == PSBT_OUT_SCRIPT)
        };
        // Asserts the pull-based encoder applies the same omit rule as `pairs`.
        let encoder_matches_pairs = |output: &Output| {
            assert_eq!(crate::encoding::encode_to_vec(output), output.serialize_map());
        };
        assert!(has_script(&ordinary));
        encoder_matches_pairs(&ordinary);

        let mut derived_sp = ordinary;
        derived_sp.sp_v0_info = Some(vec![0; 66]);
        assert!(has_script(&derived_sp));
        encoder_matches_pairs(&derived_sp);

        let mut underived_sp = derived_sp;
        underived_sp.script_pubkey = ScriptBuf::new();
        assert!(!has_script(&underived_sp));
        encoder_matches_pairs(&underived_sp);
    }

    #[test]
    fn roundtrip_all_output_fields() {
        use bitcoin::bip32::{DerivationPath, Fingerprint};
        use bitcoin::hashes::Hash as _;
        use bitcoin::secp256k1;
        use bitcoin::taproot::TaprootBuilder;

        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[4u8; 32]).unwrap();
        let secp_pk = sk.public_key(&secp);
        let pk = PublicKey::new(secp_pk);
        let (xonly, _parity) = secp_pk.x_only_public_key();

        let mut output = Output::new(TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]),
        });

        output.redeem_script = Some(ScriptBuf::from_bytes(vec![0x51]));
        output.witness_script = Some(ScriptBuf::from_bytes(vec![0x52]));

        let ks: KeySource = (Fingerprint::from([6u8; 4]), DerivationPath::default());
        output.bip32_derivations.insert(pk, ks.clone());

        output.proprietaries.insert(
            raw::ProprietaryKey::<raw::ProprietaryType> {
                prefix: vec![0xde, 0xad],
                subtype: 42,
                key: vec![0xbe, 0xef],
            },
            vec![0x01, 0x02],
        );

        output.tap_internal_key = Some(xonly);

        let mut builder = TaprootBuilder::new();
        builder = builder.add_leaf(0, ScriptBuf::from_bytes(vec![0x51])).unwrap();
        output.tap_tree = Some(TapTree::try_from(builder).unwrap());

        let leaf = TapLeafHash::from_byte_array([12u8; 32]);
        output.tap_key_origins.insert(xonly, (vec![leaf], ks));

        let encoded = crate::encoding::encode_to_vec(&output);
        let decoded = crate::encoding::decode_from_slice::<Output>(&encoded)
            .expect("roundtrip decode failed");
        assert_eq!(decoded, output);
    }
}
