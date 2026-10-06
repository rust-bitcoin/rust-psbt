// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 output map encoder and decoder.
//!
//! v0 outputs omit `amount` and `script_pubkey`, those come from the unsigned transaction.

use alloc::collections::{btree_map, BTreeMap};
use alloc::vec::Vec;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource};
use bitcoin::hashes::Hash;
use bitcoin::key::{PublicKey, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapTree, TaprootBuilder};
use bitcoin::{Amount, ScriptBuf};
use bitcoin_consensus_encoding::{
    ArrayDecoder, ByteVecDecoder, CompactSizeDecoder, CompactSizeEncoder, Decoder, Decoder2Error,
    DecoderStatus, Encoder, EncoderStatus, ExactVecDecoderWith, IterEncoder,
};

use super::super::{Key, KeyDecoder, ProprietaryKey, ProprietaryKeyValueIter, UnknownKeyValueIter};
use crate::consts::{
    PSBT_OUT_BIP32_DERIVATION, PSBT_OUT_PROPRIETARY, PSBT_OUT_REDEEM_SCRIPT,
    PSBT_OUT_TAP_BIP32_DERIVATION, PSBT_OUT_TAP_INTERNAL_KEY, PSBT_OUT_TAP_TREE,
    PSBT_OUT_WITNESS_SCRIPT, PSBT_SEPARATOR,
};
#[cfg(feature = "silent-payments")]
use crate::consts::{PSBT_OUT_SP_V0_INFO, PSBT_OUT_SP_V0_LABEL};
use crate::encoding::native::{
    OutBip32DerivationIter, OutTapKeyOriginIter, ScriptPair, SeparatorEncoder, TapInternalKeyPair,
    TapTreePair,
};
#[cfg(feature = "silent-payments")]
use crate::encoding::native::{SpV0InfoPair, SpV0LabelPair};
use crate::encoding::{KeyValueEncoder, PsbtEncode, ValueDecoder};
use crate::map::error::{OutputDecodeError, OutputInsertPairError, OutputValueDecodeError};
use crate::output::Output;
#[cfg(feature = "silent-payments")]
use crate::SpV0Info;

pub struct OutputMapEncoder<'e> {
    output: &'e Output,
    state: State<'e>,
}

enum State<'e> {
    WitnessScript(ScriptPair<'e>),
    Bip32Derivations(IterEncoder<OutBip32DerivationIter<'e>>),
    TapInternalKey(TapInternalKeyPair<'e>),
    TapTree(TapTreePair<'e>),
    TapKeyOrigins(IterEncoder<OutTapKeyOriginIter<'e>>),
    Proprietaries(IterEncoder<ProprietaryKeyValueIter<'e>>),
    Unknowns(IterEncoder<UnknownKeyValueIter<'e>>),
    #[cfg(feature = "silent-payments")]
    SpV0Info(SpV0InfoPair<'e>),
    #[cfg(feature = "silent-payments")]
    SpV0Label(SpV0LabelPair<'e>),
    Separator(SeparatorEncoder),
    Done,
}

impl<'e> OutputMapEncoder<'e> {
    pub(crate) fn new(output: &'e Output) -> Self {
        Self { output, state: Self::witness_script_or_next(output) }
    }

    fn next_state(&self) -> State<'e> {
        match &self.state {
            State::WitnessScript(_) => Self::bip32_or_next(self.output),
            State::Bip32Derivations(_) => Self::tap_internal_key_or_next(self.output),
            State::TapInternalKey(_) => Self::tap_tree_or_next(self.output),
            State::TapTree(_) => Self::tap_key_origins_or_next(self.output),
            State::TapKeyOrigins(_) => Self::proprietaries_or_next(self.output),
            State::Proprietaries(_) => Self::unknowns_or_next(self.output),
            State::Unknowns(_) => Self::sp_v0_info_or_next(self.output),
            #[cfg(feature = "silent-payments")]
            State::SpV0Info(_) => Self::sp_v0_label_or_next(self.output),
            #[cfg(feature = "silent-payments")]
            State::SpV0Label(_) => State::Separator(SeparatorEncoder::new()),
            State::Separator(_) => State::Done,
            State::Done => State::Done,
        }
    }

    fn witness_script_or_next(output: &'e Output) -> State<'e> {
        if let Some(ws) = &output.witness_script {
            State::WitnessScript(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_WITNESS_SCRIPT),
                ws.psbt_encoder(),
            ))
        } else {
            Self::bip32_or_next(output)
        }
    }

    fn bip32_or_next(o: &'e Output) -> State<'e> {
        if !o.bip32_derivations.is_empty() {
            State::Bip32Derivations(IterEncoder::new(OutBip32DerivationIter::new(
                o.bip32_derivations.iter(),
            )))
        } else {
            Self::tap_internal_key_or_next(o)
        }
    }

    fn tap_internal_key_or_next(o: &'e Output) -> State<'e> {
        if let Some(key) = o.tap_internal_key {
            State::TapInternalKey(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_TAP_INTERNAL_KEY),
                key.psbt_encoder(),
            ))
        } else {
            Self::tap_tree_or_next(o)
        }
    }

    fn tap_tree_or_next(o: &'e Output) -> State<'e> {
        if let Some(tree) = &o.tap_tree {
            State::TapTree(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_TAP_TREE),
                tree.psbt_encoder(),
            ))
        } else {
            Self::tap_key_origins_or_next(o)
        }
    }

    fn tap_key_origins_or_next(o: &'e Output) -> State<'e> {
        if !o.tap_key_origins.is_empty() {
            State::TapKeyOrigins(IterEncoder::new(OutTapKeyOriginIter::new(
                o.tap_key_origins.iter(),
            )))
        } else {
            Self::proprietaries_or_next(o)
        }
    }

    fn proprietaries_or_next(o: &'e Output) -> State<'e> {
        if !o.proprietaries.is_empty() {
            State::Proprietaries(IterEncoder::new(ProprietaryKeyValueIter(o.proprietaries.iter())))
        } else {
            Self::unknowns_or_next(o)
        }
    }

    fn unknowns_or_next(o: &'e Output) -> State<'e> {
        if !o.unknowns.is_empty() {
            return State::Unknowns(IterEncoder::new(UnknownKeyValueIter(o.unknowns.iter())));
        }
        Self::sp_v0_info_or_next(o)
    }

    fn sp_v0_info_or_next(_o: &'e Output) -> State<'e> {
        #[cfg(feature = "silent-payments")]
        {
            use crate::consts::PSBT_OUT_SP_V0_INFO;
            if let Some(ref info) = _o.sp_v0_info {
                return State::SpV0Info(KeyValueEncoder::from_sized_kv(
                    CompactSizeEncoder::new_u64(PSBT_OUT_SP_V0_INFO),
                    info.psbt_encoder(),
                ));
            }
            Self::sp_v0_label_or_next(_o)
        }
        #[cfg(not(feature = "silent-payments"))]
        State::Separator(SeparatorEncoder::new())
    }

    #[cfg(feature = "silent-payments")]
    fn sp_v0_label_or_next(o: &'e Output) -> State<'e> {
        use bitcoin_consensus_encoding::ArrayEncoder;

        if let Some(label) = o.sp_v0_label {
            return State::SpV0Label(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_SP_V0_LABEL),
                ArrayEncoder::without_length_prefix(label.to_le_bytes()),
            ));
        }
        State::Separator(SeparatorEncoder::new())
    }
}

impl Encoder for OutputMapEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match &self.state {
            State::WitnessScript(e) => e.current_chunk(),
            State::Bip32Derivations(e) => e.current_chunk(),
            State::TapInternalKey(e) => e.current_chunk(),
            State::TapTree(e) => e.current_chunk(),
            State::TapKeyOrigins(e) => e.current_chunk(),
            State::Proprietaries(e) => e.current_chunk(),
            State::Unknowns(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::SpV0Info(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::SpV0Label(e) => e.current_chunk(),
            State::Separator(e) => e.current_chunk(),
            State::Done => &[],
        }
    }

    fn advance(&mut self) -> EncoderStatus {
        let state_finished = match &mut self.state {
            State::WitnessScript(e) => e.advance().has_finished(),
            State::Bip32Derivations(e) => e.advance().has_finished(),
            State::TapInternalKey(e) => e.advance().has_finished(),
            State::TapTree(e) => e.advance().has_finished(),
            State::TapKeyOrigins(e) => e.advance().has_finished(),
            State::Proprietaries(e) => e.advance().has_finished(),
            State::Unknowns(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::SpV0Info(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::SpV0Label(e) => e.advance().has_finished(),
            State::Separator(e) => e.advance().has_finished(),
            State::Done => return EncoderStatus::Finished,
        };

        if state_finished {
            self.state = self.next_state();
            if matches!(&self.state, State::Done) {
                return EncoderStatus::Finished;
            }
        }

        EncoderStatus::HasMore
    }
}

/// Iterator that wraps each [`Output`](crate::Output) in an
/// [`OutputMapEncoder`].
pub(crate) struct Outputs<'e> {
    iter: core::slice::Iter<'e, crate::Output>,
}

impl<'e> Iterator for Outputs<'e> {
    type Item = OutputMapEncoder<'e>;

    fn next(&mut self) -> Option<Self::Item> { self.iter.next().map(OutputMapEncoder::new) }
}

impl<'e> From<core::slice::Iter<'e, crate::Output>> for Outputs<'e> {
    fn from(iter: core::slice::Iter<'e, crate::Output>) -> Self { Self { iter } }
}

/// Internal stages of the v0 output map decoder.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum OutputStage {
    DecodingSeparator,
    DecodingKey(KeyDecoder),
    DecodingRedeemScript {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingWitnessScript {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingBip32Derivation {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingTapInternalKey {
        key: Key,
        decoder: ValueDecoder<ArrayDecoder<32>>,
    },
    DecodingTapTree {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingTapBip32Derivation {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingProprietary {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingUnknown {
        key: Key,
        decoder: ByteVecDecoder,
    },
    #[cfg(feature = "silent-payments")]
    DecodingSpV0Info {
        key: Key,
        decoder: ValueDecoder<ArrayDecoder<66>>,
    },
    #[cfg(feature = "silent-payments")]
    DecodingSpV0Label {
        key: Key,
        decoder: ValueDecoder<ArrayDecoder<4>>,
    },
    Done(Output),
    Errored,
}

impl OutputStage {
    fn from_key(key: Key) -> Result<Self, OutputDecodeError> {
        match key.type_value {
            PSBT_OUT_REDEEM_SCRIPT if key.key.is_empty() =>
                Ok(Self::DecodingRedeemScript { key, decoder: ByteVecDecoder::new() }),
            PSBT_OUT_WITNESS_SCRIPT if key.key.is_empty() =>
                Ok(Self::DecodingWitnessScript { key, decoder: ByteVecDecoder::new() }),
            PSBT_OUT_TAP_INTERNAL_KEY if key.key.is_empty() =>
                Ok(Self::DecodingTapInternalKey { key, decoder: ValueDecoder::default() }),
            PSBT_OUT_TAP_TREE if key.key.is_empty() =>
                Ok(Self::DecodingTapTree { key, decoder: ByteVecDecoder::new() }),
            PSBT_OUT_PROPRIETARY if key.key.is_empty() =>
                Ok(Self::DecodingProprietary { key, decoder: ByteVecDecoder::new() }),
            PSBT_OUT_BIP32_DERIVATION =>
                Ok(Self::DecodingBip32Derivation { key, decoder: ByteVecDecoder::new() }),
            PSBT_OUT_TAP_BIP32_DERIVATION =>
                Ok(Self::DecodingTapBip32Derivation { key, decoder: ByteVecDecoder::new() }),
            #[cfg(feature = "silent-payments")]
            PSBT_OUT_SP_V0_INFO =>
                Ok(Self::DecodingSpV0Info { key, decoder: ValueDecoder::default() }),
            #[cfg(feature = "silent-payments")]
            PSBT_OUT_SP_V0_LABEL =>
                Ok(Self::DecodingSpV0Label { key, decoder: ValueDecoder::default() }),
            _ => {
                let unkeyed = core::matches!(
                    key.type_value,
                    PSBT_OUT_REDEEM_SCRIPT
                        | PSBT_OUT_WITNESS_SCRIPT
                        | PSBT_OUT_TAP_INTERNAL_KEY
                        | PSBT_OUT_TAP_TREE
                        | PSBT_OUT_PROPRIETARY
                );
                if unkeyed && !key.key.is_empty() {
                    return Err(OutputDecodeError::InsertPair(
                        OutputInsertPairError::InvalidKeyDataNotEmpty(key),
                    ));
                }
                Ok(Self::DecodingUnknown { key, decoder: ByteVecDecoder::new() })
            }
        }
    }
}

/// Decoder for a single v0 output map.
#[derive(Debug)]
pub(crate) struct OutputMapDecoder {
    stage: OutputStage,
    amount: Amount,
    script_pubkey: ScriptBuf,
    redeem_script: Option<ScriptBuf>,
    witness_script: Option<ScriptBuf>,
    bip32_derivations: BTreeMap<PublicKey, KeySource>,
    tap_internal_key: Option<XOnlyPublicKey>,
    tap_tree: Option<TapTree>,
    tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    #[cfg(feature = "silent-payments")]
    sp_v0_info: Option<SpV0Info>,
    #[cfg(feature = "silent-payments")]
    sp_v0_label: Option<u32>,
    proprietaries: BTreeMap<ProprietaryKey, Vec<u8>>,
    unknowns: BTreeMap<Key, Vec<u8>>,
}

impl Default for OutputMapDecoder {
    fn default() -> Self {
        Self {
            stage: OutputStage::DecodingSeparator,
            amount: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
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

impl OutputMapDecoder {
    /// Build the merged [`Output`].
    fn finish(&mut self) -> Result<Output, OutputDecodeError> {
        Ok(Output {
            amount: self.amount,
            script_pubkey: core::mem::take(&mut self.script_pubkey),
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
        })
    }
}

impl Decoder for OutputMapDecoder {
    type Output = Output;
    type Error = OutputDecodeError;

    #[allow(clippy::too_many_lines)]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        if matches!(&self.stage, OutputStage::Done(_)) {
            return Ok(DecoderStatus::Ready);
        }

        loop {
            if matches!(&self.stage, OutputStage::DecodingSeparator) {
                match bytes.split_first() {
                    Some((&PSBT_SEPARATOR, rest)) => {
                        *bytes = rest;
                        let output = self.finish()?;
                        self.stage = OutputStage::Done(output);
                        return Ok(DecoderStatus::Ready);
                    }
                    Some((_, _)) => {
                        self.stage = OutputStage::DecodingKey(KeyDecoder::default());
                    }
                    None => return Ok(DecoderStatus::NeedsMore),
                }
            }

            let status = match &mut self.stage {
                OutputStage::DecodingKey(d) =>
                    d.push_bytes(bytes).map_err(OutputDecodeError::KeyDecode)?,
                OutputStage::DecodingRedeemScript { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::RedeemScript(e))
                    })?,
                OutputStage::DecodingWitnessScript { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::WitnessScript(e))
                    })?,
                OutputStage::DecodingBip32Derivation { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::Bip32Derivation(e))
                    })?,
                OutputStage::DecodingTapInternalKey { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) => OutputDecodeError::ValueDecode(
                            OutputValueDecodeError::TapInternalKey(e),
                        ),
                    })?,
                OutputStage::DecodingTapTree { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::TapTree(e))
                    })?,
                OutputStage::DecodingTapBip32Derivation { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::TapBip32Derivation(
                            e,
                        ))
                    })?,
                OutputStage::DecodingProprietary { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::ProprietaryValue(e))
                    })?,
                OutputStage::DecodingUnknown { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::UnknownValue(e))
                    })?,
                #[cfg(feature = "silent-payments")]
                OutputStage::DecodingSpV0Info { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::SpV0Info(e)),
                    })?,
                #[cfg(feature = "silent-payments")]
                OutputStage::DecodingSpV0Label { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::SpV0Label(e)),
                    })?,
                OutputStage::Done(_) => return Ok(DecoderStatus::Ready),
                OutputStage::DecodingSeparator | OutputStage::Errored =>
                    panic!("push_bytes in unexpected stage"),
            };

            if status.needs_more() {
                return Ok(DecoderStatus::NeedsMore);
            }

            let old = core::mem::replace(&mut self.stage, OutputStage::Errored);
            match old {
                OutputStage::DecodingKey(decoder) => {
                    let key = decoder.end().map_err(OutputDecodeError::KeyDecode)?;
                    self.stage = OutputStage::from_key(key)?;
                }
                OutputStage::DecodingRedeemScript { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::RedeemScript(e))
                    })?;
                    if self.redeem_script.is_some() {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::DuplicateKey(key),
                        ));
                    }
                    self.redeem_script = Some(ScriptBuf::from(value));
                    self.stage = OutputStage::DecodingSeparator;
                }
                OutputStage::DecodingWitnessScript { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::WitnessScript(e))
                    })?;
                    if self.witness_script.is_some() {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::DuplicateKey(key),
                        ));
                    }
                    self.witness_script = Some(ScriptBuf::from(value));
                    self.stage = OutputStage::DecodingSeparator;
                }
                OutputStage::DecodingBip32Derivation { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::Bip32Derivation(e))
                    })?;
                    let fprint = Fingerprint::from(
                        <[u8; 4]>::try_from(&value[..4])
                            .map_err(|_| OutputDecodeError::MissingExpectedValue("fingerprint"))?,
                    );
                    let mut dpath: Vec<ChildNumber> = Default::default();
                    for chunk in value[4..].chunks_exact(4) {
                        let index = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
                        dpath.push(ChildNumber::from(index));
                    }
                    let ks = (fprint, DerivationPath::from(dpath));
                    let pk = PublicKey::from_slice(&key.key).map_err(|e| {
                        OutputDecodeError::InsertPair(OutputInsertPairError::InvalidPublicKey(e))
                    })?;
                    match self.bip32_derivations.entry(pk) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(ks);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(OutputDecodeError::InsertPair(
                                OutputInsertPairError::DuplicateKey(key),
                            )),
                    }
                    self.stage = OutputStage::DecodingSeparator;
                }
                OutputStage::DecodingTapInternalKey { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) => OutputDecodeError::ValueDecode(
                            OutputValueDecodeError::TapInternalKey(e),
                        ),
                    })?;
                    if self.tap_internal_key.is_some() {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::DuplicateKey(key),
                        ));
                    }
                    self.tap_internal_key =
                        Some(XOnlyPublicKey::from_slice(&bytes).map_err(|_| {
                            OutputDecodeError::InsertPair(OutputInsertPairError::ValueWrongLength(
                                32, 32,
                            ))
                        })?);
                    self.stage = OutputStage::DecodingSeparator;
                }
                OutputStage::DecodingTapTree { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::TapTree(e))
                    })?;
                    if self.tap_tree.is_some() {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::DuplicateKey(key),
                        ));
                    }
                    self.tap_tree = {
                        let mut builder = TaprootBuilder::new();
                        let mut slice = &value[..];
                        while let Some((&depth, rest)) = slice.split_first() {
                            let (&version, rest) =
                                rest.split_first().ok_or(OutputDecodeError::InvalidLeafVersion)?;
                            let mut cs = CompactSizeDecoder::default();
                            let mut remaining = rest;
                            cs.push_bytes(&mut remaining)
                                .map_err(|_| OutputDecodeError::InvalidLeafVersion)?;
                            let script_len =
                                cs.end().map_err(|_| OutputDecodeError::InvalidLeafVersion)?;
                            let script = ScriptBuf::from(remaining[..script_len].to_vec());
                            let leaf_version = LeafVersion::from_consensus(version)
                                .map_err(|_| OutputDecodeError::InvalidLeafVersion)?;
                            builder = builder
                                .add_leaf_with_ver(depth, script, leaf_version)
                                .map_err(|_| OutputDecodeError::InvalidLeafVersion)?;
                            slice = &remaining[script_len..];
                        }
                        Some(
                            TapTree::try_from(builder)
                                .map_err(|_| OutputDecodeError::InvalidLeafVersion)?,
                        )
                    };
                    self.stage = OutputStage::DecodingSeparator;
                }
                OutputStage::DecodingTapBip32Derivation { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::TapBip32Derivation(
                            e,
                        ))
                    })?;
                    if value.is_empty() {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::ValueWrongLength(0, 1),
                        ));
                    }
                    let count = value[0] as usize;
                    let hash_end = 1 + count * 32;
                    if value.len() < hash_end + 4 {
                        return Err(OutputDecodeError::MissingExpectedValue(
                            "tap bip32 fingerprint",
                        ));
                    }
                    let leaf_hashes: Vec<TapLeafHash> = value[1..hash_end]
                        .chunks_exact(32)
                        .map(|chunk| TapLeafHash::from_slice(chunk).expect("32 bytes"))
                        .collect();
                    let fprint = Fingerprint::from(
                        <[u8; 4]>::try_from(&value[hash_end..hash_end + 4]).expect("4 bytes"),
                    );
                    let mut dpath: Vec<ChildNumber> = Default::default();
                    let key_bytes = &value[hash_end + 4..];
                    for chunk in key_bytes.chunks_exact(4) {
                        let index = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
                        dpath.push(ChildNumber::from(index));
                    }
                    let ks = (fprint, DerivationPath::from(dpath));
                    let xonly = XOnlyPublicKey::from_slice(&key.key).map_err(|_| {
                        OutputDecodeError::InsertPair(OutputInsertPairError::InvalidXOnlyPublicKey)
                    })?;
                    match self.tap_key_origins.entry(xonly) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert((leaf_hashes, ks));
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(OutputDecodeError::InsertPair(
                                OutputInsertPairError::DuplicateKey(key),
                            )),
                    }
                    self.stage = OutputStage::DecodingSeparator;
                }
                OutputStage::DecodingProprietary { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::ProprietaryValue(e))
                    })?;
                    let prop_key: ProprietaryKey =
                        core::convert::TryInto::try_into(key).map_err(|_| {
                            OutputDecodeError::InsertPair(
                                OutputInsertPairError::InvalidProprietaryKey,
                            )
                        })?;
                    if self.proprietaries.contains_key(&prop_key) {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::DuplicateKey(prop_key.to_key()),
                        ));
                    }
                    self.proprietaries.insert(prop_key, value);
                    self.stage = OutputStage::DecodingSeparator;
                }
                OutputStage::DecodingUnknown { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        OutputDecodeError::ValueDecode(OutputValueDecodeError::UnknownValue(e))
                    })?;
                    if self.unknowns.contains_key(&key) {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::DuplicateKey(key),
                        ));
                    }
                    self.unknowns.insert(key, value);
                    self.stage = OutputStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                OutputStage::DecodingSpV0Info { key, decoder } => {
                    let (value_len, arr) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::SpV0Info(e)),
                    })?;
                    if value_len != 66 {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::ValueWrongLength(value_len as usize, 66),
                        ));
                    }
                    if self.sp_v0_info.is_some() {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::DuplicateKey(key),
                        ));
                    }
                    self.sp_v0_info = Some(SpV0Info::from_byte_array(&arr).map_err(|_| {
                        OutputDecodeError::InsertPair(OutputInsertPairError::ValueWrongLength(
                            66, 66,
                        ))
                    })?);
                    self.stage = OutputStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                OutputStage::DecodingSpV0Label { key, decoder } => {
                    let (value_len, arr) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            OutputDecodeError::ValueDecode(OutputValueDecodeError::SpV0Label(e)),
                    })?;
                    if value_len != 4 {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::ValueWrongLength(value_len as usize, 4),
                        ));
                    }
                    if self.sp_v0_label.is_some() {
                        return Err(OutputDecodeError::InsertPair(
                            OutputInsertPairError::DuplicateKey(key),
                        ));
                    }
                    self.sp_v0_label = Some(u32::from_le_bytes(arr));
                    self.stage = OutputStage::DecodingSeparator;
                }
                OutputStage::Done(_) => return Ok(DecoderStatus::Ready),
                OutputStage::DecodingSeparator | OutputStage::Errored => unreachable!(),
            }
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            OutputStage::DecodingKey(d) => d.read_limit(),
            OutputStage::DecodingTapInternalKey { ref decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            OutputStage::DecodingSpV0Info { ref decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            OutputStage::DecodingSpV0Label { ref decoder, .. } => decoder.read_limit(),
            OutputStage::DecodingRedeemScript { ref decoder, .. }
            | OutputStage::DecodingWitnessScript { ref decoder, .. }
            | OutputStage::DecodingBip32Derivation { ref decoder, .. }
            | OutputStage::DecodingTapTree { ref decoder, .. }
            | OutputStage::DecodingTapBip32Derivation { ref decoder, .. }
            | OutputStage::DecodingProprietary { ref decoder, .. }
            | OutputStage::DecodingUnknown { ref decoder, .. } => decoder.read_limit(),
            OutputStage::Done(_) | OutputStage::Errored => 0,
            OutputStage::DecodingSeparator => 1,
        }
    }

    fn end(self) -> Result<Output, Self::Error> {
        match self.stage {
            OutputStage::Done(output) => Ok(output),
            _ => Err(OutputDecodeError::MissingExpectedValue("output map separator")),
        }
    }
}

pub(crate) type OutputsDecoder = ExactVecDecoderWith<OutputMapDecoder>;
