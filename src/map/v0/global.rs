// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 global map encoder and decoder.
//!
//! `<global-map> := <unsigned_tx> <xpub>* <proprietary>* <unknown>* 0x00`
//!
//! The decoder produces a [`V0Global`] which includes the reconstructed
//! [`Global`](crate::Global) plus the per-input and per-output data extracted
//! from the unsigned transaction.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use bitcoin::bip32::{self, DerivationPath, Fingerprint, Xpub};
use bitcoin::locktime::absolute;
#[cfg(feature = "silent-payments")]
use bitcoin::CompressedPublicKey;
use bitcoin::{transaction, Amount, ScriptBuf, Sequence, Txid};
use bitcoin_consensus_encoding::{
    ByteVecDecoder, CompactSizeEncoder, Decoder, Decoder2Error, DecoderStatus, Encoder,
    EncoderStatus, IterEncoder,
};

use super::unsigned_tx::{UnsignedTxDecodeError, UnsignedTxDecoder, UnsignedTxEncoder};
use crate::consts::{
    PSBT_GLOBAL_PROPRIETARY, PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION, PSBT_GLOBAL_XPUB,
    PSBT_SEPARATOR,
};
#[cfg(feature = "silent-payments")]
use crate::consts::{PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_SP_ECDH_SHARE};
#[cfg(feature = "silent-payments")]
use crate::dleq::DleqProof;
#[cfg(feature = "silent-payments")]
use crate::encoding::native::{DleqKeyValueIter, EcdhKeyValueIter};
use crate::encoding::native::{SeparatorEncoder, XpubKeyValueIter};
use crate::encoding::{KeyValueEncoder, ValueDecoder};
use crate::map::{Key, KeyDecodeError, KeyDecoder, ProprietaryKey, ProprietaryKeyValueIter};
use crate::version::{Version, VersionDecoderError, VersionValueDecoder};
use crate::{V0, V2};

pub(crate) struct GlobalMapEncoder<'e> {
    psbt: &'e crate::Psbt,
    state: State<'e>,
}

enum State<'e> {
    UnsignedTx(KeyValueEncoder<CompactSizeEncoder, UnsignedTxEncoder<'e>>),
    Xpubs(IterEncoder<XpubKeyValueIter<'e>>),
    Proprietaries(IterEncoder<ProprietaryKeyValueIter<'e>>),
    Unknowns(IterEncoder<crate::map::UnknownKeyValueIter<'e>>),
    #[cfg(feature = "silent-payments")]
    Ecdh(IterEncoder<EcdhKeyValueIter<'e>>),
    #[cfg(feature = "silent-payments")]
    Dleq(IterEncoder<DleqKeyValueIter<'e>>),
    Separator(SeparatorEncoder),
    Done,
}

impl<'e> GlobalMapEncoder<'e> {
    pub(crate) fn new(v0: &'e crate::psbt::PsbtV0) -> Self {
        Self { psbt: &v0.psbt, state: Self::unsigned_tx(v0) }
    }

    fn unsigned_tx(v0: &'e crate::psbt::PsbtV0) -> State<'e> {
        State::UnsignedTx(KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_GLOBAL_UNSIGNED_TX),
            UnsignedTxEncoder::from_psbt(v0),
        ))
    }

    fn next_state(&self) -> State<'e> {
        match &self.state {
            State::UnsignedTx(_) => self.xpubs_or_next(),
            State::Xpubs(_) => self.proprietaries_or_next(),
            State::Proprietaries(_) => self.unknowns_or_next(),
            State::Unknowns(_) => self.ecdh_or_next(),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(_) => self.dleq_or_next(),
            #[cfg(feature = "silent-payments")]
            State::Dleq(_) => State::Separator(SeparatorEncoder::new()),
            State::Separator(_) => State::Done,
            State::Done => State::Done,
        }
    }

    fn xpubs_or_next(&self) -> State<'e> {
        if self.psbt.global.xpubs.is_empty() {
            self.proprietaries_or_next()
        } else {
            State::Xpubs(IterEncoder::new(XpubKeyValueIter::new(self.psbt.global.xpubs.iter())))
        }
    }

    fn proprietaries_or_next(&self) -> State<'e> {
        if self.psbt.global.proprietaries.is_empty() {
            self.unknowns_or_next()
        } else {
            State::Proprietaries(IterEncoder::new(ProprietaryKeyValueIter(
                self.psbt.global.proprietaries.iter(),
            )))
        }
    }

    fn unknowns_or_next(&self) -> State<'e> {
        if self.psbt.global.unknowns.is_empty() {
            self.ecdh_or_next()
        } else {
            State::Unknowns(IterEncoder::new(crate::map::UnknownKeyValueIter(
                self.psbt.global.unknowns.iter(),
            )))
        }
    }

    fn ecdh_or_next(&self) -> State<'e> {
        #[cfg(feature = "silent-payments")]
        {
            if !self.psbt.global.sp_ecdh_shares.is_empty() {
                return State::Ecdh(IterEncoder::new(EcdhKeyValueIter::new(
                    self.psbt.global.sp_ecdh_shares.iter(),
                )));
            }
            self.dleq_or_next()
        }
        #[cfg(not(feature = "silent-payments"))]
        State::Separator(SeparatorEncoder::new())
    }

    #[allow(dead_code)]
    fn dleq_or_next(&self) -> State<'e> {
        #[cfg(feature = "silent-payments")]
        {
            if !self.psbt.global.sp_dleq_proofs.is_empty() {
                return State::Dleq(IterEncoder::new(DleqKeyValueIter::new(
                    self.psbt.global.sp_dleq_proofs.iter(),
                )));
            }
        }
        State::Separator(SeparatorEncoder::new())
    }
}

impl Encoder for GlobalMapEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match &self.state {
            State::UnsignedTx(e) => e.current_chunk(),
            State::Xpubs(e) => e.current_chunk(),
            State::Proprietaries(e) => e.current_chunk(),
            State::Unknowns(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::Dleq(e) => e.current_chunk(),
            State::Separator(e) => e.current_chunk(),
            State::Done => &[],
        }
    }

    fn advance(&mut self) -> EncoderStatus {
        let state_finished = match &mut self.state {
            State::UnsignedTx(e) => e.advance().has_finished(),
            State::Xpubs(e) => e.advance().has_finished(),
            State::Proprietaries(e) => e.advance().has_finished(),
            State::Unknowns(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::Dleq(e) => e.advance().has_finished(),
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

/// The result of decoding a v0 global map.
#[derive(Debug)]
pub(crate) struct V0Global {
    /// The reconstructed v2 global.
    pub global: crate::Global,
    /// Per-input data extracted from the unsigned transaction.
    pub tx_inputs: Vec<(Txid, u32, Sequence)>,
    /// Per-output data extracted from the unsigned transaction.
    pub tx_outputs: Vec<(Amount, ScriptBuf)>,
    /// The lock time resolved from the unsigned transaction.
    #[allow(dead_code)]
    pub lock_time: absolute::LockTime,
}

/// Error decoding a v0 global map.
#[derive(Debug)]
pub enum DecodeError {
    KeyDecode(KeyDecodeError),
    MissingUnsignedTx,
    UnsignedTx(UnsignedTxDecodeError),
    LengthPrefix(bitcoin_consensus_encoding::CompactSizeDecoderError),
    DuplicateKey(Key),
    NonEmptyVersionKey,
    WrongVersion(u32),
    ValueWrongLength(usize, usize),
    InvalidXpub(bip32::Error),
    XpubValueTooShort(usize),
    InvalidProprietaryKey,
    UnexpectedEof(bitcoin_consensus_encoding::UnexpectedEofError),
    UnknownValue(bitcoin_consensus_encoding::ByteVecDecoderError),
    #[cfg(feature = "silent-payments")]
    SpEcdh(bitcoin_consensus_encoding::UnexpectedEofError),
    #[cfg(feature = "silent-payments")]
    SpDleq(bitcoin_consensus_encoding::UnexpectedEofError),
    #[allow(dead_code)]
    FieldMismatch,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyDecode(e) => write!(f, "key decode: {}", e),
            Self::MissingUnsignedTx => write!(f, "missing unsigned tx in v0 global map"),
            Self::UnsignedTx(e) => write!(f, "unsigned tx: {}", e),
            Self::LengthPrefix(e) => write!(f, "value length prefix: {}", e),
            Self::DuplicateKey(k) => write!(f, "duplicate key: {}", k),
            Self::NonEmptyVersionKey => write!(f, "version key must be empty"),
            Self::WrongVersion(v) => write!(f, "unsupported PSBT version {}", v),
            Self::ValueWrongLength(got, exp) =>
                write!(f, "value length {} (expected {})", got, exp),
            Self::InvalidXpub(e) => write!(f, "invalid xpub: {}", e),
            Self::XpubValueTooShort(len) =>
                write!(f, "xpub value too short ({} bytes, need >= 4)", len),
            Self::InvalidProprietaryKey => write!(f, "invalid proprietary key"),
            Self::UnexpectedEof(e) => write!(f, "{}", e),
            Self::UnknownValue(e) => write!(f, "unknown value: {}", e),
            #[cfg(feature = "silent-payments")]
            Self::SpEcdh(e) => write!(f, "sp ecdh share: {}", e),
            #[cfg(feature = "silent-payments")]
            Self::SpDleq(e) => write!(f, "sp dleq proof: {}", e),
            Self::FieldMismatch =>
                write!(f, "silent payment fields must be present in matching pairs"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

#[derive(Debug)]
enum Stage {
    DecodingUnsignedTxKey(KeyDecoder),
    DecodingUnsignedTxValue {
        decoder: ValueDecoder<UnsignedTxDecoder>,
    },
    DecodingSeparator,
    DecodingKey(KeyDecoder),
    DecodingXpub {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingVersion {
        key: Key,
        decoder: VersionValueDecoder,
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
    DecodingSpEcdhShare {
        key: Key,
        decoder: ValueDecoder<bitcoin_consensus_encoding::ArrayDecoder<33>>,
    },
    #[cfg(feature = "silent-payments")]
    DecodingSpDleqProof {
        key: Key,
        decoder: ValueDecoder<bitcoin_consensus_encoding::ArrayDecoder<64>>,
    },
    Done(V0Global),
    Errored,
}

impl Stage {
    fn from_key(key: Key) -> Result<Self, DecodeError> {
        match key.type_value {
            PSBT_GLOBAL_UNSIGNED_TX => Err(DecodeError::DuplicateKey(key)),
            PSBT_GLOBAL_XPUB => Ok(Self::DecodingXpub { key, decoder: ByteVecDecoder::new() }),
            PSBT_GLOBAL_VERSION =>
                Ok(Self::DecodingVersion { key, decoder: VersionValueDecoder::default() }),
            PSBT_GLOBAL_PROPRIETARY =>
                Ok(Self::DecodingProprietary { key, decoder: ByteVecDecoder::new() }),
            #[cfg(feature = "silent-payments")]
            PSBT_GLOBAL_SP_ECDH_SHARE =>
                Ok(Self::DecodingSpEcdhShare { key, decoder: ValueDecoder::default() }),
            #[cfg(feature = "silent-payments")]
            PSBT_GLOBAL_SP_DLEQ =>
                Ok(Self::DecodingSpDleqProof { key, decoder: ValueDecoder::default() }),
            _ => Ok(Self::DecodingUnknown { key, decoder: ByteVecDecoder::new() }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct GlobalMapDecoder {
    stage: Stage,
    version: Option<Version>,
    tx_version: Option<transaction::Version>,
    xpubs: BTreeMap<Xpub, (Fingerprint, DerivationPath)>,
    #[cfg(feature = "silent-payments")]
    sp_ecdh_shares: BTreeMap<CompressedPublicKey, CompressedPublicKey>,
    #[cfg(feature = "silent-payments")]
    sp_dleq_proofs: BTreeMap<CompressedPublicKey, DleqProof>,
    proprietaries: BTreeMap<ProprietaryKey, Vec<u8>>,
    unknowns: BTreeMap<Key, Vec<u8>>,
    tx_inputs: Option<Vec<(Txid, u32, Sequence)>>,
    tx_outputs: Option<Vec<(Amount, ScriptBuf)>>,
    tx_lock_time: Option<absolute::LockTime>,
}

impl Default for GlobalMapDecoder {
    fn default() -> Self {
        Self {
            stage: Stage::DecodingUnsignedTxKey(KeyDecoder::default()),
            version: None,
            tx_version: None,
            xpubs: BTreeMap::default(),
            #[cfg(feature = "silent-payments")]
            sp_ecdh_shares: BTreeMap::default(),
            #[cfg(feature = "silent-payments")]
            sp_dleq_proofs: BTreeMap::default(),
            proprietaries: BTreeMap::default(),
            unknowns: BTreeMap::default(),
            tx_inputs: None,
            tx_outputs: None,
            tx_lock_time: None,
        }
    }
}

impl Decoder for GlobalMapDecoder {
    type Output = V0Global;
    type Error = DecodeError;

    #[allow(clippy::too_many_lines)]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        if matches!(&self.stage, Stage::Done(_)) {
            return Ok(DecoderStatus::Ready);
        }

        loop {
            if matches!(&self.stage, Stage::DecodingSeparator) {
                match bytes.split_first() {
                    Some((&PSBT_SEPARATOR, rest)) => {
                        *bytes = rest;
                        let tx_version = self.tx_version.ok_or(DecodeError::MissingUnsignedTx)?;
                        let tx_inputs =
                            self.tx_inputs.take().ok_or(DecodeError::MissingUnsignedTx)?;
                        let tx_outputs =
                            self.tx_outputs.take().ok_or(DecodeError::MissingUnsignedTx)?;
                        let lock_time = self.tx_lock_time.ok_or(DecodeError::MissingUnsignedTx)?;

                        #[cfg(feature = "silent-payments")]
                        {
                            let has_ecdh = !self.sp_ecdh_shares.is_empty();
                            let has_dleq = !self.sp_dleq_proofs.is_empty();
                            if has_ecdh != has_dleq {
                                return Err(DecodeError::FieldMismatch);
                            }
                        }

                        self.stage = Stage::Done(V0Global {
                            global: crate::Global {
                                tx_version,
                                fallback_lock_time: (lock_time != absolute::LockTime::ZERO)
                                    .then_some(lock_time),
                                input_count: tx_inputs.len(),
                                output_count: tx_outputs.len(),
                                tx_modifiable_flags: 0,
                                version: self.version.unwrap_or(V2),
                                xpubs: core::mem::take(&mut self.xpubs),
                                #[cfg(feature = "silent-payments")]
                                sp_ecdh_shares: core::mem::take(&mut self.sp_ecdh_shares),
                                #[cfg(feature = "silent-payments")]
                                sp_dleq_proofs: core::mem::take(&mut self.sp_dleq_proofs),
                                proprietaries: core::mem::take(&mut self.proprietaries),
                                unknowns: core::mem::take(&mut self.unknowns),
                            },
                            tx_inputs,
                            tx_outputs,
                            lock_time,
                        });
                        return Ok(DecoderStatus::Ready);
                    }
                    Some((_, _)) => {
                        self.stage = Stage::DecodingKey(KeyDecoder::default());
                    }
                    None => return Ok(DecoderStatus::NeedsMore),
                }
            }

            let status = match &mut self.stage {
                Stage::DecodingUnsignedTxKey(d) =>
                    d.push_bytes(bytes).map_err(DecodeError::KeyDecode)?,
                Stage::DecodingUnsignedTxValue { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) => DecodeError::LengthPrefix(e),
                        Decoder2Error::Second(e) => DecodeError::UnsignedTx(e),
                    })?,
                Stage::DecodingKey(d) => d.push_bytes(bytes).map_err(DecodeError::KeyDecode)?,
                Stage::DecodingVersion { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) => DecodeError::LengthPrefix(e),
                        Decoder2Error::Second(e) => match e {
                            VersionDecoderError::UnexpectedEof(e) => DecodeError::UnexpectedEof(e),
                            VersionDecoderError::UnsupportedVersion(e) =>
                                DecodeError::WrongVersion(e.version()),
                        },
                    })?,
                Stage::DecodingXpub { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(DecodeError::UnknownValue)?,
                Stage::DecodingProprietary { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(DecodeError::UnknownValue)?,
                Stage::DecodingUnknown { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(DecodeError::UnknownValue)?,
                #[cfg(feature = "silent-payments")]
                Stage::DecodingSpEcdhShare { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) => DecodeError::LengthPrefix(e),
                        Decoder2Error::Second(e) => DecodeError::SpEcdh(e),
                    })?,
                #[cfg(feature = "silent-payments")]
                Stage::DecodingSpDleqProof { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) => DecodeError::LengthPrefix(e),
                        Decoder2Error::Second(e) => DecodeError::SpDleq(e),
                    })?,
                Stage::Done(_) => return Ok(DecoderStatus::Ready),
                Stage::DecodingSeparator | Stage::Errored =>
                    panic!("call to push_bytes() in unexpected stage"),
            };

            if status.needs_more() {
                return Ok(DecoderStatus::NeedsMore);
            }

            let old = core::mem::replace(&mut self.stage, Stage::Errored);
            match old {
                Stage::DecodingUnsignedTxKey(decoder) => {
                    let key = decoder.end().map_err(DecodeError::KeyDecode)?;
                    if key.type_value != PSBT_GLOBAL_UNSIGNED_TX || !key.key.is_empty() {
                        return Err(DecodeError::MissingUnsignedTx);
                    }
                    self.stage =
                        Stage::DecodingUnsignedTxValue { decoder: ValueDecoder::default() };
                }
                Stage::DecodingUnsignedTxValue { decoder } => {
                    let (_value_len, (version, tx_inputs, tx_outputs, lock_time)) =
                        decoder.end().map_err(|e| match e {
                            Decoder2Error::First(e) => DecodeError::LengthPrefix(e),
                            Decoder2Error::Second(e) => DecodeError::UnsignedTx(e),
                        })?;
                    self.tx_version = Some(version);
                    self.tx_inputs = Some(tx_inputs);
                    self.tx_outputs = Some(tx_outputs);
                    self.tx_lock_time = Some(lock_time);
                    self.stage = Stage::DecodingSeparator;
                }
                Stage::DecodingKey(decoder) => {
                    let key = decoder.end().map_err(DecodeError::KeyDecode)?;
                    self.stage = Stage::from_key(key)?;
                }
                Stage::DecodingVersion { key, decoder } => {
                    let (value_len, version) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) => DecodeError::LengthPrefix(e),
                        Decoder2Error::Second(e) => match e {
                            VersionDecoderError::UnexpectedEof(e) => DecodeError::UnexpectedEof(e),
                            VersionDecoderError::UnsupportedVersion(e) =>
                                DecodeError::WrongVersion(e.version()),
                        },
                    })?;
                    if value_len != 4 {
                        return Err(DecodeError::ValueWrongLength(value_len as usize, 4));
                    }
                    if version != V0 {
                        return Err(DecodeError::WrongVersion(version.to_u32()));
                    }
                    if !key.key.is_empty() {
                        return Err(DecodeError::NonEmptyVersionKey);
                    }
                    if self.version.is_some() {
                        return Err(DecodeError::DuplicateKey(key));
                    }
                    self.version = Some(V2);
                    self.stage = Stage::DecodingSeparator;
                }
                Stage::DecodingXpub { key, decoder } => {
                    let value = decoder.end().map_err(DecodeError::UnknownValue)?;
                    if value.len() < 4 {
                        return Err(DecodeError::XpubValueTooShort(value.len()));
                    }
                    let xpub = Xpub::decode(&key.key).map_err(DecodeError::InvalidXpub)?;
                    let fingerprint = Fingerprint::from(
                        <[u8; 4]>::try_from(&value[..4]).expect("checked length >= 4"),
                    );
                    let derivation: DerivationPath = if value.len() > 4 {
                        let child_bytes = &value[4..];
                        if child_bytes.len() % 4 != 0 {
                            return Err(DecodeError::XpubValueTooShort(value.len()));
                        }
                        let children: Vec<bip32::ChildNumber> = child_bytes
                            .chunks_exact(4)
                            .map(|c| {
                                let idx =
                                    u32::from_le_bytes(c.try_into().expect("chunks_exact(4)"));
                                bip32::ChildNumber::from(idx)
                            })
                            .collect();
                        bip32::DerivationPath::from(children)
                    } else {
                        bip32::DerivationPath::master()
                    };
                    if self.xpubs.contains_key(&xpub) {
                        return Err(DecodeError::DuplicateKey(key));
                    }
                    self.xpubs.insert(xpub, (fingerprint, derivation));
                    self.stage = Stage::DecodingSeparator;
                }
                Stage::DecodingProprietary { key, decoder } => {
                    let value = decoder.end().map_err(DecodeError::UnknownValue)?;
                    let prop_key = core::convert::TryInto::<ProprietaryKey>::try_into(key)
                        .map_err(|_| DecodeError::InvalidProprietaryKey)?;
                    if self.proprietaries.contains_key(&prop_key) {
                        return Err(DecodeError::DuplicateKey(prop_key.to_key()));
                    }
                    self.proprietaries.insert(prop_key, value);
                    self.stage = Stage::DecodingSeparator;
                }
                Stage::DecodingUnknown { key, decoder } => {
                    let value = decoder.end().map_err(DecodeError::UnknownValue)?;
                    if self.unknowns.contains_key(&key) {
                        return Err(DecodeError::DuplicateKey(key));
                    }
                    self.unknowns.insert(key, value);
                    self.stage = Stage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                Stage::DecodingSpEcdhShare { key, decoder } => {
                    let (value_len, arr) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) => DecodeError::LengthPrefix(e),
                        Decoder2Error::Second(e) => DecodeError::SpEcdh(e),
                    })?;
                    if value_len != 33 {
                        return Err(DecodeError::ValueWrongLength(value_len as usize, 33));
                    }
                    let scan_key = CompressedPublicKey::from_slice(&key.key)
                        .map_err(|_| DecodeError::InvalidProprietaryKey)?;
                    let share = CompressedPublicKey::from_slice(&arr)
                        .map_err(|_| DecodeError::InvalidProprietaryKey)?;
                    if self.sp_ecdh_shares.contains_key(&scan_key) {
                        return Err(DecodeError::DuplicateKey(key));
                    }
                    self.sp_ecdh_shares.insert(scan_key, share);
                    self.stage = Stage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                Stage::DecodingSpDleqProof { key, decoder } => {
                    let (value_len, arr) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) => DecodeError::LengthPrefix(e),
                        Decoder2Error::Second(e) => DecodeError::SpDleq(e),
                    })?;
                    if value_len != 64 {
                        return Err(DecodeError::ValueWrongLength(value_len as usize, 64));
                    }
                    let scan_key = CompressedPublicKey::from_slice(&key.key)
                        .map_err(|_| DecodeError::InvalidProprietaryKey)?;
                    let proof = DleqProof::from(arr);
                    if self.sp_dleq_proofs.contains_key(&scan_key) {
                        return Err(DecodeError::DuplicateKey(key));
                    }
                    self.sp_dleq_proofs.insert(scan_key, proof);
                    self.stage = Stage::DecodingSeparator;
                }
                Stage::Done(_) => return Ok(DecoderStatus::Ready),
                Stage::DecodingSeparator | Stage::Errored => unreachable!(),
            }
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            Stage::DecodingUnsignedTxKey(d) => d.read_limit(),
            Stage::DecodingUnsignedTxValue { ref decoder, .. } => decoder.read_limit(),
            Stage::DecodingKey(d) => d.read_limit(),
            Stage::DecodingVersion { ref decoder, .. } => decoder.read_limit(),
            Stage::DecodingXpub { ref decoder, .. } => decoder.read_limit(),
            Stage::DecodingProprietary { ref decoder, .. } => decoder.read_limit(),
            Stage::DecodingUnknown { ref decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            Stage::DecodingSpEcdhShare { ref decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            Stage::DecodingSpDleqProof { ref decoder, .. } => decoder.read_limit(),
            Stage::Done(_) | Stage::Errored => 0,
            Stage::DecodingSeparator => 1,
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.stage {
            Stage::Done(v0) => Ok(v0),
            _ => Err(DecodeError::MissingUnsignedTx),
        }
    }
}
