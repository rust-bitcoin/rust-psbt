// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 input map encoder and decoder.
//!
//! v0 inputs omit `previous_txid`, `spent_output_index`, `sequence`,
//! `min_time`, and `min_height`, those come from the unsigned transaction.

use alloc::collections::{btree_map, BTreeMap};
use alloc::vec::Vec;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource};
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use bitcoin::key::{PublicKey, XOnlyPublicKey};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
#[cfg(feature = "silent-payments")]
use bitcoin::CompressedPublicKey;
use bitcoin::{ecdsa, taproot, ScriptBuf, Sequence, Transaction, TxOut, Txid, Witness};
use bitcoin_consensus_encoding::{
    ArrayDecoder, ByteVecDecoder, CompactSizeEncoder, Decoder, Decoder2Error, DecoderStatus,
    Encoder, EncoderStatus, ExactVecDecoderWith, IterEncoder,
};

use super::super::{Key, KeyDecoder, ProprietaryKey, ProprietaryKeyValueIter, UnknownKeyValueIter};
use crate::consts::{
    PSBT_IN_BIP32_DERIVATION, PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_HASH160, PSBT_IN_HASH256, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_PARTIAL_SIG,
    PSBT_IN_PROPRIETARY, PSBT_IN_REDEEM_SCRIPT, PSBT_IN_RIPEMD160, PSBT_IN_SHA256,
    PSBT_IN_SIGHASH_TYPE, PSBT_IN_TAP_BIP32_DERIVATION, PSBT_IN_TAP_INTERNAL_KEY,
    PSBT_IN_TAP_KEY_SIG, PSBT_IN_TAP_LEAF_SCRIPT, PSBT_IN_TAP_MERKLE_ROOT, PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_WITNESS_SCRIPT, PSBT_IN_WITNESS_UTXO, PSBT_SEPARATOR,
};
#[cfg(feature = "silent-payments")]
use crate::consts::{PSBT_IN_SP_DLEQ, PSBT_IN_SP_ECDH_SHARE};
use crate::encoding::delegates::{FinalScriptWitnessPair, WitnessUtxoPair};
use crate::encoding::native::{
    Bip32DerivationIter, Hash160Iter, Hash256Iter, PartialSigIter, Ripemd160Iter, ScriptPair,
    SeparatorEncoder, Sha256Iter, SighashPair, TapInternalKeyPair, TapKeyOriginIter, TapKeySigPair,
    TapMerkleRootPair, TapScriptIter, TapScriptSigIter,
};
#[cfg(feature = "silent-payments")]
use crate::encoding::native::{DleqPairIter, EcdhPairIter};
use crate::encoding::{KeyValueEncoder, PsbtEncode, ValueDecoder};
use crate::input::Input;
use crate::map::error::{InputDecodeError, InputValueDecodeError};
use crate::sighash_type::PsbtSighashType;
#[cfg(feature = "silent-payments")]
use crate::silent_payments::DleqProof;

pub struct InputMapEncoder<'e> {
    input: &'e Input,
    state: State<'e>,
}

enum State<'e> {
    NonWitnessUtxo(
        KeyValueEncoder<
            CompactSizeEncoder,
            crate::encoding::ExactLenEncoder<'e, bitcoin::Transaction>,
        >,
    ),
    WitnessUtxo(WitnessUtxoPair<'e>),
    PartialSigs(IterEncoder<PartialSigIter<'e>>),
    SighashType(SighashPair<'e>),
    RedeemScript(ScriptPair<'e>),
    WitnessScript(ScriptPair<'e>),
    Bip32Derivations(IterEncoder<Bip32DerivationIter<'e>>),
    FinalScriptSig(ScriptPair<'e>),
    FinalScriptWitness(FinalScriptWitnessPair<'e>),
    Ripemd160Preimages(IterEncoder<Ripemd160Iter<'e>>),
    Sha256Preimages(IterEncoder<Sha256Iter<'e>>),
    Hash160Preimages(IterEncoder<Hash160Iter<'e>>),
    Hash256Preimages(IterEncoder<Hash256Iter<'e>>),
    TapKeySig(TapKeySigPair<'e>),
    TapScriptSigs(IterEncoder<TapScriptSigIter<'e>>),
    TapScripts(IterEncoder<TapScriptIter<'e>>),
    TapKeyOrigins(IterEncoder<TapKeyOriginIter<'e>>),
    TapInternalKey(TapInternalKeyPair<'e>),
    TapMerkleRoot(TapMerkleRootPair<'e>),
    Proprietaries(IterEncoder<ProprietaryKeyValueIter<'e>>),
    Unknowns(IterEncoder<UnknownKeyValueIter<'e>>),
    #[cfg(feature = "silent-payments")]
    Ecdh(IterEncoder<EcdhPairIter<'e>>),
    #[cfg(feature = "silent-payments")]
    Dleq(IterEncoder<DleqPairIter<'e>>),
    Separator(SeparatorEncoder),
    Done,
}

impl<'e> InputMapEncoder<'e> {
    pub(crate) fn new(input: &'e Input) -> Self {
        Self { input, state: Self::non_witness_utxo_or_next(input) }
    }

    fn next_state(&self) -> State<'e> {
        match &self.state {
            State::NonWitnessUtxo(_) => Self::witness_utxo_or_next(self.input),
            State::WitnessUtxo(_) => Self::partial_sigs_or_next(self.input),
            State::PartialSigs(_) => Self::sighash_or_next(self.input),
            State::SighashType(_) => Self::redeem_script_or_next(self.input),
            State::RedeemScript(_) => Self::witness_script_or_next(self.input),
            State::WitnessScript(_) => Self::bip32_or_next(self.input),
            State::Bip32Derivations(_) => Self::final_script_sig_or_next(self.input),
            State::FinalScriptSig(_) => Self::final_script_witness_or_next(self.input),
            State::FinalScriptWitness(_) => Self::ripemd160_or_next(self.input),
            State::Ripemd160Preimages(_) => Self::sha256_or_next(self.input),
            State::Sha256Preimages(_) => Self::hash160_or_next(self.input),
            State::Hash160Preimages(_) => Self::hash256_or_next(self.input),
            State::Hash256Preimages(_) => Self::tap_key_sig_or_next(self.input),
            State::TapKeySig(_) => Self::tap_script_sigs_or_next(self.input),
            State::TapScriptSigs(_) => Self::tap_scripts_or_next(self.input),
            State::TapScripts(_) => Self::tap_key_origins_or_next(self.input),
            State::TapKeyOrigins(_) => Self::tap_internal_key_or_next(self.input),
            State::TapInternalKey(_) => Self::tap_merkle_root_or_next(self.input),
            State::TapMerkleRoot(_) => Self::proprietaries_or_next(self.input),
            State::Proprietaries(_) => Self::unknowns_or_next(self.input),
            State::Unknowns(_) => Self::ecdh_or_next(self.input),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(_) => Self::dleq_or_next(self.input),
            #[cfg(feature = "silent-payments")]
            State::Dleq(_) => State::Separator(SeparatorEncoder::new()),
            State::Separator(_) => State::Done,
            State::Done => State::Done,
        }
    }

    fn non_witness_utxo_or_next(input: &'e Input) -> State<'e> {
        if let Some(tx) = &input.non_witness_utxo {
            State::NonWitnessUtxo(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_NON_WITNESS_UTXO),
                crate::encoding::ExactLenEncoder::new(tx, tx.total_size()),
            ))
        } else {
            Self::witness_utxo_or_next(input)
        }
    }

    fn witness_utxo_or_next(input: &'e Input) -> State<'e> {
        if let Some(tx_out) = &input.witness_utxo {
            State::WitnessUtxo(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_WITNESS_UTXO),
                tx_out.psbt_encoder(),
            ))
        } else {
            Self::partial_sigs_or_next(input)
        }
    }

    fn partial_sigs_or_next(input: &'e Input) -> State<'e> {
        if !input.partial_sigs.is_empty() {
            State::PartialSigs(IterEncoder::new(PartialSigIter::new(input.partial_sigs.iter())))
        } else {
            Self::sighash_or_next(input)
        }
    }

    fn sighash_or_next(input: &'e Input) -> State<'e> {
        if let Some(st) = &input.sighash_type {
            State::SighashType(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_SIGHASH_TYPE),
                st.psbt_encoder(),
            ))
        } else {
            Self::redeem_script_or_next(input)
        }
    }

    fn redeem_script_or_next(input: &'e Input) -> State<'e> {
        if let Some(rs) = &input.redeem_script {
            State::RedeemScript(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_REDEEM_SCRIPT),
                rs.psbt_encoder(),
            ))
        } else {
            Self::witness_script_or_next(input)
        }
    }

    fn witness_script_or_next(input: &'e Input) -> State<'e> {
        if let Some(ws) = &input.witness_script {
            State::WitnessScript(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_WITNESS_SCRIPT),
                ws.psbt_encoder(),
            ))
        } else {
            Self::bip32_or_next(input)
        }
    }

    fn bip32_or_next(input: &'e Input) -> State<'e> {
        if !input.bip32_derivations.is_empty() {
            State::Bip32Derivations(IterEncoder::new(Bip32DerivationIter::new(
                input.bip32_derivations.iter(),
            )))
        } else {
            Self::final_script_sig_or_next(input)
        }
    }

    fn final_script_sig_or_next(input: &'e Input) -> State<'e> {
        if let Some(fs) = &input.final_script_sig {
            State::FinalScriptSig(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_FINAL_SCRIPTSIG),
                fs.psbt_encoder(),
            ))
        } else {
            Self::final_script_witness_or_next(input)
        }
    }

    fn final_script_witness_or_next(input: &'e Input) -> State<'e> {
        if let Some(witness) = &input.final_script_witness {
            State::FinalScriptWitness(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_FINAL_SCRIPTWITNESS),
                crate::encoding::ExactLenEncoder::new(witness, witness.size()),
            ))
        } else {
            Self::ripemd160_or_next(input)
        }
    }

    fn ripemd160_or_next(input: &'e Input) -> State<'e> {
        if !input.ripemd160_preimages.is_empty() {
            State::Ripemd160Preimages(IterEncoder::new(Ripemd160Iter::new_bytes(
                input.ripemd160_preimages.iter(),
            )))
        } else {
            Self::sha256_or_next(input)
        }
    }

    fn sha256_or_next(input: &'e Input) -> State<'e> {
        if !input.sha256_preimages.is_empty() {
            State::Sha256Preimages(IterEncoder::new(Sha256Iter::new_bytes(
                input.sha256_preimages.iter(),
            )))
        } else {
            Self::hash160_or_next(input)
        }
    }

    fn hash160_or_next(input: &'e Input) -> State<'e> {
        if !input.hash160_preimages.is_empty() {
            State::Hash160Preimages(IterEncoder::new(Hash160Iter::new_bytes(
                input.hash160_preimages.iter(),
            )))
        } else {
            Self::hash256_or_next(input)
        }
    }

    fn hash256_or_next(input: &'e Input) -> State<'e> {
        if !input.hash256_preimages.is_empty() {
            State::Hash256Preimages(IterEncoder::new(Hash256Iter::new_bytes(
                input.hash256_preimages.iter(),
            )))
        } else {
            Self::tap_key_sig_or_next(input)
        }
    }

    fn tap_key_sig_or_next(input: &'e Input) -> State<'e> {
        if let Some(sig) = &input.tap_key_sig {
            State::TapKeySig(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_TAP_KEY_SIG),
                sig.psbt_encoder(),
            ))
        } else {
            Self::tap_script_sigs_or_next(input)
        }
    }

    fn tap_script_sigs_or_next(input: &'e Input) -> State<'e> {
        if !input.tap_script_sigs.is_empty() {
            State::TapScriptSigs(IterEncoder::new(TapScriptSigIter::new(
                input.tap_script_sigs.iter(),
            )))
        } else {
            Self::tap_scripts_or_next(input)
        }
    }

    fn tap_scripts_or_next(input: &'e Input) -> State<'e> {
        if !input.tap_scripts.is_empty() {
            State::TapScripts(IterEncoder::new(TapScriptIter::new(input.tap_scripts.iter())))
        } else {
            Self::tap_key_origins_or_next(input)
        }
    }

    fn tap_key_origins_or_next(input: &'e Input) -> State<'e> {
        if !input.tap_key_origins.is_empty() {
            State::TapKeyOrigins(IterEncoder::new(TapKeyOriginIter::new(
                input.tap_key_origins.iter(),
            )))
        } else {
            Self::tap_internal_key_or_next(input)
        }
    }

    fn tap_internal_key_or_next(input: &'e Input) -> State<'e> {
        if let Some(key) = input.tap_internal_key {
            State::TapInternalKey(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_TAP_INTERNAL_KEY),
                key.psbt_encoder(),
            ))
        } else {
            Self::tap_merkle_root_or_next(input)
        }
    }

    fn tap_merkle_root_or_next(input: &'e Input) -> State<'e> {
        if let Some(root) = input.tap_merkle_root {
            State::TapMerkleRoot(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_TAP_MERKLE_ROOT),
                root.psbt_encoder(),
            ))
        } else {
            Self::proprietaries_or_next(input)
        }
    }

    fn proprietaries_or_next(input: &'e Input) -> State<'e> {
        if !input.proprietaries.is_empty() {
            State::Proprietaries(IterEncoder::new(ProprietaryKeyValueIter(
                input.proprietaries.iter(),
            )))
        } else {
            Self::unknowns_or_next(input)
        }
    }

    fn unknowns_or_next(input: &'e Input) -> State<'e> {
        if !input.unknowns.is_empty() {
            return State::Unknowns(IterEncoder::new(UnknownKeyValueIter(input.unknowns.iter())));
        }
        Self::ecdh_or_next(input)
    }

    fn ecdh_or_next(_input: &'e Input) -> State<'e> {
        #[cfg(feature = "silent-payments")]
        {
            if !_input.sp_ecdh_shares.is_empty() {
                return State::Ecdh(IterEncoder::new(EcdhPairIter::new(
                    _input.sp_ecdh_shares.iter(),
                )));
            }
            Self::dleq_or_next(_input)
        }
        #[cfg(not(feature = "silent-payments"))]
        State::Separator(SeparatorEncoder::new())
    }

    #[cfg(feature = "silent-payments")]
    fn dleq_or_next(input: &'e Input) -> State<'e> {
        if !input.sp_dleq_proofs.is_empty() {
            return State::Dleq(IterEncoder::new(DleqPairIter::new(input.sp_dleq_proofs.iter())));
        }
        State::Separator(SeparatorEncoder::new())
    }
}

impl Encoder for InputMapEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match &self.state {
            State::NonWitnessUtxo(e) => e.current_chunk(),
            State::WitnessUtxo(e) => e.current_chunk(),
            State::PartialSigs(e) => e.current_chunk(),
            State::SighashType(e) => e.current_chunk(),
            State::RedeemScript(e) => e.current_chunk(),
            State::WitnessScript(e) => e.current_chunk(),
            State::Bip32Derivations(e) => e.current_chunk(),
            State::FinalScriptSig(e) => e.current_chunk(),
            State::FinalScriptWitness(e) => e.current_chunk(),
            State::Ripemd160Preimages(e) => e.current_chunk(),
            State::Sha256Preimages(e) => e.current_chunk(),
            State::Hash160Preimages(e) => e.current_chunk(),
            State::Hash256Preimages(e) => e.current_chunk(),
            State::TapKeySig(e) => e.current_chunk(),
            State::TapScriptSigs(e) => e.current_chunk(),
            State::TapScripts(e) => e.current_chunk(),
            State::TapKeyOrigins(e) => e.current_chunk(),
            State::TapInternalKey(e) => e.current_chunk(),
            State::TapMerkleRoot(e) => e.current_chunk(),
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
            State::NonWitnessUtxo(e) => e.advance().has_finished(),
            State::WitnessUtxo(e) => e.advance().has_finished(),
            State::PartialSigs(e) => e.advance().has_finished(),
            State::SighashType(e) => e.advance().has_finished(),
            State::RedeemScript(e) => e.advance().has_finished(),
            State::WitnessScript(e) => e.advance().has_finished(),
            State::Bip32Derivations(e) => e.advance().has_finished(),
            State::FinalScriptSig(e) => e.advance().has_finished(),
            State::FinalScriptWitness(e) => e.advance().has_finished(),
            State::Ripemd160Preimages(e) => e.advance().has_finished(),
            State::Sha256Preimages(e) => e.advance().has_finished(),
            State::Hash160Preimages(e) => e.advance().has_finished(),
            State::Hash256Preimages(e) => e.advance().has_finished(),
            State::TapKeySig(e) => e.advance().has_finished(),
            State::TapScriptSigs(e) => e.advance().has_finished(),
            State::TapScripts(e) => e.advance().has_finished(),
            State::TapKeyOrigins(e) => e.advance().has_finished(),
            State::TapInternalKey(e) => e.advance().has_finished(),
            State::TapMerkleRoot(e) => e.advance().has_finished(),
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

/// Iterator that wraps each [`Input`] in an [`InputMapEncoder`].
pub(crate) struct Inputs<'e> {
    iter: core::slice::Iter<'e, crate::input::Input>,
}

impl<'e> Iterator for Inputs<'e> {
    type Item = InputMapEncoder<'e>;

    fn next(&mut self) -> Option<Self::Item> { self.iter.next().map(InputMapEncoder::new) }
}

impl<'e> From<core::slice::Iter<'e, crate::input::Input>> for Inputs<'e> {
    fn from(iter: core::slice::Iter<'e, crate::input::Input>) -> Self { Self { iter } }
}

/// Internal stages of the v0 input map decoder.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum InputStage {
    DecodingSeparator,
    DecodingKey(KeyDecoder),
    DecodingNonWitnessUtxo {
        key: Key,
        decoder: ValueDecoder<<Transaction as crate::encoding::PsbtDecode>::Decoder>,
    },
    DecodingWitnessUtxo {
        key: Key,
        decoder: ValueDecoder<<TxOut as crate::encoding::PsbtDecode>::Decoder>,
    },
    DecodingSighashType {
        key: Key,
        decoder: ValueDecoder<ArrayDecoder<4>>,
    },
    DecodingRedeemScript {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingWitnessScript {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingFinalScriptSig {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingFinalScriptWitness {
        key: Key,
        decoder: ValueDecoder<<Witness as crate::encoding::PsbtDecode>::Decoder>,
    },
    DecodingTapKeySig {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingTapInternalKey {
        key: Key,
        decoder: ValueDecoder<ArrayDecoder<32>>,
    },
    DecodingTapMerkleRoot {
        key: Key,
        decoder: ValueDecoder<ArrayDecoder<32>>,
    },
    DecodingPartialSig {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingBip32Derivation {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingRipemd160 {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingSha256 {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingHash160 {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingHash256 {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingTapScriptSig {
        key: Key,
        decoder: ByteVecDecoder,
    },
    DecodingTapLeafScript {
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
    DecodingSpEcdhShare {
        key: Key,
        decoder: ValueDecoder<ArrayDecoder<33>>,
    },
    #[cfg(feature = "silent-payments")]
    DecodingSpDleqProof {
        key: Key,
        decoder: ValueDecoder<ArrayDecoder<64>>,
    },
    Done(Input),
    Errored,
}

impl InputStage {
    fn from_key(key: Key) -> Result<Self, InputDecodeError> {
        match key.type_value {
            PSBT_IN_NON_WITNESS_UTXO if key.key.is_empty() =>
                Ok(Self::DecodingNonWitnessUtxo { key, decoder: ValueDecoder::default() }),
            PSBT_IN_WITNESS_UTXO if key.key.is_empty() =>
                Ok(Self::DecodingWitnessUtxo { key, decoder: ValueDecoder::default() }),
            PSBT_IN_SIGHASH_TYPE if key.key.is_empty() =>
                Ok(Self::DecodingSighashType { key, decoder: ValueDecoder::default() }),
            PSBT_IN_REDEEM_SCRIPT if key.key.is_empty() =>
                Ok(Self::DecodingRedeemScript { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_WITNESS_SCRIPT if key.key.is_empty() =>
                Ok(Self::DecodingWitnessScript { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_FINAL_SCRIPTSIG if key.key.is_empty() =>
                Ok(Self::DecodingFinalScriptSig { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_FINAL_SCRIPTWITNESS if key.key.is_empty() =>
                Ok(Self::DecodingFinalScriptWitness { key, decoder: ValueDecoder::default() }),
            PSBT_IN_TAP_KEY_SIG if key.key.is_empty() =>
                Ok(Self::DecodingTapKeySig { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_TAP_INTERNAL_KEY if key.key.is_empty() =>
                Ok(Self::DecodingTapInternalKey { key, decoder: ValueDecoder::default() }),
            PSBT_IN_TAP_MERKLE_ROOT if key.key.is_empty() =>
                Ok(Self::DecodingTapMerkleRoot { key, decoder: ValueDecoder::default() }),
            PSBT_IN_RIPEMD160 if key.key.is_empty() =>
                Ok(Self::DecodingRipemd160 { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_SHA256 if key.key.is_empty() =>
                Ok(Self::DecodingSha256 { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_HASH160 if key.key.is_empty() =>
                Ok(Self::DecodingHash160 { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_HASH256 if key.key.is_empty() =>
                Ok(Self::DecodingHash256 { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_PROPRIETARY if key.key.is_empty() =>
                Ok(Self::DecodingProprietary { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_PARTIAL_SIG =>
                Ok(Self::DecodingPartialSig { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_BIP32_DERIVATION =>
                Ok(Self::DecodingBip32Derivation { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_TAP_SCRIPT_SIG =>
                Ok(Self::DecodingTapScriptSig { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_TAP_LEAF_SCRIPT =>
                Ok(Self::DecodingTapLeafScript { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_TAP_BIP32_DERIVATION =>
                Ok(Self::DecodingTapBip32Derivation { key, decoder: ByteVecDecoder::new() }),
            #[cfg(feature = "silent-payments")]
            PSBT_IN_SP_ECDH_SHARE =>
                Ok(Self::DecodingSpEcdhShare { key, decoder: ValueDecoder::default() }),
            #[cfg(feature = "silent-payments")]
            PSBT_IN_SP_DLEQ =>
                Ok(Self::DecodingSpDleqProof { key, decoder: ValueDecoder::default() }),
            _ => {
                let unkeyed = core::matches!(
                    key.type_value,
                    PSBT_IN_NON_WITNESS_UTXO
                        | PSBT_IN_WITNESS_UTXO
                        | PSBT_IN_SIGHASH_TYPE
                        | PSBT_IN_REDEEM_SCRIPT
                        | PSBT_IN_WITNESS_SCRIPT
                        | PSBT_IN_FINAL_SCRIPTSIG
                        | PSBT_IN_FINAL_SCRIPTWITNESS
                        | PSBT_IN_TAP_KEY_SIG
                        | PSBT_IN_TAP_INTERNAL_KEY
                        | PSBT_IN_TAP_MERKLE_ROOT
                        | PSBT_IN_RIPEMD160
                        | PSBT_IN_SHA256
                        | PSBT_IN_HASH160
                        | PSBT_IN_HASH256
                        | PSBT_IN_PROPRIETARY
                );
                if unkeyed && !key.key.is_empty() {
                    return Err(InputDecodeError::InvalidKeyData(key));
                }
                Ok(Self::DecodingUnknown { key, decoder: ByteVecDecoder::new() })
            }
        }
    }
}

/// Decoder for a single v0 input map.
#[derive(Debug)]
pub(crate) struct InputMapDecoder {
    stage: InputStage,
    txid: Txid,
    vout: u32,
    sequence: Sequence,
    non_witness_utxo: Option<Transaction>,
    witness_utxo: Option<TxOut>,
    partial_sigs: BTreeMap<PublicKey, ecdsa::Signature>,
    sighash_type: Option<PsbtSighashType>,
    redeem_script: Option<ScriptBuf>,
    witness_script: Option<ScriptBuf>,
    bip32_derivations: BTreeMap<PublicKey, KeySource>,
    final_script_sig: Option<ScriptBuf>,
    final_script_witness: Option<Witness>,
    ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,
    sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,
    hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,
    hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,
    tap_key_sig: Option<taproot::Signature>,
    tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), taproot::Signature>,
    tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,
    tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    tap_internal_key: Option<XOnlyPublicKey>,
    tap_merkle_root: Option<TapNodeHash>,
    #[cfg(feature = "silent-payments")]
    sp_ecdh_shares: BTreeMap<CompressedPublicKey, CompressedPublicKey>,
    #[cfg(feature = "silent-payments")]
    sp_dleq_proofs: BTreeMap<CompressedPublicKey, DleqProof>,
    proprietaries: BTreeMap<ProprietaryKey, Vec<u8>>,
    unknowns: BTreeMap<Key, Vec<u8>>,
}

impl Default for InputMapDecoder {
    fn default() -> Self {
        Self {
            stage: InputStage::DecodingSeparator,
            txid: Txid::all_zeros(),
            vout: 0,
            sequence: Sequence::MAX,
            non_witness_utxo: None,
            witness_utxo: None,
            partial_sigs: BTreeMap::default(),
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: BTreeMap::default(),
            final_script_sig: None,
            final_script_witness: None,
            ripemd160_preimages: BTreeMap::default(),
            sha256_preimages: BTreeMap::default(),
            hash160_preimages: BTreeMap::default(),
            hash256_preimages: BTreeMap::default(),
            tap_key_sig: None,
            tap_script_sigs: BTreeMap::default(),
            tap_scripts: BTreeMap::default(),
            tap_key_origins: BTreeMap::default(),
            tap_internal_key: None,
            tap_merkle_root: None,
            #[cfg(feature = "silent-payments")]
            sp_ecdh_shares: BTreeMap::default(),
            #[cfg(feature = "silent-payments")]
            sp_dleq_proofs: BTreeMap::default(),
            proprietaries: BTreeMap::default(),
            unknowns: BTreeMap::default(),
        }
    }
}

impl Decoder for InputMapDecoder {
    type Output = Input;
    type Error = InputDecodeError;

    #[allow(clippy::too_many_lines)]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        if matches!(&self.stage, InputStage::Done(_)) {
            return Ok(DecoderStatus::Ready);
        }

        loop {
            if matches!(&self.stage, InputStage::DecodingSeparator) {
                match bytes.split_first() {
                    Some((&PSBT_SEPARATOR, rest)) => {
                        *bytes = rest;
                        let input = self.finish_inner()?;
                        self.stage = InputStage::Done(input);
                        return Ok(DecoderStatus::Ready);
                    }
                    Some((_, _)) => {
                        self.stage = InputStage::DecodingKey(KeyDecoder::default());
                    }
                    None => return Ok(DecoderStatus::NeedsMore),
                }
            }

            // Push bytes into the active stage decoder.
            let status = match &mut self.stage {
                InputStage::DecodingKey(d) =>
                    d.push_bytes(bytes).map_err(InputDecodeError::KeyDecode)?,
                InputStage::DecodingNonWitnessUtxo { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::NonWitnessUtxo(e)),
                    })?,
                InputStage::DecodingWitnessUtxo { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::WitnessUtxo(e)),
                    })?,
                InputStage::DecodingSighashType { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::SighashType(e)),
                    })?,
                InputStage::DecodingRedeemScript { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::RedeemScript(e))
                    })?,
                InputStage::DecodingWitnessScript { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::WitnessScript(e))
                    })?,
                InputStage::DecodingFinalScriptSig { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::FinalScriptSig(e))
                    })?,
                InputStage::DecodingFinalScriptWitness { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) => InputDecodeError::ValueDecode(
                            InputValueDecodeError::FinalScriptWitness(e),
                        ),
                    })?,
                InputStage::DecodingTapKeySig { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::TapKeySig(e))
                    })?,
                InputStage::DecodingTapInternalKey { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::TapInternalKey(e)),
                    })?,
                InputStage::DecodingTapMerkleRoot { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::TapMerkleRoot(e)),
                    })?,
                InputStage::DecodingPartialSig { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::PartialSig(e))
                    })?,
                InputStage::DecodingBip32Derivation { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Bip32Derivation(e))
                    })?,
                InputStage::DecodingRipemd160 { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Ripemd160Preimage(e))
                    })?,
                InputStage::DecodingSha256 { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Sha256Preimage(e))
                    })?,
                InputStage::DecodingHash160 { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Hash160Preimage(e))
                    })?,
                InputStage::DecodingHash256 { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Hash256Preimage(e))
                    })?,
                InputStage::DecodingTapScriptSig { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::TapScriptSig(e))
                    })?,
                InputStage::DecodingTapLeafScript { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::TapLeafScript(e))
                    })?,
                InputStage::DecodingTapBip32Derivation { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::TapBip32Derivation(e))
                    })?,
                InputStage::DecodingProprietary { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::ProprietaryValue(e))
                    })?,
                InputStage::DecodingUnknown { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::UnknownValue(e))
                    })?,
                #[cfg(feature = "silent-payments")]
                InputStage::DecodingSpEcdhShare { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::SpEcdh(e)),
                    })?,
                #[cfg(feature = "silent-payments")]
                InputStage::DecodingSpDleqProof { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::SpDleq(e)),
                    })?,
                InputStage::Done(_) => return Ok(DecoderStatus::Ready),
                InputStage::DecodingSeparator | InputStage::Errored =>
                    panic!("push_bytes in unexpected stage"),
            };

            if status.needs_more() {
                return Ok(DecoderStatus::NeedsMore);
            }

            let old = core::mem::replace(&mut self.stage, InputStage::Errored);
            match old {
                InputStage::DecodingKey(decoder) => {
                    let key = decoder.end().map_err(InputDecodeError::KeyDecode)?;
                    self.stage = InputStage::from_key(key)?;
                }
                InputStage::DecodingNonWitnessUtxo { key, decoder } => {
                    let (_, tx) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::NonWitnessUtxo(e)),
                    })?;
                    if self.non_witness_utxo.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.non_witness_utxo = Some(tx);
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingWitnessUtxo { key, decoder } => {
                    let (_, txout) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::WitnessUtxo(e)),
                    })?;
                    if self.witness_utxo.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.witness_utxo = Some(txout);
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingSighashType { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::SighashType(e)),
                    })?;
                    if self.sighash_type.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.sighash_type = Some(PsbtSighashType { inner: u32::from_le_bytes(bytes) });
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingRedeemScript { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::RedeemScript(e))
                    })?;
                    if self.redeem_script.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.redeem_script = Some(ScriptBuf::from(value));
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingWitnessScript { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::WitnessScript(e))
                    })?;
                    if self.witness_script.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.witness_script = Some(ScriptBuf::from(value));
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingFinalScriptSig { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::FinalScriptSig(e))
                    })?;
                    if self.final_script_sig.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.final_script_sig = Some(ScriptBuf::from(value));
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingFinalScriptWitness { key, decoder } => {
                    let (_, witness) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) => InputDecodeError::ValueDecode(
                            InputValueDecodeError::FinalScriptWitness(e),
                        ),
                    })?;
                    if self.final_script_witness.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.final_script_witness = Some(witness);
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingTapKeySig { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::TapKeySig(e))
                    })?;
                    if self.tap_key_sig.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.tap_key_sig =
                        Some(taproot::Signature::from_slice(&value).map_err(|_| {
                            InputDecodeError::ValueDecode(
                                InputValueDecodeError::InvalidTaprootSignature,
                            )
                        })?);
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingTapInternalKey { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::TapInternalKey(e)),
                    })?;
                    if self.tap_internal_key.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.tap_internal_key = Some(
                        XOnlyPublicKey::from_slice(&bytes)
                            .map_err(|_| InputDecodeError::ValueWrongLength(32, 32))?,
                    );
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingTapMerkleRoot { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::TapMerkleRoot(e)),
                    })?;
                    if self.tap_merkle_root.is_some() {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.tap_merkle_root = Some(
                        TapNodeHash::from_slice(&bytes).map_err(InputDecodeError::InvalidHash)?,
                    );
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingPartialSig { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::PartialSig(e))
                    })?;
                    let pk = PublicKey::from_slice(&key.key)
                        .map_err(InputDecodeError::InvalidPublicKey)?;
                    let sig = ecdsa::Signature::from_slice(&value)
                        .map_err(InputDecodeError::InvalidEcdsaSignature)?;
                    match self.partial_sigs.entry(pk) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(sig);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(InputDecodeError::DuplicateKey(key)),
                    }
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingBip32Derivation { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Bip32Derivation(e))
                    })?;
                    let fprint = Fingerprint::from(
                        <[u8; 4]>::try_from(&value[..4])
                            .map_err(|_| InputDecodeError::MissingExpectedValue("fingerprint"))?,
                    );
                    let mut dpath: Vec<ChildNumber> = Default::default();
                    for chunk in value[4..].chunks_exact(4) {
                        let index = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
                        dpath.push(ChildNumber::from(index));
                    }
                    let ks = (fprint, DerivationPath::from(dpath));
                    let pk = PublicKey::from_slice(&key.key)
                        .map_err(InputDecodeError::InvalidPublicKey)?;
                    match self.bip32_derivations.entry(pk) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(ks);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(InputDecodeError::DuplicateKey(key)),
                    }
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingRipemd160 { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Ripemd160Preimage(e))
                    })?;
                    let hash = ripemd160::Hash::from_slice(&key.key)
                        .map_err(InputDecodeError::InvalidHash)?;
                    match self.ripemd160_preimages.entry(hash) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(InputDecodeError::DuplicateKey(key)),
                    }
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingSha256 { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Sha256Preimage(e))
                    })?;
                    let hash = sha256::Hash::from_slice(&key.key)
                        .map_err(InputDecodeError::InvalidHash)?;
                    match self.sha256_preimages.entry(hash) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(InputDecodeError::DuplicateKey(key)),
                    }
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingHash160 { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Hash160Preimage(e))
                    })?;
                    let hash = hash160::Hash::from_slice(&key.key)
                        .map_err(InputDecodeError::InvalidHash)?;
                    match self.hash160_preimages.entry(hash) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(InputDecodeError::DuplicateKey(key)),
                    }
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingHash256 { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::Hash256Preimage(e))
                    })?;
                    let hash = sha256d::Hash::from_slice(&key.key)
                        .map_err(InputDecodeError::InvalidHash)?;
                    match self.hash256_preimages.entry(hash) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(InputDecodeError::DuplicateKey(key)),
                    }
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingTapScriptSig { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::TapScriptSig(e))
                    })?;
                    if key.key.len() != 64 {
                        return Err(InputDecodeError::KeyWrongLength(key.key.len(), 64));
                    }
                    let xonly = XOnlyPublicKey::from_slice(&key.key[..32])
                        .map_err(|_| InputDecodeError::KeyWrongLength(32, 32))?;
                    let leaf_hash = TapLeafHash::from_slice(&key.key[32..64])
                        .map_err(|_| InputDecodeError::KeyWrongLength(32, 32))?;
                    let sig = taproot::Signature::from_slice(&value).map_err(|_| {
                        InputDecodeError::ValueDecode(
                            InputValueDecodeError::InvalidTaprootSignature,
                        )
                    })?;
                    match self.tap_script_sigs.entry((xonly, leaf_hash)) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(sig);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(InputDecodeError::DuplicateKey(key)),
                    }
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingTapLeafScript { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::TapLeafScript(e))
                    })?;
                    let cb = ControlBlock::decode(&key.key).map_err(|_| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::InvalidControlBlock)
                    })?;
                    if value.is_empty() {
                        return Err(InputDecodeError::ValueWrongLength(0, 1));
                    }
                    let last = value.len() - 1;
                    let script = ScriptBuf::from_bytes(value[..last].to_vec());
                    let ver = LeafVersion::from_consensus(value[last]).map_err(|_| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::InvalidLeafVersion)
                    })?;
                    match self.tap_scripts.entry(cb) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert((script, ver));
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(InputDecodeError::DuplicateKey(key)),
                    }
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingTapBip32Derivation { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::TapBip32Derivation(e))
                    })?;
                    if value.is_empty() {
                        return Err(InputDecodeError::ValueWrongLength(0, 1));
                    }
                    let count = value[0] as usize;
                    let hash_end = 1 + count * 32;
                    if value.len() < hash_end + 4 {
                        return Err(InputDecodeError::MissingExpectedValue(
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
                    let xonly = XOnlyPublicKey::from_slice(&key.key)
                        .map_err(|_| InputDecodeError::KeyWrongLength(32, 32))?;
                    match self.tap_key_origins.entry(xonly) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert((leaf_hashes, ks));
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(InputDecodeError::DuplicateKey(key)),
                    }
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingProprietary { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::ProprietaryValue(e))
                    })?;
                    let prop_key = core::convert::TryInto::<ProprietaryKey>::try_into(key)
                        .map_err(|_| InputDecodeError::InvalidProprietaryKey)?;
                    // This will not compile as-is: need to convert from crate::map::ProprietaryKey
                    // to the generic type. We'll fix this when we connect everything.
                    if self.proprietaries.contains_key(&prop_key) {
                        return Err(InputDecodeError::DuplicateKey(prop_key.to_key()));
                    }
                    self.proprietaries.insert(prop_key, value);
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::DecodingUnknown { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        InputDecodeError::ValueDecode(InputValueDecodeError::UnknownValue(e))
                    })?;
                    if self.unknowns.contains_key(&key) {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.unknowns.insert(key, value);
                    self.stage = InputStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                InputStage::DecodingSpEcdhShare { key, decoder } => {
                    let (_, arr) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::SpEcdh(e)),
                    })?;
                    let scan_key = CompressedPublicKey::from_slice(&key.key)
                        .map_err(|_| InputDecodeError::KeyWrongLength(key.key.len(), 33))?;
                    let share = CompressedPublicKey::from_slice(&arr)
                        .map_err(|_| InputDecodeError::ValueWrongLength(33, 33))?;
                    if self.sp_ecdh_shares.contains_key(&scan_key) {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.sp_ecdh_shares.insert(scan_key, share);
                    self.stage = InputStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                InputStage::DecodingSpDleqProof { key, decoder } => {
                    let (_, arr) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            InputDecodeError::ValueDecode(InputValueDecodeError::SpDleq(e)),
                    })?;
                    let scan_key = CompressedPublicKey::from_slice(&key.key)
                        .map_err(|_| InputDecodeError::KeyWrongLength(key.key.len(), 33))?;
                    let proof = DleqProof::from(arr);
                    if self.sp_dleq_proofs.contains_key(&scan_key) {
                        return Err(InputDecodeError::DuplicateKey(key));
                    }
                    self.sp_dleq_proofs.insert(scan_key, proof);
                    self.stage = InputStage::DecodingSeparator;
                }
                InputStage::Done(_) => return Ok(DecoderStatus::Ready),
                InputStage::DecodingSeparator | InputStage::Errored => unreachable!(),
            }
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            InputStage::DecodingKey(d) => d.read_limit(),
            InputStage::DecodingNonWitnessUtxo { ref decoder, .. } => decoder.read_limit(),
            InputStage::DecodingWitnessUtxo { ref decoder, .. } => decoder.read_limit(),
            InputStage::DecodingSighashType { ref decoder, .. } => decoder.read_limit(),
            InputStage::DecodingFinalScriptWitness { ref decoder, .. } => decoder.read_limit(),
            InputStage::DecodingTapInternalKey { ref decoder, .. } => decoder.read_limit(),
            InputStage::DecodingTapMerkleRoot { ref decoder, .. } => decoder.read_limit(),
            InputStage::DecodingRedeemScript { ref decoder, .. }
            | InputStage::DecodingWitnessScript { ref decoder, .. }
            | InputStage::DecodingFinalScriptSig { ref decoder, .. }
            | InputStage::DecodingTapKeySig { ref decoder, .. }
            | InputStage::DecodingPartialSig { ref decoder, .. }
            | InputStage::DecodingBip32Derivation { ref decoder, .. }
            | InputStage::DecodingRipemd160 { ref decoder, .. }
            | InputStage::DecodingSha256 { ref decoder, .. }
            | InputStage::DecodingHash160 { ref decoder, .. }
            | InputStage::DecodingHash256 { ref decoder, .. }
            | InputStage::DecodingTapScriptSig { ref decoder, .. }
            | InputStage::DecodingTapLeafScript { ref decoder, .. }
            | InputStage::DecodingTapBip32Derivation { ref decoder, .. }
            | InputStage::DecodingProprietary { ref decoder, .. }
            | InputStage::DecodingUnknown { ref decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            InputStage::DecodingSpEcdhShare { ref decoder, .. } => decoder.read_limit(),
            #[cfg(feature = "silent-payments")]
            InputStage::DecodingSpDleqProof { ref decoder, .. } => decoder.read_limit(),
            InputStage::Done(_) | InputStage::Errored => 0,
            InputStage::DecodingSeparator => 1,
        }
    }

    fn end(self) -> Result<Input, Self::Error> {
        match self.stage {
            InputStage::Done(input) => Ok(input),
            _ => Err(InputDecodeError::MissingExpectedValue("input map separator")),
        }
    }
}

// Helper that extracts the accumulator and panics if we're not Done.
impl InputMapDecoder {
    fn finish_inner(&mut self) -> Result<Input, InputDecodeError> {
        // Take all the fields by replacing with defaults, then build.
        let txid = self.txid;
        let vout = self.vout;
        let sequence = self.sequence;
        Ok(Input {
            previous_txid: txid,
            spent_output_index: vout,
            sequence: Some(sequence),
            min_time: None,
            min_height: None,
            non_witness_utxo: self.non_witness_utxo.take(),
            witness_utxo: self.witness_utxo.take(),
            partial_sigs: core::mem::take(&mut self.partial_sigs),
            sighash_type: self.sighash_type.take(),
            redeem_script: self.redeem_script.take(),
            witness_script: self.witness_script.take(),
            bip32_derivations: core::mem::take(&mut self.bip32_derivations),
            final_script_sig: self.final_script_sig.take(),
            final_script_witness: self.final_script_witness.take(),
            ripemd160_preimages: core::mem::take(&mut self.ripemd160_preimages),
            sha256_preimages: core::mem::take(&mut self.sha256_preimages),
            hash160_preimages: core::mem::take(&mut self.hash160_preimages),
            hash256_preimages: core::mem::take(&mut self.hash256_preimages),
            tap_key_sig: self.tap_key_sig.take(),
            tap_script_sigs: core::mem::take(&mut self.tap_script_sigs),
            tap_scripts: core::mem::take(&mut self.tap_scripts),
            tap_key_origins: core::mem::take(&mut self.tap_key_origins),
            tap_internal_key: self.tap_internal_key.take(),
            tap_merkle_root: self.tap_merkle_root.take(),
            #[cfg(feature = "silent-payments")]
            sp_ecdh_shares: core::mem::take(&mut self.sp_ecdh_shares),
            #[cfg(feature = "silent-payments")]
            sp_dleq_proofs: core::mem::take(&mut self.sp_dleq_proofs),
            proprietaries: core::mem::take(&mut self.proprietaries),
            unknowns: core::mem::take(&mut self.unknowns),
        })
    }
}

pub(crate) type InputsDecoder = ExactVecDecoderWith<InputMapDecoder>;
