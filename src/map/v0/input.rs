// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 input map encoder.
//!
//! v0 inputs omit `previous_txid`, `spent_output_index`, `sequence`,
//! `min_time`, and `min_height`, those come from the unsigned transaction.

use bitcoin_consensus_encoding::{CompactSizeEncoder, Encoder, EncoderStatus, IterEncoder};

use crate::consts::{
    PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS, PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_REDEEM_SCRIPT, PSBT_IN_SIGHASH_TYPE, PSBT_IN_TAP_INTERNAL_KEY, PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_MERKLE_ROOT, PSBT_IN_WITNESS_SCRIPT, PSBT_IN_WITNESS_UTXO,
};
use crate::encoding::delegates::{FinalScriptWitnessPair, WitnessUtxoPair};
#[cfg(feature = "silent-payments")]
use crate::encoding::native::DleqPairIter;
#[cfg(feature = "silent-payments")]
use crate::encoding::native::EcdhPairIter;
use crate::encoding::native::{
    Bip32DerivationIter, Hash160Iter, Hash256Iter, PartialSigIter, Ripemd160Iter, ScriptPair,
    SeparatorEncoder, Sha256Iter, SighashPair, TapInternalKeyPair, TapKeyOriginIter, TapKeySigPair,
    TapMerkleRootPair, TapScriptIter, TapScriptSigIter,
};
use crate::encoding::{KeyValueEncoder, PsbtEncode};
use crate::input::Input;
use crate::map::{ProprietaryKeyValueIter, UnknownKeyValueIter};

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
        #[cfg(feature = "silent-payments")]
        {
            if !input.sp_dleq_proofs.is_empty() {
                return State::Dleq(IterEncoder::new(DleqPairIter::new(
                    input.sp_dleq_proofs.iter(),
                )));
            }
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
///
/// Used by [`PsbtV0Encoder`](crate::PsbtV0Encoder) to stream input maps without
/// allocation.
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
