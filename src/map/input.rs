// SPDX-License-Identifier: CC0-1.0

use alloc::boxed::Box;
use alloc::collections::{btree_map, BTreeMap};
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;

use bitcoin::bip32::KeySource;
use bitcoin::blockdata::transaction::{TransactionDecoderError, TxOutDecoderError};
use bitcoin::blockdata::witness::WitnessDecoderError;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::key::{PublicKey, XOnlyPublicKey};
use bitcoin::locktime::absolute;
use bitcoin::sighash::{EcdsaSighashType, NonStandardSighashTypeError, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TapNodeHash};
#[cfg(feature = "silent-payments")]
use bitcoin::CompressedPublicKey;
use bitcoin::{
    ecdsa, taproot, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, ByteVecDecoderError, CompactSizeDecoderError,
    CompactSizeEncoder, Decoder, Decoder2Error, DecoderStatus, Encoder, EncoderStatus,
    ExactVecDecoderWith, IterEncoder, UnexpectedEofError,
};

use crate::consts::{
    PSBT_IN_BIP32_DERIVATION, PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_HASH160, PSBT_IN_HASH256, PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PARTIAL_SIG, PSBT_IN_PREVIOUS_TXID, PSBT_IN_PROPRIETARY, PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, PSBT_IN_REQUIRED_TIME_LOCKTIME, PSBT_IN_RIPEMD160,
    PSBT_IN_SEQUENCE, PSBT_IN_SHA256, PSBT_IN_SIGHASH_TYPE, PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_IN_TAP_INTERNAL_KEY, PSBT_IN_TAP_KEY_SIG, PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_MERKLE_ROOT, PSBT_IN_TAP_SCRIPT_SIG, PSBT_IN_WITNESS_SCRIPT, PSBT_IN_WITNESS_UTXO,
};
#[cfg(feature = "silent-payments")]
use crate::consts::{PSBT_IN_SP_DLEQ, PSBT_IN_SP_ECDH_SHARE};
#[cfg(feature = "silent-payments")]
use crate::dleq::DleqProof;
use crate::encoding::delegates::{
    FinalScriptWitnessPair, NonWitnessUtxoPair, SequencePair, WitnessUtxoPair,
};
use crate::encoding::native::{
    Bip32DerivationIter, Hash160Iter, Hash256Iter, MinHeightPair, MinTimePair, PartialSigIter,
    PreviousTxidPair, Ripemd160Iter, ScriptPair, SeparatorEncoder, Sha256Iter, SighashPair,
    TapInternalKeyPair, TapKeyOriginIter, TapKeySigPair, TapMerkleRootPair, TapScriptIter,
    TapScriptSigIter,
};
#[cfg(feature = "silent-payments")]
use crate::encoding::native::{DleqPairIter, EcdhPairIter};
use crate::encoding::{ExactLenEncoder, KeyValueEncoder, PsbtEncode, ValueDecoder};
use crate::error::{write_err, FundingUtxoError};
use crate::map::Map;
use crate::psbt::{OutputType, SigningAlgorithm};
use crate::raw::{ProprietaryKeyValueIter, UnknownKeyValueIter};
use crate::serialize::Serialize;
use crate::sighash_type::{InvalidSighashTypeError, PsbtSighashType};
use crate::{raw, serialize, SignError};

/// A key-value map for an input of the corresponding index in the unsigned
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Input {
    /// The txid of the previous transaction whose output at `self.spent_output_index` is being spent.
    ///
    /// In other words, the output being spent by this `Input` is:
    ///
    ///  `OutPoint { txid: self.previous_txid, vout: self.spent_output_index }`
    pub previous_txid: Txid,

    /// The index of the output being spent in the transaction with the txid of `self.previous_txid`.
    pub spent_output_index: u32,

    /// The sequence number of this input.
    ///
    /// If omitted, assumed to be the final sequence number ([`Sequence::MAX`]).
    pub sequence: Option<Sequence>,

    /// The minimum Unix timestamp that this input requires to be set as the transaction's lock time.
    pub min_time: Option<absolute::Time>,

    /// The minimum block height that this input requires to be set as the transaction's lock time.
    pub min_height: Option<absolute::Height>,

    /// The non-witness transaction this input spends from. Should only be
    /// `Option::Some` for inputs which spend non-segwit outputs or
    /// if it is unknown whether an input spends a segwit output.
    pub non_witness_utxo: Option<Transaction>,
    /// The transaction output this input spends from. Should only be
    /// `Option::Some` for inputs which spend segwit outputs,
    /// including P2SH embedded ones.
    pub witness_utxo: Option<TxOut>,
    /// A map from public keys to their corresponding signature as would be
    /// pushed to the stack from a scriptSig or witness for a non-taproot inputs.
    pub partial_sigs: BTreeMap<PublicKey, ecdsa::Signature>,
    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<PsbtSighashType>,
    /// The redeem script for this input.
    pub redeem_script: Option<ScriptBuf>,
    /// The witness script for this input.
    pub witness_script: Option<ScriptBuf>,
    /// A map from public keys needed to sign this input to their corresponding
    /// master key fingerprints and derivation paths.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub bip32_derivations: BTreeMap<PublicKey, KeySource>,
    /// The finalized, fully-constructed scriptSig with signatures and any other
    /// scripts necessary for this input to pass validation.
    pub final_script_sig: Option<ScriptBuf>,
    /// The finalized, fully-constructed scriptWitness with signatures and any
    /// other scripts necessary for this input to pass validation.
    pub final_script_witness: Option<Witness>,
    /// TODO: Proof of reserves commitment
    /// RIPEMD160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,
    /// SHA256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,
    /// HSAH160 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,
    /// HAS256 hash to preimage map.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_byte_values"))]
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,
    /// Serialized taproot signature with sighash type for key spend.
    pub tap_key_sig: Option<taproot::Signature>,
    /// Map of `<xonlypubkey>|<leafhash>` with signature.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_script_sigs: BTreeMap<(XOnlyPublicKey, TapLeafHash), taproot::Signature>,
    /// Map of Control blocks to Script version pair.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_scripts: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>,
    /// Map of tap root x only keys to origin info and leaf hashes contained in it.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Taproot Internal key.
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot Merkle root.
    pub tap_merkle_root: Option<TapNodeHash>,

    /// BIP-375: Map from scan public key to per-input ECDH share (33 bytes each).
    #[cfg(feature = "silent-payments")]
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub sp_ecdh_shares: BTreeMap<CompressedPublicKey, CompressedPublicKey>,

    /// BIP-375: Map from scan public key to per-input DLEQ proof (64 bytes each).
    #[cfg(feature = "silent-payments")]
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq"))]
    pub sp_dleq_proofs: BTreeMap<CompressedPublicKey, DleqProof>,

    /// Proprietary key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs for this input.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::btreemap_as_seq_byte_values"))]
    pub unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

impl Input {
    /// Creates a new `Input` that spends the `previous_output`.
    pub fn new(previous_output: &OutPoint) -> Self {
        Self {
            previous_txid: previous_output.txid,
            spent_output_index: previous_output.vout,
            sequence: None,
            min_time: None,
            min_height: None,
            non_witness_utxo: None,
            witness_utxo: None,
            partial_sigs: BTreeMap::new(),
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: BTreeMap::new(),
            final_script_sig: None,
            final_script_witness: None,
            ripemd160_preimages: BTreeMap::new(),
            sha256_preimages: BTreeMap::new(),
            hash160_preimages: BTreeMap::new(),
            hash256_preimages: BTreeMap::new(),
            tap_key_sig: None,
            tap_script_sigs: BTreeMap::new(),
            tap_scripts: BTreeMap::new(),
            tap_key_origins: BTreeMap::new(),
            tap_internal_key: None,
            tap_merkle_root: None,
            #[cfg(feature = "silent-payments")]
            sp_ecdh_shares: BTreeMap::new(),
            #[cfg(feature = "silent-payments")]
            sp_dleq_proofs: BTreeMap::new(),
            proprietaries: BTreeMap::new(),
            unknowns: BTreeMap::new(),
        }
    }

    /// Returns the [`OutputType`] of the spend utxo for this PSBT's input at `input_index`.
    pub fn output_type(&self) -> Result<OutputType, SignError> {
        let utxo = self.funding_utxo()?;
        let spk = utxo.script_pubkey.clone();

        // Anything that is not segwit and is not p2sh is `Bare`.
        if !(spk.is_witness_program() || spk.is_p2sh()) {
            return Ok(OutputType::Bare);
        }

        if spk.is_p2wpkh() {
            return Ok(OutputType::Wpkh);
        }

        if spk.is_p2wsh() {
            return Ok(OutputType::Wsh);
        }

        if spk.is_p2sh() {
            if self.redeem_script.as_ref().map(|s| s.is_p2wpkh()).unwrap_or(false) {
                return Ok(OutputType::ShWpkh);
            }
            if self.redeem_script.as_ref().map(|x| x.is_p2wsh()).unwrap_or(false) {
                return Ok(OutputType::ShWsh);
            }
            return Ok(OutputType::Sh);
        }

        if spk.is_p2tr() {
            return Ok(OutputType::Tr);
        }

        // Something is wrong with the input scriptPubkey or we do not know how to sign
        // because there has been a new softfork that we do not yet support.
        Err(SignError::UnknownOutputType)
    }

    /// Returns the algorithm used to sign this PSBT's input at `input_index`.
    pub fn signing_algorithm(&self) -> Result<SigningAlgorithm, SignError> {
        let output_type = self.output_type()?;
        Ok(output_type.signing_algorithm())
    }

    /// Performs the BIP-174 signer validity checks for the input at `index`.
    pub fn signer_checks(&self) -> Result<(), SignError> {
        let prevout_type = self.output_type();
        let prevout = self.funding_utxo()?;

        // If a witness UTXO is provided, no non-witness signature may be created.
        if self.witness_utxo.is_some() {
            if let Ok(OutputType::Bare) = prevout_type {
                return Err(SignError::NonWitnessSig);
            }
        }

        // If a non-witness UTXO is provided, its hash must match the prevout txid.
        if let Some(ref tx) = self.non_witness_utxo {
            if tx.compute_txid() != self.previous_txid {
                return Err(SignError::NonWitnessUtxoTxidMismatch);
            }
        }

        // If a redeemScript is provided, the scriptPubKey must be for that redeemScript.
        if let Some(ref redeem_script) = self.redeem_script {
            let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
            if prevout.script_pubkey != script_pubkey {
                return Err(SignError::RedeemScriptMismatch);
            }
        }

        // If a witnessScript is provided the redeemScript must be for that witnessScript, and the
        // scriptPubKey must be for that witnessScript.
        if let Some(ref witness_script) = self.witness_script {
            match prevout_type {
                Ok(OutputType::Wsh)
                    if ScriptBuf::new_p2wsh(&witness_script.wscript_hash())
                        != *prevout.script_pubkey =>
                {
                    return Err(SignError::WitnessScriptMismatchWsh);
                }
                Ok(OutputType::ShWsh) =>
                    if let Some(ref redeem_script) = self.redeem_script {
                        if ScriptBuf::new_p2wsh(&witness_script.wscript_hash()) != *redeem_script
                            || ScriptBuf::new_p2sh(&redeem_script.script_hash())
                                != *prevout.script_pubkey
                        {
                            return Err(SignError::WitnessScriptMismatchShWsh);
                        }
                    },
                _ => (),
            }
        }

        // Use provided sighash or DEFAULT for taproot output and ALL for non-taproot outputs.
        let expected_sighash_type = match (self.sighash_type, prevout_type) {
            (None, Ok(OutputType::Tr)) => PsbtSighashType::from(TapSighashType::Default),
            (None, _) => PsbtSighashType::ALL,
            (Some(sighash_type), _) => sighash_type,
        };

        let sighash_mismatches = |sighash: PsbtSighashType| sighash != expected_sighash_type;

        let has_mismatch = self
            .tap_key_sig
            .is_some_and(|sig| sighash_mismatches(PsbtSighashType::from(sig.sighash_type)))
            || self
                .tap_script_sigs
                .values()
                .any(|sig| sighash_mismatches(PsbtSighashType::from(sig.sighash_type)))
            || self
                .partial_sigs
                .values()
                .any(|sig| sighash_mismatches(PsbtSighashType::from(sig.sighash_type)));

        if has_mismatch {
            return Err(SignError::SighashMismatch);
        }

        Ok(())
    }

    /// Returns all key-value pairs for this input map in serialization order.
    pub fn pairs(&self) -> Vec<raw::Pair> { Map::get_pairs(self) }

    /// Creates a new finalized input.
    ///
    /// Note the `Witness` is not optional because `miniscript` returns an empty `Witness` in the
    /// case that this is a legacy input.
    ///
    /// The `final_script_sig` and `final_script_witness` should come from `miniscript`.
    #[cfg(feature = "miniscript")]
    pub(crate) fn finalize(
        &self,
        final_script_sig: ScriptBuf,
        final_script_witness: Witness,
    ) -> Result<Self, FinalizeError> {
        debug_assert!(self.has_funding_utxo());

        let mut ret = Self {
            previous_txid: self.previous_txid,
            spent_output_index: self.spent_output_index,
            non_witness_utxo: self.non_witness_utxo.clone(),
            witness_utxo: self.witness_utxo.clone(),

            // Set below.
            final_script_sig: None,
            final_script_witness: None,

            // Preserve the fields required to reconstruct the unsigned transaction,
            // clearing them would change the transaction the Extractor produces.
            sequence: self.sequence,
            min_time: self.min_time,
            min_height: self.min_height,
            partial_sigs: BTreeMap::new(),
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivations: BTreeMap::new(),
            ripemd160_preimages: BTreeMap::new(),
            sha256_preimages: BTreeMap::new(),
            hash160_preimages: BTreeMap::new(),
            hash256_preimages: BTreeMap::new(),
            tap_key_sig: None,
            tap_script_sigs: BTreeMap::new(),
            tap_scripts: BTreeMap::new(),
            tap_key_origins: BTreeMap::new(),
            tap_internal_key: None,
            tap_merkle_root: None,
            // BIP-375 has the transaction extractor verify silent payment output
            // scripts against the ECDH shares and DLEQ proofs. The extractor runs
            // after the finalizer, so they must survive.
            #[cfg(feature = "silent-payments")]
            sp_ecdh_shares: self.sp_ecdh_shares.clone(),
            #[cfg(feature = "silent-payments")]
            sp_dleq_proofs: self.sp_dleq_proofs.clone(),
            // BIP-174: "All other data except the UTXO and unknown fields (including
            // PSBT_IN_PROPRIETARY fields the Input Finalizer does not understand) in
            // the input key-value map should be cleared from the PSBT." Retain all
            // proprietary and unknown fields.
            proprietaries: self.proprietaries.clone(),
            unknowns: self.unknowns.clone(),
        };

        // TODO: These errors should only trigger if there are bugs in this crate or miniscript.
        // Is there an infallible way to do this?
        if self.witness_utxo.is_some() {
            if final_script_witness.is_empty() {
                return Err(FinalizeError::EmptyWitness);
            }
            ret.final_script_sig = Some(final_script_sig);
            ret.final_script_witness = Some(final_script_witness);
        } else {
            // TODO: Any checks should do here?
            ret.final_script_sig = Some(final_script_sig);
        }

        Ok(ret)
    }

    // TODO: Work out if this is in line with bip-370
    #[cfg(feature = "miniscript")]
    pub(crate) fn lock_time(&self) -> absolute::LockTime {
        match (self.min_height, self.min_time) {
            // If we have both, bip says use height.
            (Some(height), Some(_)) => height.into(),
            (Some(height), None) => height.into(),
            (None, Some(time)) => time.into(),
            // TODO: Check this is correct.
            (None, None) => absolute::LockTime::ZERO,
        }
    }

    pub(crate) fn has_lock_time(&self) -> bool {
        self.min_time.is_some() || self.min_height.is_some()
    }

    pub(crate) fn is_satisfied_with_height_based_lock_time(&self) -> bool {
        self.requires_height_based_lock_time()
            || self.min_time.is_some() && self.min_height.is_some()
            || self.min_time.is_none() && self.min_height.is_none()
    }

    pub(crate) fn requires_time_based_lock_time(&self) -> bool {
        self.min_time.is_some() && self.min_height.is_none()
    }

    pub(crate) fn requires_height_based_lock_time(&self) -> bool {
        self.min_height.is_some() && self.min_time.is_none()
    }

    /// Constructs a [`TxIn`] for this input, excluding any signature material.
    pub(crate) fn unsigned_tx_in(&self) -> TxIn {
        TxIn {
            previous_output: self.out_point(),
            script_sig: ScriptBuf::default(),
            sequence: self.sequence.unwrap_or(Sequence::MAX),
            witness: Witness::default(),
        }
    }

    /// Constructs a signed [`TxIn`] for this input.
    ///
    /// Should only be called on a finalized PSBT.
    pub(crate) fn signed_tx_in(&self) -> TxIn {
        debug_assert!(self.is_finalized());

        // Inputs spending non-witness (legacy) outputs have no final script witness, and vice
        // versa for the final script sig of witness spends (see BIP-174 "Input Finalizer").
        let script_sig = self.final_script_sig.clone().unwrap_or_default();
        let witness = self.final_script_witness.clone().unwrap_or_default();

        TxIn {
            previous_output: self.out_point(),
            script_sig,
            sequence: self.sequence.unwrap_or(Sequence::MAX),
            witness,
        }
    }

    #[cfg(feature = "miniscript")]
    pub(crate) fn has_funding_utxo(&self) -> bool { self.funding_utxo().is_ok() }

    /// Returns a reference to the funding utxo for this input.
    pub fn funding_utxo(&self) -> Result<&TxOut, FundingUtxoError> {
        if let Some(ref utxo) = self.witness_utxo {
            Ok(utxo)
        } else if let Some(ref tx) = self.non_witness_utxo {
            let vout = self.spent_output_index as usize;
            tx.output.get(vout).ok_or(FundingUtxoError::OutOfBounds { vout, len: tx.output.len() })
        } else {
            Err(FundingUtxoError::MissingUtxo)
        }
    }

    /// Returns true if this input has been finalized.
    ///
    /// > It checks whether all inputs have complete scriptSigs and scriptWitnesses by checking for
    /// > the presence of 0x07 Finalized scriptSig and 0x08 Finalized scriptWitness typed records.
    ///
    /// Only one of the two records is required. An input spending a legacy output has no final
    /// script witness, and an input with a final script witness may have no final script sig.
    pub fn is_finalized(&self) -> bool {
        self.final_script_sig.is_some() || self.final_script_witness.is_some()
    }

    /// TODO: Use this.
    #[allow(dead_code)]
    fn has_sig_data(&self) -> bool {
        !(self.partial_sigs.is_empty()
            && self.tap_key_sig.is_none()
            && self.tap_script_sigs.is_empty())
    }

    fn out_point(&self) -> OutPoint {
        OutPoint { txid: self.previous_txid, vout: self.spent_output_index }
    }

    /// Obtains the [`EcdsaSighashType`] for this input if one is specified. If no sighash type is
    /// specified, returns [`EcdsaSighashType::All`].
    ///
    /// # Errors
    ///
    /// If the `sighash_type` field is set to a non-standard ECDSA sighash value.
    pub fn ecdsa_hash_ty(&self) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        self.sighash_type
            .map(|sighash_type| sighash_type.ecdsa_hash_ty())
            .unwrap_or(Ok(EcdsaSighashType::All))
    }

    /// Obtains the [`TapSighashType`] for this input if one is specified. If no sighash type is
    /// specified, returns [`TapSighashType::Default`].
    ///
    /// # Errors
    ///
    /// If the `sighash_type` field is set to an invalid Taproot sighash value.
    pub fn taproot_hash_ty(&self) -> Result<TapSighashType, InvalidSighashTypeError> {
        self.sighash_type
            .map(|sighash_type| sighash_type.taproot_hash_ty())
            .unwrap_or(Ok(TapSighashType::Default))
    }

    /// Combines this [`Input`] with `other`.
    pub fn combine(&mut self, other: Self) -> Result<(), CombineError> {
        if self.previous_txid != other.previous_txid {
            return Err(CombineError::PreviousTxidMismatch {
                this: self.previous_txid,
                that: other.previous_txid,
            });
        }

        if self.spent_output_index != other.spent_output_index {
            return Err(CombineError::SpentOutputIndexMismatch {
                this: self.spent_output_index,
                that: other.spent_output_index,
            });
        }

        // TODO: Should we keep any value other than Sequence::MAX since it is default?
        v2_combine_option!(sequence, self, other);
        v2_combine_option!(min_time, self, other);
        v2_combine_option!(min_height, self, other);
        v2_combine_option!(non_witness_utxo, self, other);

        // TODO: Copied from v0, confirm this is correct.
        if let (&None, Some(witness_utxo)) = (&self.witness_utxo, other.witness_utxo) {
            self.witness_utxo = Some(witness_utxo);
            self.non_witness_utxo = None; // Clear out any non-witness UTXO when we set a witness one
        }

        v2_combine_map!(partial_sigs, self, other);
        // TODO: Why do we not combine sighash_type?
        v2_combine_option!(redeem_script, self, other);
        v2_combine_option!(witness_script, self, other);
        v2_combine_map!(bip32_derivations, self, other);
        v2_combine_option!(final_script_sig, self, other);
        v2_combine_option!(final_script_witness, self, other);
        v2_combine_map!(ripemd160_preimages, self, other);
        v2_combine_map!(sha256_preimages, self, other);
        v2_combine_map!(hash160_preimages, self, other);
        v2_combine_map!(hash256_preimages, self, other);
        v2_combine_option!(tap_key_sig, self, other);
        v2_combine_map!(tap_script_sigs, self, other);
        v2_combine_map!(tap_scripts, self, other);
        v2_combine_map!(tap_key_origins, self, other);
        v2_combine_option!(tap_internal_key, self, other);
        v2_combine_option!(tap_merkle_root, self, other);
        #[cfg(feature = "silent-payments")]
        v2_combine_map!(sp_ecdh_shares, self, other);
        #[cfg(feature = "silent-payments")]
        v2_combine_map!(sp_dleq_proofs, self, other);
        v2_combine_map!(proprietaries, self, other);
        v2_combine_map!(unknowns, self, other);

        Ok(())
    }
}

/// Decoder for a single PSBT input map.
///
/// Incrementally decodes `<keypair>* <PSBT_SEPARATOR>`.
#[derive(Debug)]
pub struct InputDecoder {
    stage: DecoderStage,
    previous_txid: Option<Txid>,
    spent_output_index: Option<u32>,
    sequence: Option<Sequence>,
    min_time: Option<absolute::Time>,
    min_height: Option<absolute::Height>,
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
    proprietaries: BTreeMap<raw::ProprietaryKey, Vec<u8>>,
    unknowns: BTreeMap<raw::Key, Vec<u8>>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum DecoderStage {
    DecodingSeparator,
    DecodingKey(raw::KeyDecoder),
    /// Decoding the previous txid.
    DecodingPreviousTxid {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<32>>,
    },
    /// Decoding the spent output index.
    DecodingOutputIndex {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<4>>,
    },
    /// Decoding a sequence value.
    DecodingSequence {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<4>>,
    },
    /// Decoding a minimum time locktime value.
    DecodingMinTime {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<4>>,
    },
    /// Decoding a minimum height locktime value.
    DecodingMinHeight {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<4>>,
    },
    /// Decoding a non-witness UTXO (full transaction).
    DecodingNonWitnessUtxo {
        key: raw::Key,
        decoder: ValueDecoder<<Transaction as crate::encoding::PsbtDecode>::Decoder>,
    },
    /// Decoding a witness UTXO (TxOut).
    DecodingWitnessUtxo {
        key: raw::Key,
        decoder: ValueDecoder<<TxOut as crate::encoding::PsbtDecode>::Decoder>,
    },
    /// Decoding a sighash type.
    DecodingSighashType {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<4>>,
    },
    /// Decoding a redeem script.
    DecodingRedeemScript {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a witness script.
    DecodingWitnessScript {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a final scriptSig.
    DecodingFinalScriptSig {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a final scriptWitness.
    DecodingFinalScriptWitness {
        key: raw::Key,
        decoder: ValueDecoder<<Witness as crate::encoding::PsbtDecode>::Decoder>,
    },
    /// Decoding a taproot key spend signature.
    DecodingTapKeySig {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a taproot internal key.
    DecodingTapInternalKey {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<32>>,
    },
    /// Decoding a taproot merkle root.
    DecodingTapMerkleRoot {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<32>>,
    },
    /// Decoding a partial signature.
    DecodingPartialSig {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a BIP32 derivation.
    DecodingBip32Derivation {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a RIPEMD160 preimage.
    DecodingRipemd160 {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a SHA256 preimage.
    DecodingSha256 {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a HASH160 preimage.
    DecodingHash160 {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a HASH256 preimage.
    DecodingHash256 {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a taproot script signature.
    DecodingTapScriptSig {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a taproot leaf script.
    DecodingTapLeafScript {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a taproot BIP32 derivation.
    DecodingTapBip32Derivation {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding a proprietary value.
    DecodingProprietary {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    /// Decoding an unknown value.
    DecodingUnknown {
        key: raw::Key,
        decoder: ByteVecDecoder,
    },
    #[cfg(feature = "silent-payments")]
    /// Decoding an ECDH share for silent payments.
    DecodingSpEcdhShare {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<33>>,
    },
    #[cfg(feature = "silent-payments")]
    /// Decoding a DLEQ proof for silent payments.
    DecodingSpDleqProof {
        key: raw::Key,
        decoder: ValueDecoder<ArrayDecoder<64>>,
    },
    /// The end-of-map separator has been reached.
    Done(Input),
    /// The decoder has entered a non-recoverable error state.
    Errored,
}

impl DecoderStage {
    /// Select the appropriate value-decoding stage based on the decoded key.
    fn from_key(key: raw::Key) -> Result<Self, DecodeError> {
        match key.type_value {
            PSBT_IN_PREVIOUS_TXID =>
                Ok(Self::DecodingPreviousTxid { key, decoder: ValueDecoder::default() }),
            PSBT_IN_OUTPUT_INDEX =>
                Ok(Self::DecodingOutputIndex { key, decoder: ValueDecoder::default() }),
            PSBT_IN_SEQUENCE =>
                Ok(Self::DecodingSequence { key, decoder: ValueDecoder::default() }),
            PSBT_IN_REQUIRED_TIME_LOCKTIME =>
                Ok(Self::DecodingMinTime { key, decoder: ValueDecoder::default() }),
            PSBT_IN_REQUIRED_HEIGHT_LOCKTIME =>
                Ok(Self::DecodingMinHeight { key, decoder: ValueDecoder::default() }),
            PSBT_IN_NON_WITNESS_UTXO =>
                Ok(Self::DecodingNonWitnessUtxo { key, decoder: ValueDecoder::default() }),
            PSBT_IN_WITNESS_UTXO =>
                Ok(Self::DecodingWitnessUtxo { key, decoder: ValueDecoder::default() }),
            PSBT_IN_SIGHASH_TYPE =>
                Ok(Self::DecodingSighashType { key, decoder: ValueDecoder::default() }),
            PSBT_IN_REDEEM_SCRIPT =>
                Ok(Self::DecodingRedeemScript { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_WITNESS_SCRIPT =>
                Ok(Self::DecodingWitnessScript { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_FINAL_SCRIPTSIG =>
                Ok(Self::DecodingFinalScriptSig { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_FINAL_SCRIPTWITNESS =>
                Ok(Self::DecodingFinalScriptWitness { key, decoder: ValueDecoder::default() }),
            PSBT_IN_TAP_KEY_SIG =>
                Ok(Self::DecodingTapKeySig { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_TAP_INTERNAL_KEY =>
                Ok(Self::DecodingTapInternalKey { key, decoder: ValueDecoder::default() }),
            PSBT_IN_TAP_MERKLE_ROOT =>
                Ok(Self::DecodingTapMerkleRoot { key, decoder: ValueDecoder::default() }),
            PSBT_IN_PARTIAL_SIG =>
                Ok(Self::DecodingPartialSig { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_BIP32_DERIVATION =>
                Ok(Self::DecodingBip32Derivation { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_RIPEMD160 =>
                Ok(Self::DecodingRipemd160 { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_SHA256 => Ok(Self::DecodingSha256 { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_HASH160 => Ok(Self::DecodingHash160 { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_HASH256 => Ok(Self::DecodingHash256 { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_TAP_SCRIPT_SIG =>
                Ok(Self::DecodingTapScriptSig { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_TAP_LEAF_SCRIPT =>
                Ok(Self::DecodingTapLeafScript { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_TAP_BIP32_DERIVATION =>
                Ok(Self::DecodingTapBip32Derivation { key, decoder: ByteVecDecoder::new() }),
            PSBT_IN_PROPRIETARY =>
                Ok(Self::DecodingProprietary { key, decoder: ByteVecDecoder::new() }),
            #[cfg(feature = "silent-payments")]
            PSBT_IN_SP_ECDH_SHARE =>
                Ok(Self::DecodingSpEcdhShare { key, decoder: ValueDecoder::default() }),
            #[cfg(feature = "silent-payments")]
            PSBT_IN_SP_DLEQ =>
                Ok(Self::DecodingSpDleqProof { key, decoder: ValueDecoder::default() }),
            _ => Ok(Self::DecodingUnknown { key, decoder: ByteVecDecoder::new() }),
        }
    }
}

impl Default for InputDecoder {
    fn default() -> Self {
        Self {
            stage: DecoderStage::DecodingSeparator,
            previous_txid: None,
            spent_output_index: None,
            sequence: None,
            min_time: None,
            min_height: None,
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

impl crate::encoding::PsbtDecode for Input {
    type Decoder = InputDecoder;
}

impl Decoder for InputDecoder {
    type Output = Input;
    type Error = DecodeError;

    #[allow(clippy::too_many_lines)] // State machine.
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
                        let previous_txid =
                            self.previous_txid.take().ok_or(DecodeError::MissingPreviousTxid)?;
                        let spent_output_index = self
                            .spent_output_index
                            .take()
                            .ok_or(DecodeError::MissingSpentOutputIndex)?;
                        #[cfg(feature = "silent-payments")]
                        {
                            let has_ecdh = !self.sp_ecdh_shares.is_empty();
                            let has_dleq = !self.sp_dleq_proofs.is_empty();
                            if has_ecdh != has_dleq {
                                return Err(DecodeError::FieldMismatch);
                            }
                        }
                        self.stage = DecoderStage::Done(Input {
                            previous_txid,
                            spent_output_index,
                            sequence: self.sequence.take(),
                            min_time: self.min_time.take(),
                            min_height: self.min_height.take(),
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
                DecoderStage::DecodingPreviousTxid { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::PreviousTxid(e)),
                    })?,
                DecoderStage::DecodingTapInternalKey { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::TapInternalKey(e)),
                    })?,
                DecoderStage::DecodingTapMerkleRoot { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::TapMerkleRoot(e)),
                    })?,
                DecoderStage::DecodingOutputIndex { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::OutputIndex(e)),
                    })?,
                DecoderStage::DecodingSighashType { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::SighashType(e)),
                    })?,
                DecoderStage::DecodingSequence { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::Sequence(e)),
                    })?,
                DecoderStage::DecodingMinTime { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::MinTime(e)),
                    })?,
                DecoderStage::DecodingMinHeight { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::MinHeight(e)),
                    })?,
                DecoderStage::DecodingNonWitnessUtxo { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::NonWitnessUtxo(e)),
                    })?,
                DecoderStage::DecodingWitnessUtxo { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::WitnessUtxo(e)),
                    })?,
                DecoderStage::DecodingFinalScriptWitness { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::FinalScriptWitness(e)),
                    })?,
                DecoderStage::DecodingRedeemScript { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::RedeemScript(e)))?,
                DecoderStage::DecodingWitnessScript { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::WitnessScript(e)))?,
                DecoderStage::DecodingFinalScriptSig { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::FinalScriptSig(e)))?,
                DecoderStage::DecodingTapKeySig { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::TapKeySig(e)))?,
                DecoderStage::DecodingPartialSig { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::PartialSig(e)))?,
                DecoderStage::DecodingBip32Derivation { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::Bip32Derivation(e)))?,
                DecoderStage::DecodingTapBip32Derivation { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::TapBip32Derivation(e))
                    })?,
                DecoderStage::DecodingRipemd160 { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::Ripemd160Preimage(e))
                    })?,
                DecoderStage::DecodingSha256 { ref mut decoder, .. } =>
                    decoder.push_bytes(bytes).map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::Sha256Preimage(e))
                    })?,
                DecoderStage::DecodingHash160 { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::Hash160Preimage(e)))?,
                DecoderStage::DecodingHash256 { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::Hash256Preimage(e)))?,
                DecoderStage::DecodingTapScriptSig { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::TapScriptSig(e)))?,
                DecoderStage::DecodingTapLeafScript { ref mut decoder, .. } => decoder
                    .push_bytes(bytes)
                    .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::TapLeafScript(e)))?,
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
                DecoderStage::DecodingPreviousTxid { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::PreviousTxid(e)),
                    })?;
                    if self.previous_txid.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.previous_txid =
                        Some(Txid::from_slice(&bytes).map_err(|e| {
                            DecodeError::DeserPair(serialize::Error::InvalidHash(e))
                        })?);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingOutputIndex { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::OutputIndex(e)),
                    })?;
                    if self.spent_output_index.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.spent_output_index = Some(u32::from_le_bytes(bytes));
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingSequence { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::Sequence(e)),
                    })?;
                    if self.sequence.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.sequence = Some(Sequence(u32::from_le_bytes(bytes)));
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingMinTime { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::MinTime(e)),
                    })?;
                    if self.min_time.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.min_time =
                        Some(absolute::Time::from_consensus(u32::from_le_bytes(bytes)).map_err(
                            |_| DecodeError::ValueDecode(ValueDecodeError::InvalidMinTime),
                        )?);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingMinHeight { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::MinHeight(e)),
                    })?;
                    if self.min_height.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.min_height =
                        Some(absolute::Height::from_consensus(u32::from_le_bytes(bytes)).map_err(
                            |_| DecodeError::ValueDecode(ValueDecodeError::InvalidMinHeight),
                        )?);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingNonWitnessUtxo { key, decoder } => {
                    let (_, tx) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::NonWitnessUtxo(e)),
                    })?;
                    if self.non_witness_utxo.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.non_witness_utxo = Some(tx);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingWitnessUtxo { key, decoder } => {
                    let (_, txout) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::WitnessUtxo(e)),
                    })?;
                    if self.witness_utxo.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.witness_utxo = Some(txout);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingSighashType { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::SighashType(e)),
                    })?;
                    if self.sighash_type.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.sighash_type = Some(PsbtSighashType { inner: u32::from_le_bytes(bytes) });
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingRedeemScript { key, decoder } => {
                    let value = decoder
                        .end()
                        .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::RedeemScript(e)))?;
                    if self.redeem_script.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.redeem_script = Some(ScriptBuf::from(value));
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingWitnessScript { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::WitnessScript(e))
                    })?;
                    if self.witness_script.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.witness_script = Some(ScriptBuf::from(value));
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingFinalScriptSig { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::FinalScriptSig(e))
                    })?;
                    if self.final_script_sig.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.final_script_sig = Some(ScriptBuf::from(value));
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingFinalScriptWitness { key, decoder } => {
                    let (_, witness) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::FinalScriptWitness(e)),
                    })?;
                    if self.final_script_witness.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.final_script_witness = Some(witness);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTapKeySig { key, decoder } => {
                    let value = decoder
                        .end()
                        .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::TapKeySig(e)))?;
                    if self.tap_key_sig.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.tap_key_sig =
                        Some(taproot::Signature::from_slice(&value).map_err(|_e| {
                            DecodeError::ValueDecode(ValueDecodeError::InvalidTaprootSignature)
                        })?);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTapInternalKey { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::TapInternalKey(e)),
                    })?;
                    if self.tap_internal_key.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.tap_internal_key = Some(
                        XOnlyPublicKey::from_slice(&bytes)
                            .map_err(|_| InsertPairError::ValueWrongLength(32, 32))?,
                    );
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTapMerkleRoot { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::TapMerkleRoot(e)),
                    })?;
                    if self.tap_merkle_root.is_some() {
                        return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key)));
                    }
                    self.tap_merkle_root =
                        Some(TapNodeHash::from_slice(&bytes).map_err(|e| {
                            DecodeError::DeserPair(serialize::Error::InvalidHash(e))
                        })?);
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingPartialSig { key, decoder } => {
                    let value = decoder
                        .end()
                        .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::PartialSig(e)))?;
                    let pk = PublicKey::from_slice(&key.key).map_err(|e| {
                        DecodeError::DeserPair(serialize::Error::InvalidPublicKey(e))
                    })?;
                    let sig = ecdsa::Signature::from_slice(&value).map_err(|e| {
                        DecodeError::DeserPair(serialize::Error::InvalidEcdsaSignature(e))
                    })?;
                    match self.partial_sigs.entry(pk) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(sig);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingBip32Derivation { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::Bip32Derivation(e))
                    })?;
                    use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
                    let fprint =
                        Fingerprint::from(<[u8; 4]>::try_from(&value[..4]).expect("4 bytes"));
                    let mut dpath: Vec<ChildNumber> = Default::default();
                    for chunk in value[4..].chunks_exact(4) {
                        let index = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
                        dpath.push(ChildNumber::from(index));
                    }
                    let ks = (fprint, DerivationPath::from(dpath));
                    let pk = PublicKey::from_slice(&key.key).map_err(|e| {
                        DecodeError::DeserPair(serialize::Error::InvalidPublicKey(e))
                    })?;
                    match self.bip32_derivations.entry(pk) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(ks);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingRipemd160 { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::Ripemd160Preimage(e))
                    })?;
                    let hash = ripemd160::Hash::from_slice(&key.key)
                        .map_err(|e| DecodeError::DeserPair(serialize::Error::InvalidHash(e)))?;
                    match self.ripemd160_preimages.entry(hash) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingSha256 { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::Sha256Preimage(e))
                    })?;
                    let hash = sha256::Hash::from_slice(&key.key)
                        .map_err(|e| DecodeError::DeserPair(serialize::Error::InvalidHash(e)))?;
                    match self.sha256_preimages.entry(hash) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingHash160 { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::Hash160Preimage(e))
                    })?;
                    let hash = hash160::Hash::from_slice(&key.key)
                        .map_err(|e| DecodeError::DeserPair(serialize::Error::InvalidHash(e)))?;
                    match self.hash160_preimages.entry(hash) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingHash256 { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::Hash256Preimage(e))
                    })?;
                    let hash = sha256d::Hash::from_slice(&key.key)
                        .map_err(|e| DecodeError::DeserPair(serialize::Error::InvalidHash(e)))?;
                    match self.hash256_preimages.entry(hash) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTapScriptSig { key, decoder } => {
                    let value = decoder
                        .end()
                        .map_err(|e| DecodeError::ValueDecode(ValueDecodeError::TapScriptSig(e)))?;
                    if key.key.len() != 64 {
                        return Err(DecodeError::InsertPair(InsertPairError::KeyWrongLength(
                            key.key.len(),
                            64,
                        )));
                    }
                    let xonly = XOnlyPublicKey::from_slice(&key.key[..32])
                        .map_err(|_| InsertPairError::KeyWrongLength(32, 32))?;
                    let leaf_hash = TapLeafHash::from_slice(&key.key[32..64])
                        .map_err(|_| InsertPairError::KeyWrongLength(32, 32))?;
                    let sig = taproot::Signature::from_slice(&value).map_err(|_e| {
                        DecodeError::ValueDecode(ValueDecodeError::InvalidTaprootSignature)
                    })?;
                    match self.tap_script_sigs.entry((xonly, leaf_hash)) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(sig);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTapLeafScript { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::TapLeafScript(e))
                    })?;
                    let cb = ControlBlock::decode(&key.key).map_err(|_| {
                        DecodeError::ValueDecode(ValueDecodeError::InvalidControlBlock)
                    })?;
                    if value.is_empty() {
                        return Err(DecodeError::InsertPair(InsertPairError::ValueWrongLength(
                            0, 1,
                        )));
                    }
                    let last = value.len() - 1;
                    let script = ScriptBuf::from_bytes(value[..last].to_vec());
                    let ver = LeafVersion::from_consensus(value[last]).map_err(|_| {
                        DecodeError::ValueDecode(ValueDecodeError::InvalidLeafVersion)
                    })?;
                    match self.tap_scripts.entry(cb) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert((script, ver));
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingTapBip32Derivation { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::TapBip32Derivation(e))
                    })?;
                    let pair = if value.is_empty() {
                        use bitcoin::bip32::{DerivationPath, Fingerprint};
                        let fprint =
                            Fingerprint::from(<[u8; 4]>::try_from(&value[..]).unwrap_or_default());
                        (vec![], (fprint, DerivationPath::default()))
                    } else {
                        use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
                        let count = value[0] as usize;
                        let hash_end = 1 + count * 32;
                        let leaf_hashes: Vec<TapLeafHash> = value[1..hash_end]
                            .chunks_exact(32)
                            .map(|chunk| TapLeafHash::from_slice(chunk).expect("32 bytes"))
                            .collect();
                        let fprint = Fingerprint::from(
                            <[u8; 4]>::try_from(&value[hash_end..hash_end + 4]).expect("4 bytes"),
                        );
                        let mut dpath: Vec<ChildNumber> = Default::default();
                        for chunk in value[hash_end + 4..].chunks_exact(4) {
                            let index = u32::from_le_bytes(chunk.try_into().expect("4 bytes"));
                            dpath.push(ChildNumber::from(index));
                        }
                        let ks = (fprint, DerivationPath::from(dpath));
                        (leaf_hashes, ks)
                    };
                    let xonly = XOnlyPublicKey::from_slice(&key.key)
                        .map_err(|_| InsertPairError::KeyWrongLength(key.key.len(), 32))?;
                    match self.tap_key_origins.entry(xonly) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(pair);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::DecodingProprietary { key, decoder } => {
                    let value = decoder.end().map_err(|e| {
                        DecodeError::ValueDecode(ValueDecodeError::ProprietaryValue(e))
                    })?;
                    let pk = raw::ProprietaryKey::try_from(key.clone())
                        .map_err(InsertPairError::Deser)?;
                    match self.proprietaries.entry(pk) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(value);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
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
                        btree_map::Entry::Occupied(k) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(
                                k.key().clone(),
                            ))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpEcdhShare { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::SpEcdh(e)),
                    })?;
                    if key.key.is_empty() {
                        return Err(DecodeError::InsertPair(InsertPairError::InvalidKeyDataEmpty(
                            key,
                        )));
                    }
                    let scan_key = CompressedPublicKey::from_slice(&key.key)
                        .map_err(|_| InsertPairError::KeyWrongLength(key.key.len(), 33))?;
                    let share = CompressedPublicKey::from_slice(&bytes)
                        .map_err(|_| InsertPairError::ValueWrongLength(33, 33))?;
                    match self.sp_ecdh_shares.entry(scan_key) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(share);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                #[cfg(feature = "silent-payments")]
                DecoderStage::DecodingSpDleqProof { key, decoder } => {
                    let (_, bytes) = decoder.end().map_err(|e| match e {
                        Decoder2Error::First(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::LengthPrefix(e)),
                        Decoder2Error::Second(e) =>
                            DecodeError::ValueDecode(ValueDecodeError::SpDleq(e)),
                    })?;
                    if key.key.is_empty() {
                        return Err(DecodeError::InsertPair(InsertPairError::InvalidKeyDataEmpty(
                            key,
                        )));
                    }
                    let scan_key = CompressedPublicKey::from_slice(&key.key)
                        .map_err(|_| InsertPairError::KeyWrongLength(key.key.len(), 33))?;
                    let proof = DleqProof::try_from(bytes.as_slice())
                        .map_err(|_| InsertPairError::ValueWrongLength(64, 64))?;
                    match self.sp_dleq_proofs.entry(scan_key) {
                        btree_map::Entry::Vacant(e) => {
                            e.insert(proof);
                        }
                        btree_map::Entry::Occupied(_) =>
                            return Err(DecodeError::InsertPair(InsertPairError::DuplicateKey(key))),
                    }
                    self.stage = DecoderStage::DecodingSeparator;
                }
                DecoderStage::Done(input) => {
                    self.stage = DecoderStage::Done(input);
                    return Ok(DecoderStatus::Ready);
                }
                DecoderStage::Errored => unreachable!(),
                DecoderStage::DecodingSeparator => unreachable!(),
            }
        }
    }

    fn end(self) -> Result<Input, Self::Error> {
        match self.stage {
            DecoderStage::Done(input) => {
                if let Some(ref tx) = input.non_witness_utxo {
                    let txid = tx.compute_txid();
                    if txid != input.previous_txid {
                        return Err(DecodeError::IncorrectNonWitnessUtxo {
                            previous_txid: input.previous_txid,
                            non_witness_utxo_txid: txid,
                        });
                    }
                }
                Ok(input)
            }
            _ => Err(DecodeError::EarlyEnd),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            DecoderStage::DecodingSeparator => 1,
            DecoderStage::DecodingKey(d) => d.read_limit(),
            DecoderStage::DecodingPreviousTxid { decoder, .. }
            | DecoderStage::DecodingTapInternalKey { decoder, .. }
            | DecoderStage::DecodingTapMerkleRoot { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingOutputIndex { decoder, .. }
            | DecoderStage::DecodingSighashType { decoder, .. }
            | DecoderStage::DecodingSequence { decoder, .. }
            | DecoderStage::DecodingMinTime { decoder, .. }
            | DecoderStage::DecodingMinHeight { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingNonWitnessUtxo { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingWitnessUtxo { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingFinalScriptWitness { decoder, .. } => decoder.read_limit(),
            DecoderStage::DecodingRedeemScript { decoder, .. }
            | DecoderStage::DecodingWitnessScript { decoder, .. }
            | DecoderStage::DecodingFinalScriptSig { decoder, .. }
            | DecoderStage::DecodingTapKeySig { decoder, .. }
            | DecoderStage::DecodingPartialSig { decoder, .. }
            | DecoderStage::DecodingBip32Derivation { decoder, .. }
            | DecoderStage::DecodingTapBip32Derivation { decoder, .. }
            | DecoderStage::DecodingRipemd160 { decoder, .. }
            | DecoderStage::DecodingSha256 { decoder, .. }
            | DecoderStage::DecodingHash160 { decoder, .. }
            | DecoderStage::DecodingHash256 { decoder, .. }
            | DecoderStage::DecodingTapScriptSig { decoder, .. }
            | DecoderStage::DecodingTapLeafScript { decoder, .. }
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

/// Decodes a sequence of input maps, one per input.
pub(crate) type InputsDecoder = ExactVecDecoderWith<InputDecoder>;

type OutputIndexPair = KeyValueEncoder<CompactSizeEncoder, ArrayEncoder<4>>;

/// State of the input map encoder, one key-value pair per variant.
enum EncoderState<'e> {
    PreviousTxid(PreviousTxidPair<'e>),
    OutputIndex(OutputIndexPair),
    Sequence(SequencePair<'e>),
    MinTime(MinTimePair<'e>),
    MinHeight(MinHeightPair<'e>),
    NonWitnessUtxo(NonWitnessUtxoPair<'e>),
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
    #[cfg(feature = "silent-payments")]
    Ecdh(IterEncoder<EcdhPairIter<'e>>),
    #[cfg(feature = "silent-payments")]
    Dleq(IterEncoder<DleqPairIter<'e>>),
    Proprietaries(IterEncoder<ProprietaryKeyValueIter<'e>>),
    Unknowns(IterEncoder<UnknownKeyValueIter<'e>>),
    Separator(SeparatorEncoder),
}

/// Encoder for a PSBT input map.
///
/// Walks the map's fields in canonical order without materializing raw `Pair` buffers.
pub struct InputMapEncoder<'e> {
    input: &'e Input,
    state: EncoderState<'e>,
}

impl<'e> InputMapEncoder<'e> {
    fn new(input: &'e Input) -> Self {
        let state = EncoderState::PreviousTxid(KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_IN_PREVIOUS_TXID),
            input.previous_txid.psbt_encoder(),
        ));
        Self { input, state }
    }

    /// Constructs the next state in field order after the current one, if any.
    fn next_state(&self) -> Option<EncoderState<'e>> {
        match &self.state {
            EncoderState::PreviousTxid(_) =>
                Some(EncoderState::OutputIndex(self.output_index_pair())),
            EncoderState::OutputIndex(_) => self.sequence_state(),
            EncoderState::Sequence(_) => self.min_time_state(),
            EncoderState::MinTime(_) => self.min_height_state(),
            EncoderState::MinHeight(_) => self.non_witness_utxo_state(),
            EncoderState::NonWitnessUtxo(_) => self.witness_utxo_state(),
            EncoderState::WitnessUtxo(_) => Some(self.partial_sigs_state()),
            EncoderState::PartialSigs(_) => self.sighash_type_state(),
            EncoderState::SighashType(_) => self.redeem_script_state(),
            EncoderState::RedeemScript(_) => self.witness_script_state(),
            EncoderState::WitnessScript(_) => Some(self.bip32_derivations_state()),
            EncoderState::Bip32Derivations(_) => self.final_script_sig_state(),
            EncoderState::FinalScriptSig(_) => self.final_script_witness_state(),
            EncoderState::FinalScriptWitness(_) => Some(self.ripemd160_state()),
            EncoderState::Ripemd160Preimages(_) => Some(self.sha256_state()),
            EncoderState::Sha256Preimages(_) => Some(self.hash160_state()),
            EncoderState::Hash160Preimages(_) => Some(self.hash256_state()),
            EncoderState::Hash256Preimages(_) => self.tap_key_sig_state(),
            EncoderState::TapKeySig(_) => Some(self.tap_script_sigs_state()),
            EncoderState::TapScriptSigs(_) => Some(self.tap_scripts_state()),
            EncoderState::TapScripts(_) => Some(self.tap_key_origins_state()),
            EncoderState::TapKeyOrigins(_) => self.tap_internal_key_state(),
            EncoderState::TapInternalKey(_) => self.tap_merkle_root_state(),
            EncoderState::TapMerkleRoot(_) => self.first_collection_after_tap_merkle_root(),
            #[cfg(feature = "silent-payments")]
            EncoderState::Ecdh(_) => Some(self.dleq_state()),
            #[cfg(feature = "silent-payments")]
            EncoderState::Dleq(_) => Some(self.proprietaries_state()),
            EncoderState::Proprietaries(_) => Some(self.unknowns_state()),
            EncoderState::Unknowns(_) => Some(EncoderState::Separator(SeparatorEncoder::new())),
            EncoderState::Separator(_) => None,
        }
    }

    fn first_collection_after_tap_merkle_root(&self) -> Option<EncoderState<'e>> {
        #[cfg(feature = "silent-payments")]
        {
            Some(self.ecdh_state())
        }
        #[cfg(not(feature = "silent-payments"))]
        {
            Some(self.proprietaries_state())
        }
    }

    fn output_index_pair(&self) -> OutputIndexPair {
        KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_IN_OUTPUT_INDEX),
            ArrayEncoder::without_length_prefix(self.input.spent_output_index.to_le_bytes()),
        )
    }

    fn sequence_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.sequence {
            Some(seq) => Some(EncoderState::Sequence(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_SEQUENCE),
                seq.psbt_encoder(),
            ))),
            None => self.min_time_state(),
        }
    }

    fn min_time_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.min_time {
            Some(min_time) => Some(EncoderState::MinTime(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_REQUIRED_TIME_LOCKTIME),
                min_time.psbt_encoder(),
            ))),
            None => self.min_height_state(),
        }
    }

    fn min_height_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.min_height {
            Some(min_height) => Some(EncoderState::MinHeight(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_REQUIRED_HEIGHT_LOCKTIME),
                min_height.psbt_encoder(),
            ))),
            None => self.non_witness_utxo_state(),
        }
    }

    fn non_witness_utxo_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.non_witness_utxo {
            Some(tx) => {
                let exact = ExactLenEncoder::new(tx, tx.total_size());
                Some(EncoderState::NonWitnessUtxo(KeyValueEncoder::from_sized_kv(
                    CompactSizeEncoder::new_u64(PSBT_IN_NON_WITNESS_UTXO),
                    exact,
                )))
            }
            None => self.witness_utxo_state(),
        }
    }

    fn witness_utxo_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.witness_utxo {
            Some(tx_out) => Some(EncoderState::WitnessUtxo(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_WITNESS_UTXO),
                tx_out.psbt_encoder(),
            ))),
            None => Some(self.partial_sigs_state()),
        }
    }

    fn partial_sigs_state(&self) -> EncoderState<'e> {
        EncoderState::PartialSigs(IterEncoder::new(PartialSigIter::new(
            self.input.partial_sigs.iter(),
        )))
    }

    fn sighash_type_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.sighash_type {
            Some(sighash) => Some(EncoderState::SighashType(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_SIGHASH_TYPE),
                sighash.psbt_encoder(),
            ))),
            None => self.redeem_script_state(),
        }
    }

    fn redeem_script_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.redeem_script {
            Some(script) => Some(EncoderState::RedeemScript(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_REDEEM_SCRIPT),
                script.psbt_encoder(),
            ))),
            None => self.witness_script_state(),
        }
    }

    fn witness_script_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.witness_script {
            Some(script) => Some(EncoderState::WitnessScript(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_WITNESS_SCRIPT),
                script.psbt_encoder(),
            ))),
            None => Some(self.bip32_derivations_state()),
        }
    }

    fn bip32_derivations_state(&self) -> EncoderState<'e> {
        EncoderState::Bip32Derivations(IterEncoder::new(Bip32DerivationIter::new(
            self.input.bip32_derivations.iter(),
        )))
    }

    fn final_script_sig_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.final_script_sig {
            Some(script) => Some(EncoderState::FinalScriptSig(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_FINAL_SCRIPTSIG),
                script.psbt_encoder(),
            ))),
            None => self.final_script_witness_state(),
        }
    }

    fn final_script_witness_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.final_script_witness {
            Some(witness) => {
                let exact = ExactLenEncoder::new(witness, witness.size());
                Some(EncoderState::FinalScriptWitness(KeyValueEncoder::from_sized_kv(
                    CompactSizeEncoder::new_u64(PSBT_IN_FINAL_SCRIPTWITNESS),
                    exact,
                )))
            }
            None => Some(self.ripemd160_state()),
        }
    }

    fn ripemd160_state(&self) -> EncoderState<'e> {
        EncoderState::Ripemd160Preimages(IterEncoder::new(Ripemd160Iter::new_bytes(
            self.input.ripemd160_preimages.iter(),
        )))
    }

    fn sha256_state(&self) -> EncoderState<'e> {
        EncoderState::Sha256Preimages(IterEncoder::new(Sha256Iter::new_bytes(
            self.input.sha256_preimages.iter(),
        )))
    }

    fn hash160_state(&self) -> EncoderState<'e> {
        EncoderState::Hash160Preimages(IterEncoder::new(Hash160Iter::new_bytes(
            self.input.hash160_preimages.iter(),
        )))
    }

    fn hash256_state(&self) -> EncoderState<'e> {
        EncoderState::Hash256Preimages(IterEncoder::new(Hash256Iter::new_bytes(
            self.input.hash256_preimages.iter(),
        )))
    }

    fn tap_key_sig_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.tap_key_sig {
            Some(sig) => Some(EncoderState::TapKeySig(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_TAP_KEY_SIG),
                sig.psbt_encoder(),
            ))),
            None => Some(self.tap_script_sigs_state()),
        }
    }

    fn tap_script_sigs_state(&self) -> EncoderState<'e> {
        EncoderState::TapScriptSigs(IterEncoder::new(TapScriptSigIter::new(
            self.input.tap_script_sigs.iter(),
        )))
    }

    fn tap_scripts_state(&self) -> EncoderState<'e> {
        EncoderState::TapScripts(IterEncoder::new(TapScriptIter::new(
            self.input.tap_scripts.iter(),
        )))
    }

    fn tap_key_origins_state(&self) -> EncoderState<'e> {
        EncoderState::TapKeyOrigins(IterEncoder::new(TapKeyOriginIter::new(
            self.input.tap_key_origins.iter(),
        )))
    }

    fn tap_internal_key_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.tap_internal_key {
            Some(key) => Some(EncoderState::TapInternalKey(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_TAP_INTERNAL_KEY),
                key.psbt_encoder(),
            ))),
            None => self.tap_merkle_root_state(),
        }
    }

    fn tap_merkle_root_state(&self) -> Option<EncoderState<'e>> {
        match &self.input.tap_merkle_root {
            Some(root) => Some(EncoderState::TapMerkleRoot(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_IN_TAP_MERKLE_ROOT),
                root.psbt_encoder(),
            ))),
            None => self.first_collection_after_tap_merkle_root(),
        }
    }

    #[cfg(feature = "silent-payments")]
    fn ecdh_state(&self) -> EncoderState<'e> {
        EncoderState::Ecdh(IterEncoder::new(EcdhPairIter::new(self.input.sp_ecdh_shares.iter())))
    }

    #[cfg(feature = "silent-payments")]
    fn dleq_state(&self) -> EncoderState<'e> {
        use crate::encoding::native::DleqPairIter;

        EncoderState::Dleq(IterEncoder::new(DleqPairIter::new(self.input.sp_dleq_proofs.iter())))
    }

    fn proprietaries_state(&self) -> EncoderState<'e> {
        EncoderState::Proprietaries(IterEncoder::new(ProprietaryKeyValueIter(
            self.input.proprietaries.iter(),
        )))
    }

    fn unknowns_state(&self) -> EncoderState<'e> {
        EncoderState::Unknowns(IterEncoder::new(UnknownKeyValueIter(self.input.unknowns.iter())))
    }
}

impl Encoder for InputMapEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match &self.state {
            EncoderState::PreviousTxid(e) => e.current_chunk(),
            EncoderState::OutputIndex(e) => e.current_chunk(),
            EncoderState::Sequence(e) => e.current_chunk(),
            EncoderState::MinTime(e) => e.current_chunk(),
            EncoderState::MinHeight(e) => e.current_chunk(),
            EncoderState::NonWitnessUtxo(e) => e.current_chunk(),
            EncoderState::WitnessUtxo(e) => e.current_chunk(),
            EncoderState::PartialSigs(e) => e.current_chunk(),
            EncoderState::SighashType(e) => e.current_chunk(),
            EncoderState::RedeemScript(e) => e.current_chunk(),
            EncoderState::WitnessScript(e) => e.current_chunk(),
            EncoderState::Bip32Derivations(e) => e.current_chunk(),
            EncoderState::FinalScriptSig(e) => e.current_chunk(),
            EncoderState::FinalScriptWitness(e) => e.current_chunk(),
            EncoderState::Ripemd160Preimages(e) => e.current_chunk(),
            EncoderState::Sha256Preimages(e) => e.current_chunk(),
            EncoderState::Hash160Preimages(e) => e.current_chunk(),
            EncoderState::Hash256Preimages(e) => e.current_chunk(),
            EncoderState::TapKeySig(e) => e.current_chunk(),
            EncoderState::TapScriptSigs(e) => e.current_chunk(),
            EncoderState::TapScripts(e) => e.current_chunk(),
            EncoderState::TapKeyOrigins(e) => e.current_chunk(),
            EncoderState::TapInternalKey(e) => e.current_chunk(),
            EncoderState::TapMerkleRoot(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            EncoderState::Ecdh(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            EncoderState::Dleq(e) => e.current_chunk(),
            EncoderState::Proprietaries(e) => e.current_chunk(),
            EncoderState::Unknowns(e) => e.current_chunk(),
            EncoderState::Separator(e) => e.current_chunk(),
        }
    }

    fn advance(&mut self) -> EncoderStatus {
        let finished = match &mut self.state {
            EncoderState::PreviousTxid(e) => e.advance().has_finished(),
            EncoderState::OutputIndex(e) => e.advance().has_finished(),
            EncoderState::Sequence(e) => e.advance().has_finished(),
            EncoderState::MinTime(e) => e.advance().has_finished(),
            EncoderState::MinHeight(e) => e.advance().has_finished(),
            EncoderState::NonWitnessUtxo(e) => e.advance().has_finished(),
            EncoderState::WitnessUtxo(e) => e.advance().has_finished(),
            EncoderState::PartialSigs(e) => e.advance().has_finished(),
            EncoderState::SighashType(e) => e.advance().has_finished(),
            EncoderState::RedeemScript(e) => e.advance().has_finished(),
            EncoderState::WitnessScript(e) => e.advance().has_finished(),
            EncoderState::Bip32Derivations(e) => e.advance().has_finished(),
            EncoderState::FinalScriptSig(e) => e.advance().has_finished(),
            EncoderState::FinalScriptWitness(e) => e.advance().has_finished(),
            EncoderState::Ripemd160Preimages(e) => e.advance().has_finished(),
            EncoderState::Sha256Preimages(e) => e.advance().has_finished(),
            EncoderState::Hash160Preimages(e) => e.advance().has_finished(),
            EncoderState::Hash256Preimages(e) => e.advance().has_finished(),
            EncoderState::TapKeySig(e) => e.advance().has_finished(),
            EncoderState::TapScriptSigs(e) => e.advance().has_finished(),
            EncoderState::TapScripts(e) => e.advance().has_finished(),
            EncoderState::TapKeyOrigins(e) => e.advance().has_finished(),
            EncoderState::TapInternalKey(e) => e.advance().has_finished(),
            EncoderState::TapMerkleRoot(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            EncoderState::Ecdh(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            EncoderState::Dleq(e) => e.advance().has_finished(),
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

impl PsbtEncode for Input {
    type Encoder<'e> = InputMapEncoder<'e>;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        // `<input-map> := <keypair>* 0x00`
        InputMapEncoder::new(self)
    }
}

impl Map for Input {
    fn get_pairs(&self) -> Vec<raw::Pair> {
        let mut rv: Vec<raw::Pair> = Default::default();

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_IN_PREVIOUS_TXID, key: vec![] },
            value: self.previous_txid.serialize(),
        });

        rv.push(raw::Pair {
            key: raw::Key { type_value: PSBT_IN_OUTPUT_INDEX, key: vec![] },
            value: self.spent_output_index.serialize(),
        });

        v2_impl_psbt_get_pair! {
            rv.push(self.sequence, PSBT_IN_SEQUENCE)
        }
        v2_impl_psbt_get_pair! {
            rv.push(self.min_time, PSBT_IN_REQUIRED_TIME_LOCKTIME)
        }
        v2_impl_psbt_get_pair! {
            rv.push(self.min_height, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.non_witness_utxo, PSBT_IN_NON_WITNESS_UTXO)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.witness_utxo, PSBT_IN_WITNESS_UTXO)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.partial_sigs, PSBT_IN_PARTIAL_SIG)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.sighash_type, PSBT_IN_SIGHASH_TYPE)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.redeem_script, PSBT_IN_REDEEM_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.witness_script, PSBT_IN_WITNESS_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.bip32_derivations, PSBT_IN_BIP32_DERIVATION)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.final_script_sig, PSBT_IN_FINAL_SCRIPTSIG)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.final_script_witness, PSBT_IN_FINAL_SCRIPTWITNESS)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.ripemd160_preimages, PSBT_IN_RIPEMD160)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.sha256_preimages, PSBT_IN_SHA256)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.hash160_preimages, PSBT_IN_HASH160)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.hash256_preimages, PSBT_IN_HASH256)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_key_sig, PSBT_IN_TAP_KEY_SIG)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.tap_script_sigs, PSBT_IN_TAP_SCRIPT_SIG)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.tap_scripts, PSBT_IN_TAP_LEAF_SCRIPT)
        }

        v2_impl_psbt_get_pair! {
            rv.push_map(self.tap_key_origins, PSBT_IN_TAP_BIP32_DERIVATION)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_internal_key, PSBT_IN_TAP_INTERNAL_KEY)
        }

        v2_impl_psbt_get_pair! {
            rv.push(self.tap_merkle_root, PSBT_IN_TAP_MERKLE_ROOT)
        }

        #[cfg(feature = "silent-payments")]
        for (scan_key, ecdh_share) in &self.sp_ecdh_shares {
            rv.push(raw::Pair {
                key: raw::Key {
                    type_value: PSBT_IN_SP_ECDH_SHARE,
                    key: scan_key.to_bytes().to_vec(),
                },
                value: ecdh_share.to_bytes().to_vec(),
            });
        }

        #[cfg(feature = "silent-payments")]
        for (scan_key, dleq_proof) in &self.sp_dleq_proofs {
            rv.push(raw::Pair {
                key: raw::Key { type_value: PSBT_IN_SP_DLEQ, key: scan_key.to_bytes().to_vec() },
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

// TODO: This is an exact duplicate of that in v0.

/// Enables building an [`Input`] using the standard builder pattern.
pub struct InputBuilder(Input);

impl InputBuilder {
    /// Creates a new builder that can be used to build an [`Input`] that spends `previous_output`.
    pub fn new(previous_output: &OutPoint) -> Self { Self(Input::new(previous_output)) }

    /// Sets the [`Input::min_time`] field.
    pub fn minimum_required_time_based_lock_time(mut self, lock: absolute::Time) -> Self {
        self.0.min_time = Some(lock);
        self
    }

    /// Sets the [`Input::min_height`] field.
    pub fn minimum_required_height_based_lock_time(mut self, lock: absolute::Height) -> Self {
        self.0.min_height = Some(lock);
        self
    }

    /// Funds this input with a segwit UTXO.
    pub fn segwit_fund(mut self, utxo: TxOut) -> Self {
        self.0.witness_utxo = Some(utxo);
        self
    }

    /// Funds this input with a legacy UTXO.
    ///
    /// Caller to guarantee that this `tx` is correct for this input (i.e., has a txid equal to
    /// `self.previous_txid`).
    // TODO: Consider adding error checks that tx is correct.
    pub fn legacy_fund(mut self, tx: Transaction) -> Self {
        self.0.non_witness_utxo = Some(tx);
        self
    }

    /// Builds the [`Input`].
    pub fn build(self) -> Input { self.0 }
}

/// Error decoding the body of a value.
#[derive(Debug)]
pub enum ValueDecodeError {
    /// Error decoding the value's compact-size length prefix.
    LengthPrefix(CompactSizeDecoderError),
    /// Error decoding the previous transaction ID (32-byte fixed value).
    PreviousTxid(UnexpectedEofError),
    /// Error decoding the output index (4-byte fixed value).
    OutputIndex(UnexpectedEofError),
    /// Error decoding the sequence number (4-byte fixed value).
    Sequence(UnexpectedEofError),
    /// Error decoding the minimum lock time (4-byte fixed value).
    MinTime(UnexpectedEofError),
    /// Error decoding the minimum lock height (4-byte fixed value).
    MinHeight(UnexpectedEofError),
    /// Error decoding the sighash type (4-byte fixed value).
    SighashType(UnexpectedEofError),
    /// Error decoding the taproot internal key (32-byte fixed value).
    TapInternalKey(UnexpectedEofError),
    /// Error decoding the taproot merkle root (32-byte fixed value).
    TapMerkleRoot(UnexpectedEofError),
    /// Error decoding the non-witness UTXO (full transaction).
    NonWitnessUtxo(TransactionDecoderError),
    /// Error decoding the witness UTXO (transaction output).
    WitnessUtxo(TxOutDecoderError),
    /// Error decoding the final script witness (witness stack).
    FinalScriptWitness(WitnessDecoderError),
    /// Error decoding the redeem script.
    RedeemScript(ByteVecDecoderError),
    /// Error decoding the witness script.
    WitnessScript(ByteVecDecoderError),
    /// Error decoding the final scriptSig.
    FinalScriptSig(ByteVecDecoderError),
    /// Error decoding the taproot key signature.
    TapKeySig(ByteVecDecoderError),
    /// Error decoding an ECDSA partial signature.
    PartialSig(ByteVecDecoderError),
    /// Error decoding the BIP32 derivation key source.
    Bip32Derivation(ByteVecDecoderError),
    /// Error decoding the taproot BIP32 derivation key source.
    TapBip32Derivation(ByteVecDecoderError),
    /// Error decoding a RIPEMD160 preimage.
    Ripemd160Preimage(ByteVecDecoderError),
    /// Error decoding a SHA256 preimage.
    Sha256Preimage(ByteVecDecoderError),
    /// Error decoding a HASH160 preimage.
    Hash160Preimage(ByteVecDecoderError),
    /// Error decoding a HASH256 preimage.
    Hash256Preimage(ByteVecDecoderError),
    /// Error decoding a taproot script signature.
    TapScriptSig(ByteVecDecoderError),
    /// Error decoding a tap leaf script.
    TapLeafScript(ByteVecDecoderError),
    /// Error decoding a proprietary value.
    ProprietaryValue(ByteVecDecoderError),
    /// Error decoding an unknown value.
    UnknownValue(ByteVecDecoderError),
    /// The decoded value is not a valid minimum lock time.
    InvalidMinTime,
    /// The decoded value is not a valid minimum lock height.
    InvalidMinHeight,
    /// The decoded value is not a valid taproot signature.
    InvalidTaprootSignature,
    /// The decoded value is not a valid taproot control block.
    InvalidControlBlock,
    /// The decoded value is not a valid taproot leaf version.
    InvalidLeafVersion,
    /// Error decoding a silent payments ECDH share (33-byte fixed value).
    #[cfg(feature = "silent-payments")]
    SpEcdh(UnexpectedEofError),
    /// Error decoding a silent payments DLEQ proof (64-byte fixed value).
    #[cfg(feature = "silent-payments")]
    SpDleq(UnexpectedEofError),
}

impl fmt::Display for ValueDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthPrefix(ref e) => write_err!(f, "error decoding value length prefix"; e),
            Self::PreviousTxid(ref e) => write_err!(f, "error decoding previous txid"; e),
            Self::OutputIndex(ref e) => write_err!(f, "error decoding output index"; e),
            Self::Sequence(ref e) => write_err!(f, "error decoding sequence"; e),
            Self::MinTime(ref e) => write_err!(f, "error decoding min time"; e),
            Self::MinHeight(ref e) => write_err!(f, "error decoding min height"; e),
            Self::SighashType(ref e) => write_err!(f, "error decoding sighash type"; e),
            Self::TapInternalKey(ref e) => write_err!(f, "error decoding tap internal key"; e),
            Self::TapMerkleRoot(ref e) => write_err!(f, "error decoding tap merkle root"; e),
            Self::NonWitnessUtxo(ref e) => write_err!(f, "error decoding non-witness UTXO"; e),
            Self::WitnessUtxo(ref e) => write_err!(f, "error decoding witness UTXO"; e),
            Self::FinalScriptWitness(ref e) =>
                write_err!(f, "error decoding final script witness"; e),
            Self::RedeemScript(ref e) => write_err!(f, "error decoding redeem script"; e),
            Self::WitnessScript(ref e) => write_err!(f, "error decoding witness script"; e),
            Self::FinalScriptSig(ref e) => write_err!(f, "error decoding final scriptSig"; e),
            Self::TapKeySig(ref e) => write_err!(f, "error decoding tap key signature"; e),
            Self::PartialSig(ref e) => write_err!(f, "error decoding partial signature"; e),
            Self::Bip32Derivation(ref e) => write_err!(f, "error decoding BIP32 derivation"; e),
            Self::TapBip32Derivation(ref e) =>
                write_err!(f, "error decoding tap BIP32 derivation"; e),
            Self::Ripemd160Preimage(ref e) => write_err!(f, "error decoding RIPEMD160 preimage"; e),
            Self::Sha256Preimage(ref e) => write_err!(f, "error decoding SHA256 preimage"; e),
            Self::Hash160Preimage(ref e) => write_err!(f, "error decoding HASH160 preimage"; e),
            Self::Hash256Preimage(ref e) => write_err!(f, "error decoding HASH256 preimage"; e),
            Self::TapScriptSig(ref e) => write_err!(f, "error decoding tap script signature"; e),
            Self::TapLeafScript(ref e) => write_err!(f, "error decoding tap leaf script"; e),
            Self::ProprietaryValue(ref e) => write_err!(f, "error decoding proprietary value"; e),
            Self::UnknownValue(ref e) => write_err!(f, "error decoding unknown value"; e),
            Self::InvalidMinTime => write!(f, "invalid minimum lock time"),
            Self::InvalidMinHeight => write!(f, "invalid minimum lock height"),
            Self::InvalidTaprootSignature => write!(f, "invalid taproot signature"),
            Self::InvalidControlBlock => write!(f, "invalid control block"),
            Self::InvalidLeafVersion => write!(f, "invalid leaf version"),
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
            Self::PreviousTxid(ref e) => Some(e),
            Self::OutputIndex(ref e) => Some(e),
            Self::Sequence(ref e) => Some(e),
            Self::MinTime(ref e) => Some(e),
            Self::MinHeight(ref e) => Some(e),
            Self::SighashType(ref e) => Some(e),
            Self::TapInternalKey(ref e) => Some(e),
            Self::TapMerkleRoot(ref e) => Some(e),
            Self::NonWitnessUtxo(ref e) => Some(e),
            Self::WitnessUtxo(ref e) => Some(e),
            Self::FinalScriptWitness(ref e) => Some(e),
            Self::RedeemScript(ref e) => Some(e),
            Self::WitnessScript(ref e) => Some(e),
            Self::FinalScriptSig(ref e) => Some(e),
            Self::TapKeySig(ref e) => Some(e),
            Self::PartialSig(ref e) => Some(e),
            Self::Bip32Derivation(ref e) => Some(e),
            Self::TapBip32Derivation(ref e) => Some(e),
            Self::Ripemd160Preimage(ref e) => Some(e),
            Self::Sha256Preimage(ref e) => Some(e),
            Self::Hash160Preimage(ref e) => Some(e),
            Self::Hash256Preimage(ref e) => Some(e),
            Self::TapScriptSig(ref e) => Some(e),
            Self::TapLeafScript(ref e) => Some(e),
            Self::ProprietaryValue(ref e) => Some(e),
            Self::UnknownValue(ref e) => Some(e),
            Self::InvalidMinTime
            | Self::InvalidMinHeight
            | Self::InvalidTaprootSignature
            | Self::InvalidControlBlock
            | Self::InvalidLeafVersion => None,
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
    /// Error decoding a pair.
    DeserPair(serialize::Error),
    /// Error decoding key.
    KeyDecode(raw::KeyDecodeError),
    /// Error decoding a value.
    ValueDecode(ValueDecodeError),
    /// Input must contain a previous txid.
    MissingPreviousTxid,
    /// Input must contain a spent output index.
    MissingSpentOutputIndex,
    /// Called build() before fully decoding the input map.
    EarlyEnd,
    /// BIP-375: ECDH shares and DLEQ proofs must both be present or both absent.
    FieldMismatch,
    /// Non-witness UTXO txid does not match the input's previous txid.
    IncorrectNonWitnessUtxo {
        /// The txid of the input being spent.
        previous_txid: Txid,
        /// The txid of the non-witness UTXO.
        non_witness_utxo_txid: Txid,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsertPair(ref e) => write_err!(f, "error inserting a key-value pair"; e),
            Self::DeserPair(ref e) => write_err!(f, "error decoding pair"; e),
            Self::KeyDecode(ref e) => write_err!(f, "error decoding key"; e),
            Self::ValueDecode(ref e) => write_err!(f, "error decoding value"; e),
            Self::MissingPreviousTxid => write!(f, "input must contain a previous txid"),
            Self::MissingSpentOutputIndex => write!(f, "input must contain a spent output index"),
            Self::EarlyEnd => write!(f, "called build() before completing input map decode"),
            Self::FieldMismatch => {
                write!(f, "ECDH shares and DLEQ proofs must both be present or both absent")
            }
            Self::IncorrectNonWitnessUtxo { previous_txid, non_witness_utxo_txid } => {
                write!(
                    f,
                    "non-witness utxo txid {} does not match previous txid {}",
                    non_witness_utxo_txid, previous_txid
                )
            }
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
            Self::ValueDecode(ref e) => Some(e),
            Self::MissingPreviousTxid
            | Self::MissingSpentOutputIndex
            | Self::EarlyEnd
            | Self::FieldMismatch
            | Self::IncorrectNonWitnessUtxo { .. } => None,
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
    /// Error deserializing raw value.
    Deser(serialize::Error),
    /// Key should contain data.
    InvalidKeyDataEmpty(raw::Key),
    /// Key should not contain data.
    InvalidKeyDataNotEmpty(raw::Key),
    /// The pre-image must hash to the correponding psbt hash
    HashPreimage(HashPreimageError),
    /// Key was not the correct length (got, expected).
    KeyWrongLength(usize, usize),
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
            Self::HashPreimage(ref e) => write_err!(f, "invalid hash preimage"; e),
            Self::KeyWrongLength(got, expected) => {
                write!(f, "key wrong length (got: {}, expected: {})", got, expected)
            }
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
            Self::HashPreimage(ref e) => Some(e),
            Self::DuplicateKey(_)
            | Self::InvalidKeyDataEmpty(_)
            | Self::InvalidKeyDataNotEmpty(_)
            | Self::KeyWrongLength(..)
            | Self::ValueWrongLength(..) => None,
        }
    }
}

impl From<serialize::Error> for InsertPairError {
    fn from(e: serialize::Error) -> Self { Self::Deser(e) }
}

impl From<HashPreimageError> for InsertPairError {
    fn from(e: HashPreimageError) -> Self { Self::HashPreimage(e) }
}

/// An hash and hash preimage do not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashPreimageError {
    /// The hash-type causing this error.
    hash_type: HashType,
    /// The hash pre-image.
    preimage: Box<[u8]>,
    /// The hash (should equal hash of the preimage).
    hash: Box<[u8]>,
}

impl fmt::Display for HashPreimageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid hash preimage {} {:x} {:x}",
            self.hash_type,
            self.preimage.as_hex(),
            self.hash.as_hex()
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HashPreimageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Enum for marking invalid preimage error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum HashType {
    /// The ripemd hash algorithm.
    Ripemd,
    /// The sha-256 hash algorithm.
    Sha256,
    /// The hash-160 hash algorithm.
    Hash160,
    /// The Hash-256 hash algorithm.
    Hash256,
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", stringify!(self)) }
}

/// Error finalizing an input.
#[cfg(feature = "miniscript")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizeError {
    /// Failed to create a final witness.
    EmptyWitness,
    /// Unexpected witness data.
    UnexpectedWitness,
}

#[cfg(feature = "miniscript")]
impl fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyWitness => write!(f, "failed to create a final witness"),
            Self::UnexpectedWitness => write!(f, "unexpected witness data"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "miniscript")]
impl std::error::Error for FinalizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error combining two input maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// The previous txids are not the same.
    PreviousTxidMismatch {
        /// Attempted to combine a PSBT with `this` previous txid.
        this: Txid,
        /// Into a PSBT with `that` previous txid.
        that: Txid,
    },
    /// The spent output indecies are not the same.
    SpentOutputIndexMismatch {
        /// Attempted to combine a PSBT with `this` spent output index.
        this: u32,
        /// Into a PSBT with `that` spent output index.
        that: u32,
    },
}
impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreviousTxidMismatch { ref this, ref that } => {
                write!(f, "combine two PSBTs with different previous txids: {:?} {:?}", this, that)
            }
            Self::SpentOutputIndexMismatch { ref this, ref that } => write!(
                f,
                "combine two PSBTs with different spent output indecies: {:?} {:?}",
                this, that
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PreviousTxidMismatch { .. } | Self::SpentOutputIndexMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use bitcoin::Amount;

    use super::*;

    fn out_point() -> OutPoint {
        let txid = Txid::hash(b"some arbitrary bytes");
        let vout = 0xab;
        OutPoint { txid, vout }
    }

    #[test]
    fn serialize_roundtrip() {
        let input = Input::new(&out_point());

        let ser = input.serialize_map();

        let decoded = crate::encoding::decode_from_slice::<Input>(&ser).expect("failed to decode");

        assert_eq!(decoded, input);
    }

    #[test]
    fn pairs_matches_serialize_map() {
        let input = Input::new(&out_point());

        let mut from_pairs = Vec::new();
        for pair in input.pairs() {
            from_pairs.extend(pair.serialize());
        }
        from_pairs.push(crate::consts::PSBT_SEPARATOR);

        assert_eq!(from_pairs, input.serialize_map());
    }

    #[test]
    fn encode_nonempty() {
        let input = Input::new(&out_point());
        let bytes = crate::encoding::encode_to_vec(&input);
        assert!(!bytes.is_empty());
        assert!(bytes.len() > 1, "map must have at least one keypair before separator");
        assert_eq!(
            bytes.last(),
            Some(&crate::consts::PSBT_SEPARATOR),
            "input map must end with separator"
        );
    }

    #[test]
    fn read_limit_lifecycle() {
        let input = Input::new(&out_point());
        let bytes = crate::encoding::encode_to_vec(&input);

        let mut decoder = InputDecoder::default();
        assert_eq!(decoder.read_limit(), 1, "fresh decoder should request bytes");

        let mut remaining = &bytes[..];
        assert!(decoder.push_bytes(&mut remaining).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0, "completed decoder should request no bytes");
    }

    #[test]
    fn decode_non_witness_utxo_matching_txid() {
        // A non-witness UTXO whose txid matches the input's previous txid is valid.
        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let txid = funding_tx.compute_txid();

        let mut input = Input::new(&OutPoint { txid, vout: 0 });
        input.non_witness_utxo = Some(funding_tx);

        let bytes = crate::encoding::encode_to_vec(&input);
        let mut decoder = InputDecoder::default();
        let mut remaining = &bytes[..];
        assert!(decoder.push_bytes(&mut remaining).unwrap().is_ready());
        let decoded = decoder.end().expect("matching txid must decode");
        assert_eq!(decoded.previous_txid, txid);
    }

    #[test]
    fn decode_non_witness_utxo_mismatched_txid() {
        // A non-witness UTXO whose txid does not match the previous txid is invalid.
        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut input = Input::new(&out_point());
        input.non_witness_utxo = Some(funding_tx);

        let bytes = crate::encoding::encode_to_vec(&input);
        let mut decoder = InputDecoder::default();
        let mut remaining = &bytes[..];
        assert!(decoder.push_bytes(&mut remaining).unwrap().is_ready());
        match decoder.end() {
            Err(DecodeError::IncorrectNonWitnessUtxo { .. }) => {}
            other => panic!("expected IncorrectNonWitnessUtxo, got {other:?}"),
        }
    }

    // Asserts byte-equality between the native pull-encoder and `Map::serialize_map`, and
    // decodability of that output through the legacy `Input::decode(Read)` waiter.
    fn check_input(input: &Input) {
        let encoded = crate::encoding::encode_to_vec(input);
        assert_eq!(encoded, input.serialize_map());
        assert_eq!(
            encoded.last(),
            Some(&crate::consts::PSBT_SEPARATOR),
            "input map must end with separator"
        );

        let decoded =
            crate::encoding::decode_from_slice::<Input>(&encoded).expect("failed to decode");
        assert_eq!(decoded, input.clone());
    }

    #[test]
    fn encode_default() {
        let input = Input::new(&out_point());
        check_input(&input);
    }

    #[test]
    fn encode_with_sequence_and_lock_times() {
        let mut input = Input::new(&out_point());
        input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
        input.min_time =
            Some(bitcoin::locktime::absolute::Time::from_consensus(1_700_000_000).unwrap());
        input.min_height =
            Some(bitcoin::locktime::absolute::Height::from_consensus(800_000).unwrap());
        check_input(&input);
    }

    #[test]
    fn encode_with_scripts_and_sighash() {
        let mut input = Input::new(&out_point());
        input.redeem_script = Some(ScriptBuf::from_bytes(Vec::from([0x51u8])));
        input.witness_script = Some(ScriptBuf::from_bytes(Vec::from([0x51u8, 0x52])));
        input.final_script_sig = Some(ScriptBuf::from_bytes(Vec::from([0x51u8])));
        input.sighash_type = Some(PsbtSighashType::ALL);
        check_input(&input);
    }

    #[test]
    fn encode_with_sighash_types() {
        for sigh in [
            PsbtSighashType::ALL,
            EcdsaSighashType::All.into(),
            EcdsaSighashType::AllPlusAnyoneCanPay.into(),
        ] {
            let mut input = Input::new(&out_point());
            input.sighash_type = Some(sigh);
            check_input(&input);
        }
    }

    #[cfg(feature = "miniscript")]
    #[test]
    fn finalize_preserves_transaction_fields() {
        // Fields that the Extractor rebuilds the transaction from must survive finalization.
        let mut input = Input::new(&out_point());
        input.witness_utxo = Some(TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        });
        input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
        input.min_time =
            Some(bitcoin::locktime::absolute::Time::from_consensus(1_700_000_000).unwrap());
        input.min_height =
            Some(bitcoin::locktime::absolute::Height::from_consensus(800_000).unwrap());

        let finalized = input
            .finalize(ScriptBuf::new(), Witness::from_slice(&[vec![1u8]]))
            .expect("finalize must succeed");

        assert_eq!(finalized.sequence, input.sequence);
        assert_eq!(finalized.min_time, input.min_time);
        assert_eq!(finalized.min_height, input.min_height);
    }

    #[cfg(feature = "miniscript")]
    #[test]
    fn finalize_retains_unknown_and_proprietary_fields() {
        let mut input = Input::new(&out_point());
        input.witness_utxo = Some(TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        });
        input.proprietaries.insert(
            raw::ProprietaryKey { prefix: b"test".to_vec(), subtype: 0, key: vec![0x01] },
            vec![0x02],
        );
        input.unknowns.insert(raw::Key { type_value: 0x7f, key: vec![0x03] }, vec![0x04]);

        let finalized = input
            .finalize(ScriptBuf::new(), Witness::from_slice(&[vec![1u8]]))
            .expect("finalize must succeed");

        assert_eq!(finalized.proprietaries, input.proprietaries);
        assert_eq!(finalized.unknowns, input.unknowns);
    }

    // TODO: Remove once the BIP-375 finalizer and extractor vectors land in tests/bip375.rs.
    #[cfg(feature = "miniscript")]
    #[cfg(feature = "silent-payments")]
    #[test]
    fn finalize_retains_silent_payment_fields() {
        use core::str::FromStr;

        let scan_key = CompressedPublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap();

        let mut input = Input::new(&out_point());
        input.witness_utxo = Some(TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        });
        input.sp_ecdh_shares.insert(scan_key, scan_key);
        input.sp_dleq_proofs.insert(scan_key, DleqProof([0x42; 64]));

        let finalized = input
            .finalize(ScriptBuf::new(), Witness::from_slice(&[vec![1u8]]))
            .expect("finalize must succeed");

        assert_eq!(finalized.sp_ecdh_shares, input.sp_ecdh_shares);
        assert_eq!(finalized.sp_dleq_proofs, input.sp_dleq_proofs);
    }

    #[cfg(feature = "miniscript")]
    #[test]
    fn finalize_clears_signing_material() {
        // Signing material is cleared once the final scripts exist.
        let mut input = Input::new(&out_point());
        input.witness_utxo = Some(TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        });
        input.sighash_type = Some(PsbtSighashType::ALL);

        let finalized = input
            .finalize(ScriptBuf::new(), Witness::from_slice(&[vec![1u8]]))
            .expect("finalize must succeed");

        assert!(finalized.partial_sigs.is_empty());
        assert!(finalized.sighash_type.is_none());
        assert!(finalized.bip32_derivations.is_empty());
    }

    #[test]
    fn tx_in_defaults_a_missing_sequence_to_final() {
        // An omitted PSBT_IN_SEQUENCE means the final sequence number for the unsigned and
        // signed transaction inputs.
        let mut input = Input::new(&out_point());
        input.final_script_witness = Some(Witness::from_slice(&[vec![1u8]]));

        assert!(input.sequence.is_none());
        assert_eq!(input.unsigned_tx_in().sequence, Sequence::MAX);
        assert_eq!(input.signed_tx_in().sequence, Sequence::MAX);
    }

    #[test]
    fn tx_in_preserves_an_explicit_sequence() {
        let mut input = Input::new(&out_point());
        input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
        input.final_script_witness = Some(Witness::from_slice(&[vec![1u8]]));

        assert_eq!(input.unsigned_tx_in().sequence, Sequence::ENABLE_LOCKTIME_NO_RBF);
        assert_eq!(input.signed_tx_in().sequence, Sequence::ENABLE_LOCKTIME_NO_RBF);
    }

    #[test]
    fn roundtrip_encoding() {
        use bitcoin::bip32::{DerivationPath, Fingerprint};
        use bitcoin::secp256k1;

        let mut input = Input::new(&out_point());

        // Generate valid keys from secp256k1
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[4u8; 32]).unwrap();
        let secp_pk = sk.public_key(&secp);
        let pk = PublicKey::new(secp_pk);
        let (xonly, _parity) = secp_pk.x_only_public_key();

        input.witness_utxo =
            Some(TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() });
        input.final_script_witness = Some(Witness::from_slice(&[&[0x02u8, 0x03u8]]));
        input.redeem_script = Some(ScriptBuf::from_bytes(vec![0x51]));
        input.witness_script = Some(ScriptBuf::from_bytes(vec![0x52]));
        input.sighash_type = Some(PsbtSighashType::ALL);

        input.tap_key_sig = Some(taproot::Signature {
            signature: secp256k1::schnorr::Signature::from_slice(&[1u8; 64]).unwrap(),
            sighash_type: TapSighashType::Default,
        });
        input.tap_internal_key = Some(xonly);
        input.tap_merkle_root = Some(TapNodeHash::from_byte_array([3u8; 32]));

        input.partial_sigs.insert(
            pk,
            ecdsa::Signature {
                signature: secp256k1::ecdsa::Signature::from_compact(&[5u8; 64]).unwrap(),
                sighash_type: EcdsaSighashType::All,
            },
        );

        let ks: KeySource = (Fingerprint::from([6u8; 4]), DerivationPath::default());
        input.bip32_derivations.insert(pk, ks.clone());

        input
            .ripemd160_preimages
            .insert(ripemd160::Hash::from_byte_array([7u8; 20]), vec![0x42; 32]);
        input.sha256_preimages.insert(sha256::Hash::from_byte_array([8u8; 32]), vec![0x43; 32]);
        input.hash160_preimages.insert(hash160::Hash::from_byte_array([9u8; 20]), vec![0x44; 20]);
        input.hash256_preimages.insert(sha256d::Hash::from_byte_array([10u8; 32]), vec![0x45; 32]);

        let leaf = TapLeafHash::from_slice(&[12u8; 32]).unwrap();
        input.tap_script_sigs.insert(
            (xonly, leaf),
            taproot::Signature {
                signature: secp256k1::schnorr::Signature::from_slice(&[13u8; 64]).unwrap(),
                sighash_type: TapSighashType::Default,
            },
        );

        let mut cb_bytes = vec![0x01u8];
        cb_bytes.extend_from_slice(&xonly.serialize());
        input.tap_scripts.insert(
            ControlBlock::decode(&cb_bytes).unwrap(),
            (ScriptBuf::from_bytes(vec![0x53]), LeafVersion::TapScript),
        );

        input.tap_key_origins.insert(xonly, (vec![leaf], ks));

        input.proprietaries.insert(
            raw::ProprietaryKey::<raw::ProprietaryType> {
                prefix: vec![0xde, 0xad],
                subtype: 42,
                key: vec![0xbe, 0xef],
            },
            vec![0x01, 0x02],
        );

        let encoded = crate::encoding::encode_to_vec(&input);
        let decoded =
            crate::encoding::decode_from_slice::<Input>(&encoded).expect("roundtrip decode failed");
        assert_eq!(decoded, input);
    }
}
