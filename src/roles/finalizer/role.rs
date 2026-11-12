// SPDX-License-Identifier: CC0-1.0

//! Implementation of the Finalizer role as defined in [BIP-174].
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use bitcoin::hashes::hash160;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::sighash::Prevouts;
use bitcoin::taproot::LeafVersion;
use bitcoin::{Script, ScriptBuf, Sequence, TxOut, Txid, Witness, XOnlyPublicKey};
use miniscript::{interpreter, Interpreter, Miniscript, Satisfier, SigType, Tap, ToPublicKey};

use super::satisfy::InputSatisfier;
use crate::error::{write_err, FundingUtxoError};
use crate::map::input::{FinalScripts, Input};
use crate::psbt::{OutputType, Psbt, ResolvedPsbt};
use crate::roles::{ExtractError, Extractor};
use crate::SignatureSighashTypeError;

/// Implements the BIP-370 Finalized role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Finalizer(ResolvedPsbt);

impl Finalizer {
    /// Creates a `Finalizer`.
    ///
    /// A finalizer can only be created if all inputs have a funding UTXO and every signature's
    /// sighash type matches the input's required type.
    pub fn new(psbt: ResolvedPsbt) -> Result<Self, FinalizeError> {
        for (input_index, input) in psbt.inputs.iter().enumerate() {
            let _ = input.funding_utxo().map_err(FinalizeError::FundingUtxo)?;
            if let Some((source, got)) = input.sighash_mismatch() {
                return Err(FinalizeError::SignatureSighashType(SignatureSighashTypeError {
                    input_index,
                    source,
                    got,
                    declared: input.sighash_type,
                }));
            }
        }

        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid { self.0.id() }

    /// Finalizes the PSBT, returning the finalized [`FinalizedPsbt`].
    ///
    /// Use [`FinalizedPsbt::psbt`] to extract the finalized [`Psbt`] for serialization, or
    /// [`FinalizedPsbt::extractor`] to transition to the [`Extractor`](crate::Extractor) role.
    pub fn finalize<C: Verification>(
        self,
        secp: &Secp256k1<C>,
    ) -> Result<FinalizedPsbt, FinalizeError> {
        let mut inputs = vec![];
        for (input_index, input) in self.0.inputs.iter().enumerate() {
            // Already-finalized inputs are passed through unchanged.
            if input.is_finalized() {
                inputs.push(input.clone());
                continue;
            }
            match self.finalize_input(input) {
                Ok(input) => inputs.push(input),
                // TODO: Do we want to continue loop and return a vector of errors?
                Err(error) => return Err(FinalizeError::Input { input_index, error }),
            }
        }

        let lock_time = self.0.lock_time();
        let mut psbt = self.0.into_psbt();
        psbt.inputs = inputs;
        let finalized = ResolvedPsbt::from_parts(psbt, lock_time);
        Self::interpreter_check(&finalized, secp)?;
        Ok(FinalizedPsbt(finalized))
    }

    /// Interprets all PSBT inputs and checks whether the script is correctly interpreted according
    /// to the context.
    ///
    /// The psbt must have included final script sig and final witness. In other words, this checks
    /// whether the finalized psbt interprets correctly.
    pub(crate) fn interpreter_check<C: Verification>(
        psbt: &ResolvedPsbt,
        secp: &Secp256k1<C>,
    ) -> Result<(), FinalizeError> {
        let unsigned_tx = psbt.unsigned_tx();

        let utxos: Vec<&TxOut> = psbt
            .iter_funding_utxos()
            .map(|res| res.expect("finalized PSBT has funding utxos"))
            .collect();
        let utxos = &Prevouts::All(&utxos);
        let empty_witness = Witness::default();
        let empty_script = ScriptBuf::new();
        for (index, input) in psbt.inputs.iter().enumerate() {
            let spk = &input.funding_utxo().expect("have funding utxo").script_pubkey;

            // Use the resolved lock time from the unsigned transaction rather
            // than per-input min_height/min_time fields, which may be None
            // after a v0 roundtrip (the v0 format collapses them into the
            // single nLockTime).
            let cltv = unsigned_tx.lock_time;
            // Assumed MAX if omitted.
            let csv = input.sequence.unwrap_or(Sequence::MAX);

            let witness = input.final_script_witness.as_ref().unwrap_or(&empty_witness);
            let script_sig = input.final_script_sig.as_deref().unwrap_or(empty_script.as_script());

            let interpreter =
                Interpreter::from_txdata(spk, script_sig, witness, csv, cltv).map_err(|error| {
                    FinalizeError::InterpreterConstructor { input_index: index, error }
                })?;

            let iter = interpreter.iter(secp, &unsigned_tx, index, utxos);
            if let Some(error) = iter.filter_map(Result::err).next() {
                return Err(FinalizeError::InterpreterSatisfaction { input_index: index, error });
            };
        }
        Ok(())
    }

    // `index` must be the input index of `input` which references an input in `self` - this gets rid of out-of-bounds error path.
    fn finalize_input(&self, input: &Input) -> Result<Input, InputError> {
        let allow_mall = true; // TODO: Add mall and no-mall versions.
        let fields = self.final_script_sig_and_witness(input, allow_mall)?;
        Ok(input.finalize(fields))
    }

    /// Returns the final script_sig and final witness for this input.
    // TODO: Think harder about this.
    //
    // Input finalizer should only set script sig and witness iff one is required
    //
    // > The Input Finalizer must only accept a PSBT. For each input, the Input Finalizer determines
    // > if the input has enough data to pass validation. If it does, it must construct the 0x07
    // > Finalized scriptSig and 0x08 Finalized scriptWitness and place them into the input key-value
    // > map. If scriptSig is empty for an input, 0x07 should remain unset rather than assigned an
    // > empty array. Likewise, if no scriptWitness exists for an input, 0x08 should remain unset
    // > rather than assigned an empty array.
    //
    // However a finalized input _must_ have them both set.
    //
    // > It checks whether all inputs have complete scriptSigs and scriptWitnesses by checking for
    // > the presence of 0x07 Finalized scriptSig and 0x08 Finalized scriptWitness typed records. If
    // > they do, the Transaction Extractor should ...
    //
    // TODO: Check that we are doing the right thing at the right time between finalization and extraction.
    fn final_script_sig_and_witness(
        &self,
        input: &Input,
        allow_mall: bool,
    ) -> Result<FinalScripts, InputError> {
        let (witness, script_sig) = {
            let spk =
                &input.funding_utxo().expect("guaranteed by Finalizer invariant").script_pubkey;
            let lock_time = self.0.lock_time();
            let sat = InputSatisfier { input, lock_time };

            if spk.is_p2tr() {
                // Deal with taproot case separately, we cannot infer the full descriptor for taproot.
                let wit = construct_tap_witness(spk, sat, allow_mall)?;
                (wit, ScriptBuf::new())
            } else {
                // Get a descriptor for this input.
                let desc = input.get_descriptor()?;

                // Generate the satisfaction witness and scriptsig.
                if !allow_mall {
                    desc.get_satisfaction(sat).map_err(InputError::MiniscriptError)?
                } else {
                    desc.get_satisfaction_mall(sat).map_err(InputError::MiniscriptError)?
                }
            }
        };

        let witness = Witness::from_slice(&witness);
        let output_type = input.output_type().map_err(|_| InputError::UnknownOutputType)?;

        Ok(match output_type {
            OutputType::Wpkh | OutputType::Wsh | OutputType::Tr => FinalScripts::Segwit { witness },
            OutputType::ShWpkh | OutputType::ShWsh => FinalScripts::Wrapped { script_sig, witness },
            OutputType::Bare | OutputType::Sh => FinalScripts::Legacy { script_sig },
        })
    }
}

/// A PSBT that has been finalized by [`Finalizer::finalize`].
///
/// This proof of finalization is the only way to reach the [`Psbt`] serialization point or
/// transition to the [`Extractor`](crate::Extractor) role, so neither can be reached with an
/// unfinalized PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FinalizedPsbt(ResolvedPsbt);

impl FinalizedPsbt {
    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid { self.0.id() }

    /// Returns the finalized [`Psbt`].
    pub fn psbt(self) -> Psbt { self.0.into_psbt() }

    /// Transitions to the [`Extractor`](crate::Extractor) role.
    pub fn extractor(self) -> Result<Extractor, ExtractError> { Extractor::new(self.0) }
}

impl core::ops::Deref for FinalizedPsbt {
    type Target = Psbt;

    fn deref(&self) -> &Psbt { &self.0 }
}

// Satisfy the taproot descriptor. It is not possible to infer the complete descriptor from psbt
// because the information about all the scripts might not be present. Also, currently the spec does
// not support hidden branches, so inferring a descriptor is not possible.
fn construct_tap_witness(
    spk: &Script,
    sat: InputSatisfier,
    allow_mall: bool,
) -> Result<Vec<Vec<u8>>, InputError> {
    assert!(spk.is_p2tr());
    // When miniscript tries to finalize the PSBT, it doesn't have the full descriptor (which
    // contained a pkh() fragment) and instead resorts to parsing the raw script sig, which is
    // translated into a "expr_raw_pkh" internally.
    // We need to satisfy or dissatisfy any given key. `tap_key_origin` is the only field of PSBT
    // Input which consist of all the keys added on a descriptor and thus we get keys from it.
    let map: BTreeMap<hash160::Hash, XOnlyPublicKey> = sat
        .input
        .tap_key_origins
        .keys()
        .map(|key| (key.to_pubkeyhash(SigType::Schnorr), *key))
        .collect();

    // try the key spend path first
    if let Some(sig) = sat.input.tap_internal_key.and_then(|ref key| {
        <InputSatisfier as Satisfier<XOnlyPublicKey>>::lookup_tap_key_spend_sig(&sat, key)
    }) {
        Ok(vec![sig.to_vec()])
    } else if let Some(block_map) =
        <InputSatisfier as Satisfier<XOnlyPublicKey>>::lookup_tap_control_block_map(&sat)
    {
        // Next script spends
        let (mut min_wit, mut min_wit_len) = (None, None);
        for (control_block, (script, ver)) in block_map {
            if *ver != LeafVersion::TapScript {
                // We don't know how to satisfy non default version scripts yet
                continue;
            }
            let ms = match Miniscript::<XOnlyPublicKey, Tap>::decode_consensus(script) {
                Ok(ms) => ms.substitute_raw_pkh(&map),
                Err(..) => continue, // try another script
            };
            let mut wit = if allow_mall {
                match ms.satisfy_malleable(&sat) {
                    Ok(ms) => ms,
                    Err(..) => continue,
                }
            } else {
                match ms.satisfy(&sat) {
                    Ok(ms) => ms,
                    Err(..) => continue,
                }
            };
            wit.push(ms.encode().into_bytes());
            wit.push(control_block.serialize());
            let wit_len = Some(super::witness_size(&wit));
            if min_wit_len.is_some() && wit_len > min_wit_len {
                continue;
            } else {
                // store the minimum
                min_wit = Some(wit);
                min_wit_len = wit_len;
            }
        }
        min_wit.ok_or(InputError::CouldNotSatisfyTr)
    } else {
        // No control blocks found
        Err(InputError::CouldNotSatisfyTr)
    }
}

/// Error constructing a [`Finalizer`] or finalizing a PSBT.
#[derive(Debug)]
#[non_exhaustive]
pub enum FinalizeError {
    /// An input is missing its funding UTXO.
    FundingUtxo(FundingUtxoError),
    /// An input has a signature whose sighash type differs from the required type.
    SignatureSighashType(SignatureSighashTypeError),
    /// Failed to finalize an input.
    Input {
        /// The associated input index for `error`.
        input_index: usize,
        /// Error finalizing input.
        error: InputError,
    },
    /// Failed to construct a [`miniscript::Interpreter`] during the interpreter check.
    InterpreterConstructor {
        /// Index of the input causing this error.
        input_index: usize,
        /// The interpreter error returned from `rust-miniscript`.
        error: interpreter::Error,
    },
    /// Interpreter satisfaction failed for an input during the interpreter check.
    InterpreterSatisfaction {
        /// Index of the input causing this error.
        input_index: usize,
        /// The interpreter error returned from `rust-miniscript`.
        error: interpreter::Error,
    },
}

impl fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FundingUtxo(ref e) => write_err!(f, "finalizer missing funding UTXO"; e),
            Self::SignatureSighashType(ref e) => write_err!(f, "finalizer sighash type error"; e),
            Self::Input { input_index, ref error } =>
                write_err!(f, "failed to finalize input at index {}", input_index; error),
            Self::InterpreterConstructor { input_index, ref error } =>
                write_err!(f, "interpreter constructor failed for input {}", input_index; error),
            Self::InterpreterSatisfaction { input_index, ref error } =>
                write_err!(f, "interpreter satisfaction failed for input {}", input_index; error),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FinalizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FundingUtxo(ref e) => Some(e),
            Self::SignatureSighashType(ref e) => Some(e),
            Self::Input { input_index: _, ref error } => Some(error),
            Self::InterpreterConstructor { input_index: _, ref error } => Some(error),
            Self::InterpreterSatisfaction { input_index: _, ref error } => Some(error),
        }
    }
}

/// Error type for Pbst Input
#[derive(Debug)]
#[non_exhaustive]
pub enum InputError {
    /// Key errors
    KeyErr(bitcoin::key::FromSliceError),
    /// Could not satisfy taproot descriptor
    /// This error is returned when both script path and key paths could not be
    /// satisfied. We cannot return a detailed error because we try all miniscripts
    /// in script spend path, we cannot know which miniscript failed.
    CouldNotSatisfyTr,
    /// Redeem script does not match the p2sh hash
    InvalidRedeemScript {
        /// Redeem script
        redeem: ScriptBuf,
        /// Expected p2sh Script
        p2sh_expected: ScriptBuf,
    },
    /// Witness script does not match the p2wsh hash
    InvalidWitnessScript {
        /// Witness Script
        witness_script: ScriptBuf,
        /// Expected p2wsh script
        p2wsh_expected: ScriptBuf,
    },
    /// Pass through the underlying errors in miniscript
    MiniscriptError(miniscript::Error),
    /// Missing redeem script for p2sh
    MissingRedeemScript,
    /// used for public key corresponding to pkh/wpkh
    MissingPubkey,
    /// Missing witness script for segwit descriptors
    MissingWitnessScript,
    /// Non empty Witness script for p2sh
    NonEmptyWitnessScript,
    /// Non empty Redeem script
    NonEmptyRedeemScript,
    /// Unable to determine the output type from the script pubkey.
    UnknownOutputType,
}

#[cfg(feature = "std")]
impl std::error::Error for InputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CouldNotSatisfyTr
            | Self::InvalidRedeemScript { .. }
            | Self::InvalidWitnessScript { .. }
            | Self::MissingRedeemScript
            | Self::MissingPubkey
            | Self::MissingWitnessScript
            | Self::NonEmptyWitnessScript
            | Self::NonEmptyRedeemScript
            | Self::UnknownOutputType => None,
            Self::KeyErr(e) => Some(e),
            Self::MiniscriptError(e) => Some(e),
        }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::KeyErr(ref e) => write!(f, "Key Err: {}", e),
            Self::InvalidRedeemScript { ref redeem, ref p2sh_expected } => write!(
                f,
                "Redeem script {} does not match the p2sh script {}",
                redeem, p2sh_expected
            ),
            Self::InvalidWitnessScript { ref witness_script, ref p2wsh_expected } => write!(
                f,
                "Witness script {} does not match the p2wsh script {}",
                witness_script, p2wsh_expected
            ),
            Self::MiniscriptError(ref e) => write!(f, "Miniscript Error: {}", e),
            Self::MissingRedeemScript => write!(f, "PSBT is Redeem script"),
            Self::MissingWitnessScript => write!(f, "PSBT is missing witness script"),
            Self::MissingPubkey => write!(f, "Missing pubkey for a pkh/wpkh"),
            Self::NonEmptyRedeemScript => {
                write!(f, "PSBT has non-empty redeem script at for legacy transactions")
            }
            Self::NonEmptyWitnessScript => {
                write!(f, "PSBT has non-empty witness script at for legacy input")
            }
            Self::CouldNotSatisfyTr => write!(f, "Could not satisfy Tr descriptor"),
            Self::UnknownOutputType => write!(f, "unable to determine the output type"),
        }
    }
}
