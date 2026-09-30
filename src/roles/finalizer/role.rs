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
use bitcoin::taproot::LeafVersion;
use bitcoin::{sighash, Address, Network, Script, ScriptBuf, Txid, Witness, XOnlyPublicKey};
use miniscript::{
    interpreter, BareCtx, Descriptor, Legacy, Miniscript, Satisfier, Segwitv0, SigType, Tap,
    ToPublicKey,
};

use super::satisfy::InputSatisfier;
use super::InterpreterCheckError;
use crate::error::{write_err, FundingUtxoError};
use crate::map::input::{self, Input};
use crate::psbt::Psbt;
use crate::{DetermineLockTimeError, PartialSigsSighashTypeError};

/// Implements the BIP-370 Finalized role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Finalizer(Psbt);

impl Finalizer {
    /// Creates an `Finalizer`.
    ///
    /// A finalizer can only be created if all inputs have a funding UTXO.
    pub fn new(psbt: Psbt) -> Result<Self, Error> {
        // TODO: Consider doing this with combinators.
        for input in psbt.inputs.iter() {
            let _ = input.funding_utxo()?;
        }
        let _ = psbt.determine_lock_time()?;
        psbt.check_partial_sigs_sighash_type()?;

        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Finalizer guarantees lock time can be determined")
    }

    /// Finalize the PSBT.
    ///
    /// # Returns
    ///
    /// Returns the finalized PSBT without modifying the original.
    #[must_use = "returns the finalized PSBT without modifying the original"]
    pub fn finalize<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<Psbt, FinalizeError> {
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
                Err(error) => return Err(FinalizeError::FinalizeInput { input_index, error }),
            }
        }

        let finalized =
            Psbt { global: self.0.global.clone(), inputs, outputs: self.0.outputs.to_vec() };

        finalized.interpreter_check(secp)?;
        Ok(finalized)
    }

    // `index` must be the input index of `input` which references an input in `self` - this gets rid of out-of-bounds error path.
    fn finalize_input(&self, input: &Input) -> Result<Input, FinalizeInputError> {
        let allow_mall = true; // TODO: Add mall and no-mall versions.
        let (script_sig, witness) = self.final_script_sig_and_witness(input, allow_mall)?;

        input.finalize(script_sig, witness).map_err(From::from)
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
    ) -> Result<(ScriptBuf, Witness), InputError> {
        let (witness, script_sig) = {
            let spk =
                &input.funding_utxo().expect("guaranteed by Finalizer invariant").script_pubkey;
            let sat = InputSatisfier { input };

            if spk.is_p2tr() {
                // Deal with taproot case separately, we cannot infer the full descriptor for taproot.
                let wit = construct_tap_witness(spk, sat, allow_mall)?;
                (wit, ScriptBuf::new())
            } else {
                // Get a descriptor for this input.
                let desc = self.get_descriptor(input)?;

                // Generate the satisfaction witness and scriptsig.
                if !allow_mall {
                    desc.get_satisfaction(sat)?
                } else {
                    desc.get_satisfaction_mall(sat)?
                }
            }
        };

        let witness = Witness::from_slice(&witness);
        Ok((script_sig, witness))
    }

    /// Creates a descriptor from an unfinalized PSBT input.
    ///
    /// Panics on out of bound input index for psbt Also sanity checks that the witness script and
    /// redeem script are consistent with the script pubkey. Does *not* check signatures We parse
    /// the insane version while satisfying because we want to move the script is probably already
    /// created and we want to satisfy it in any way possible.
    fn get_descriptor(&self, input: &Input) -> Result<Descriptor<bitcoin::PublicKey>, InputError> {
        let mut map: BTreeMap<hash160::Hash, bitcoin::PublicKey> = BTreeMap::new();

        // TODO(Tobin): Understand why we use keys from all inputs?
        let psbt_inputs = &self.0.inputs;
        for psbt_input in psbt_inputs {
            // Use BIP32 Derviation to get set of all possible keys.
            let public_keys = psbt_input.bip32_derivations.keys();
            for key in public_keys {
                let bitcoin_key = *key;
                let hash = bitcoin_key.pubkey_hash().to_raw_hash();
                map.insert(hash, bitcoin_key);
            }
        }

        // Figure out Scriptpubkey
        let script_pubkey = &input.funding_utxo().expect("guaranteed by Finalizer").script_pubkey;
        // 1. `PK`: creates a `Pk` descriptor(does not check if partial sig is given)
        if script_pubkey.is_p2pk() {
            let script_pubkey_len = script_pubkey.len();
            let pk_bytes = &script_pubkey.to_bytes();
            match bitcoin::PublicKey::from_slice(&pk_bytes[1..script_pubkey_len - 1]) {
                Ok(pk) => Ok(Descriptor::new_pk(pk)),
                Err(e) => Err(InputError::from(e)),
            }
        } else if script_pubkey.is_p2pkh() {
            // 2. `Pkh`: creates a `PkH` descriptor if partial_sigs has the corresponding pk
            let partial_sig_contains_pk = input.partial_sigs.iter().find(|&(&pk, _sig)| {
                // Indirect way to check the equivalence of pubkey-hashes.
                // Create a pubkey hash and check if they are the same.
                // THIS IS A BUG AND *WILL* PRODUCE WRONG SATISFACTIONS FOR UNCOMPRESSED KEYS
                // Partial sigs loses the compressed flag that is necessary
                // TODO: See https://github.com/rust-bitcoin/rust-bitcoin/pull/836
                // The type checker will fail again after we update to 0.28 and this can be removed
                let addr = Address::p2pkh(pk, Network::Bitcoin);
                *script_pubkey == addr.script_pubkey()
            });
            match partial_sig_contains_pk {
                Some((pk, _sig)) => Descriptor::new_pkh(*pk).map_err(InputError::from),
                None => Err(InputError::MissingPubkey),
            }
        } else if script_pubkey.is_p2wpkh() {
            // 3. `Wpkh`: creates a `wpkh` descriptor if the partial sig has corresponding pk.
            let partial_sig_contains_pk = input.partial_sigs.iter().find(|&(&pk, _sig)| {
                match bitcoin::key::CompressedPublicKey::try_from(pk) {
                    Ok(compressed) => {
                        // Indirect way to check the equivalence of pubkey-hashes.
                        // Create a pubkey hash and check if they are the same.
                        let addr = bitcoin::Address::p2wpkh(&compressed, bitcoin::Network::Bitcoin);
                        *script_pubkey == addr.script_pubkey()
                    }
                    Err(_) => false,
                }
            });
            match partial_sig_contains_pk {
                Some((pk, _sig)) => Ok(Descriptor::new_wpkh(*pk)?),
                None => Err(InputError::MissingPubkey),
            }
        } else if script_pubkey.is_p2wsh() {
            // 4. `Wsh`: creates a `Wsh` descriptor
            if input.redeem_script.is_some() {
                return Err(InputError::NonEmptyRedeemScript);
            }
            if let Some(ref witness_script) = input.witness_script {
                if witness_script.to_p2wsh() != *script_pubkey {
                    return Err(InputError::InvalidWitnessScript {
                        witness_script: witness_script.clone(),
                        p2wsh_expected: script_pubkey.clone(),
                    });
                }
                let ms =
                    Miniscript::<bitcoin::PublicKey, Segwitv0>::decode_consensus(witness_script)?;
                Ok(Descriptor::new_wsh(ms.substitute_raw_pkh(&map))?)
            } else {
                Err(InputError::MissingWitnessScript)
            }
        } else if script_pubkey.is_p2sh() {
            match input.redeem_script {
                None => Err(InputError::MissingRedeemScript),
                Some(ref redeem_script) => {
                    if redeem_script.to_p2sh() != *script_pubkey {
                        return Err(InputError::InvalidRedeemScript {
                            redeem: redeem_script.clone(),
                            p2sh_expected: script_pubkey.clone(),
                        });
                    }
                    if redeem_script.is_p2wsh() {
                        // 5. `ShWsh` case
                        if let Some(ref witness_script) = input.witness_script {
                            if witness_script.to_p2wsh() != *redeem_script {
                                return Err(InputError::InvalidWitnessScript {
                                    witness_script: witness_script.clone(),
                                    p2wsh_expected: redeem_script.clone(),
                                });
                            }
                            let ms = Miniscript::<bitcoin::PublicKey, Segwitv0>::decode_consensus(
                                witness_script,
                            )?;
                            Ok(Descriptor::new_sh_wsh(ms.substitute_raw_pkh(&map))?)
                        } else {
                            Err(InputError::MissingWitnessScript)
                        }
                    } else if redeem_script.is_p2wpkh() {
                        // 6. `ShWpkh` case
                        let partial_sig_contains_pk =
                            input.partial_sigs.iter().find(|&(&pk, _sig)| {
                                match bitcoin::key::CompressedPublicKey::try_from(pk) {
                                    Ok(compressed) => {
                                        let addr = bitcoin::Address::p2wpkh(
                                            &compressed,
                                            bitcoin::Network::Bitcoin,
                                        );
                                        *redeem_script == addr.script_pubkey()
                                    }
                                    Err(_) => false,
                                }
                            });
                        match partial_sig_contains_pk {
                            Some((pk, _sig)) => Ok(Descriptor::new_sh_wpkh(*pk)?),
                            None => Err(InputError::MissingPubkey),
                        }
                    } else {
                        //7. regular p2sh
                        if input.witness_script.is_some() {
                            return Err(InputError::NonEmptyWitnessScript);
                        }
                        if let Some(ref redeem_script) = input.redeem_script {
                            let ms = Miniscript::<bitcoin::PublicKey, Legacy>::decode_consensus(
                                redeem_script,
                            )?;
                            Ok(Descriptor::new_sh(ms)?)
                        } else {
                            Err(InputError::MissingWitnessScript)
                        }
                    }
                }
            }
        } else {
            // 8. Bare case
            if input.witness_script.is_some() {
                return Err(InputError::NonEmptyWitnessScript);
            }
            if input.redeem_script.is_some() {
                return Err(InputError::NonEmptyRedeemScript);
            }
            let ms = Miniscript::<bitcoin::PublicKey, BareCtx>::decode_consensus(script_pubkey)?;
            Ok(Descriptor::new_bare(ms.substitute_raw_pkh(&map))?)
        }
    }
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
    let mut map: BTreeMap<hash160::Hash, XOnlyPublicKey> = BTreeMap::new();

    // We need to satisfy or dissatisfy any given key. `tap_key_origin` is the only field of PSBT
    // Input which consist of all the keys added on a descriptor and thus we get keys from it.
    let public_keys = sat.input.tap_key_origins.keys();
    for key in public_keys {
        // TODO: How is this key converting to a miniscript::interpreter::BitcoinKey?
        // let hash = key.to_pubkeyhash(SigType::Schnorr);
        let bitcoin_key = *key;
        let hash = bitcoin_key.to_pubkeyhash(SigType::Schnorr);

        map.insert(hash, *key);
    }

    // try the key spend path first
    if let Some(ref key) = sat.input.tap_internal_key {
        if let Some(sig) =
            <InputSatisfier as Satisfier<XOnlyPublicKey>>::lookup_tap_key_spend_sig(&sat, key)
        {
            return Ok(vec![sig.to_vec()]);
        }
    }
    // Next script spends
    let (mut min_wit, mut min_wit_len) = (None, None);
    if let Some(block_map) =
        <InputSatisfier as Satisfier<XOnlyPublicKey>>::lookup_tap_control_block_map(&sat)
    {
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

/// Error constructing a [`Finalizer`].
#[derive(Debug)]
pub enum Error {
    /// An input is missing its funding UTXO.
    FundingUtxo(FundingUtxoError),
    /// Finalizer must be able to determine the lock time.
    DetermineLockTime(DetermineLockTimeError),
    /// An input has incorrect sighash type for its partial sigs (ECDSA).
    PartialSigsSighashType(PartialSigsSighashTypeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FundingUtxo(ref e) => write_err!(f, "Finalizer missing funding UTXO"; e),
            Self::DetermineLockTime(ref e) =>
                write_err!(f, "Finalizer must be able to determine the lock time"; e),
            Self::PartialSigsSighashType(ref e) => write_err!(f, "Finalizer sighash type error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FundingUtxo(ref e) => Some(e),
            Self::DetermineLockTime(ref e) => Some(e),
            Self::PartialSigsSighashType(ref e) => Some(e),
        }
    }
}

impl From<FundingUtxoError> for Error {
    fn from(e: FundingUtxoError) -> Self { Self::FundingUtxo(e) }
}

impl From<DetermineLockTimeError> for Error {
    fn from(e: DetermineLockTimeError) -> Self { Self::DetermineLockTime(e) }
}

impl From<PartialSigsSighashTypeError> for Error {
    fn from(e: PartialSigsSighashTypeError) -> Self { Self::PartialSigsSighashType(e) }
}

/// Error finalizing an input.
#[derive(Debug)]
pub enum FinalizeError {
    /// Error finalizing an input.
    FinalizeInput {
        /// The associated input index for `error`.
        input_index: usize,
        /// Error finalizing input.
        error: FinalizeInputError,
    },
    /// Error running the interpreter checks.
    InterpreterCheck(InterpreterCheckError),
}

impl fmt::Display for FinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FinalizeInput { input_index, ref error } =>
                write_err!(f, "failed to finalize input at index {}", input_index; error),
            Self::InterpreterCheck(ref e) =>
                write_err!(f, "error running the interpreter checks"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FinalizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FinalizeInput { input_index: _, ref error } => Some(error),
            Self::InterpreterCheck(ref error) => Some(error),
        }
    }
}

impl From<InterpreterCheckError> for FinalizeError {
    fn from(e: InterpreterCheckError) -> Self { Self::InterpreterCheck(e) }
}

/// Error finalizing an input.
#[derive(Debug)]
pub enum FinalizeInputError {
    /// Failed to get final script_sig and final witness.
    Final(InputError),
    /// Failed to create a finalized input from final fields.
    Input(input::FinalizeError),
}

impl fmt::Display for FinalizeInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Final(ref e) => write_err!(f, "final"; e),
            Self::Input(ref e) => write_err!(f, "input"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FinalizeInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Final(ref e) => Some(e),
            Self::Input(ref e) => Some(e),
        }
    }
}

impl From<InputError> for FinalizeInputError {
    fn from(e: InputError) -> Self { Self::Final(e) }
}

impl From<input::FinalizeError> for FinalizeInputError {
    fn from(e: input::FinalizeError) -> Self { Self::Input(e) }
}

/// Error type for Pbst Input
#[derive(Debug)]
pub enum InputError {
    /// Get the secp Errors directly
    SecpErr(bitcoin::secp256k1::Error),
    /// Key errors
    KeyErr(bitcoin::key::FromSliceError),
    /// Could not satisfy taproot descriptor
    /// This error is returned when both script path and key paths could not be
    /// satisfied. We cannot return a detailed error because we try all miniscripts
    /// in script spend path, we cannot know which miniscript failed.
    CouldNotSatisfyTr,
    /// Error doing an interpreter-check on a finalized psbt
    Interpreter(interpreter::Error),
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
    /// Invalid sig
    InvalidSignature {
        /// The bitcoin public key
        pubkey: bitcoin::PublicKey,
        /// The (incorrect) signature
        sig: Vec<u8>,
    },
    /// Pass through the underlying errors in miniscript
    MiniscriptError(miniscript::Error),
    /// Missing redeem script for p2sh
    MissingRedeemScript,
    /// Missing witness
    MissingWitness,
    /// used for public key corresponding to pkh/wpkh
    MissingPubkey,
    /// Missing witness script for segwit descriptors
    MissingWitnessScript,
    ///Missing both the witness and non-witness utxo
    MissingUtxo,
    /// Non empty Witness script for p2sh
    NonEmptyWitnessScript,
    /// Non empty Redeem script
    NonEmptyRedeemScript,
    /// Non Standard sighash type
    NonStandardSighashType(sighash::NonStandardSighashTypeError),
    /// Sighash did not match
    WrongSighashFlag {
        /// required sighash type
        required: sighash::EcdsaSighashType,
        /// the sighash type we got
        got: sighash::EcdsaSighashType,
        /// the corresponding publickey
        pubkey: bitcoin::PublicKey,
    },
}

#[cfg(feature = "std")]
impl std::error::Error for InputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CouldNotSatisfyTr
            | Self::InvalidRedeemScript { .. }
            | Self::InvalidWitnessScript { .. }
            | Self::InvalidSignature { .. }
            | Self::MissingRedeemScript
            | Self::MissingWitness
            | Self::MissingPubkey
            | Self::MissingWitnessScript
            | Self::MissingUtxo
            | Self::NonEmptyWitnessScript
            | Self::NonEmptyRedeemScript
            | Self::NonStandardSighashType(_)
            | Self::WrongSighashFlag { .. } => None,
            Self::SecpErr(e) => Some(e),
            Self::KeyErr(e) => Some(e),
            Self::Interpreter(e) => Some(e),
            Self::MiniscriptError(e) => Some(e),
        }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidSignature { ref pubkey, ref sig } => {
                write!(f, "PSBT: bad signature {} for key {:?}", pubkey, sig)
            }
            Self::KeyErr(ref e) => write!(f, "Key Err: {}", e),
            Self::Interpreter(ref e) => write!(f, "Interpreter: {}", e),
            Self::SecpErr(ref e) => write!(f, "Secp Err: {}", e),
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
            Self::MissingWitness => write!(f, "PSBT is missing witness"),
            Self::MissingRedeemScript => write!(f, "PSBT is Redeem script"),
            Self::MissingUtxo => {
                write!(f, "PSBT is missing both witness and non-witness UTXO")
            }
            Self::MissingWitnessScript => write!(f, "PSBT is missing witness script"),
            Self::MissingPubkey => write!(f, "Missing pubkey for a pkh/wpkh"),
            Self::NonEmptyRedeemScript => {
                write!(f, "PSBT has non-empty redeem script at for legacy transactions")
            }
            Self::NonEmptyWitnessScript => {
                write!(f, "PSBT has non-empty witness script at for legacy input")
            }
            Self::WrongSighashFlag { required, got, pubkey } => write!(
                f,
                "PSBT: signature with key {:?} had \
                 sighashflag {:?} rather than required {:?}",
                pubkey, got, required
            ),

            Self::CouldNotSatisfyTr => write!(f, "Could not satisfy Tr descriptor"),
            Self::NonStandardSighashType(ref e) => write!(f, "Non-standard sighash type {}", e),
        }
    }
}

impl From<crate::miniscript::Error> for InputError {
    fn from(e: crate::miniscript::Error) -> Self { Self::MiniscriptError(e) }
}

impl From<interpreter::Error> for InputError {
    fn from(e: interpreter::Error) -> Self { Self::Interpreter(e) }
}

impl From<bitcoin::secp256k1::Error> for InputError {
    fn from(e: bitcoin::secp256k1::Error) -> Self { Self::SecpErr(e) }
}

impl From<bitcoin::key::FromSliceError> for InputError {
    fn from(e: bitcoin::key::FromSliceError) -> Self { Self::KeyErr(e) }
}
