// SPDX-License-Identifier: CC0-1.0

//! Implementation of the Finalizer role as defined in [BIP-174].
//!
//! # Finalizer Role
//!
//! > For each input, the Input Finalizer determines if the input has enough data to pass validation.
//!
//! Determining if a PSBT has enough data to satisfy the spending conditions of all its inputs
//! requires usage of `rust-miniscript`.
//!
//! # Extractor Role
//!
//! > The Transaction Extractor does not need to know how to interpret scripts in order
//! > to extract the network serialized transaction.
//!
//! The Extractor role does not technically require `rust-miniscript` but since a PSBT must be

//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

mod role;
mod satisfy;

use alloc::borrow::Borrow;
use alloc::vec::Vec;
use core::fmt;

use bitcoin::consensus::encode::VarInt;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::sighash::Prevouts;
use bitcoin::{Script, Sequence, Transaction, TxOut, Witness};
use miniscript::miniscript::satisfy::Placeholder;
use miniscript::{interpreter, Interpreter, MiniscriptKey};

use crate::error::write_err;
use crate::map::input::Input;
use crate::psbt::Psbt;
use crate::DetermineLockTimeError;

#[rustfmt::skip]                // Keep public exports separate.
pub use self::role::{InputError, Finalizer, FinalizeError, FinalizeInputError};

impl Psbt {
    // TODO: Should this be on a Role? Finalizer/Extractor? Then we can remove the debug_assert
    /// Interprets all PSBT inputs and checks whether the script is correctly interpreted according
    /// to the context.
    ///
    /// The psbt must have included final script sig and final witness. In other words, this checks
    /// whether the finalized psbt interprets correctly
    pub fn interpreter_check<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
    ) -> Result<(), InterpreterCheckError> {
        debug_assert!(self.is_finalized());

        let unsigned_tx = self.unsigned_tx()?; // Used to verify signatures.

        let utxos: Vec<&TxOut> = self
            .iter_funding_utxos()
            .map(|res| res.expect("finalized PSBT has funding utxos"))
            .collect();
        let utxos = &Prevouts::All(&utxos);
        // Inputs spending legacy outputs have no final script witness, and vice versa for the
        // final script sig of witness spends.
        for (index, input) in self.inputs.iter().enumerate() {
            self.interpreter_check_input(
                secp,
                &unsigned_tx,
                index,
                input,
                utxos,
                input.final_script_witness.as_ref().unwrap_or(&Witness::default()),
                input.final_script_sig.as_deref().unwrap_or(Script::new()),
            )?;
        }
        Ok(())
    }

    /// Runs the miniscript interpreter on a single psbt input.
    #[allow(clippy::too_many_arguments)] // TODO: Remove this.
    fn interpreter_check_input<C: Verification, T: Borrow<TxOut>>(
        &self,
        secp: &Secp256k1<C>,
        unsigned_tx: &Transaction,
        index: usize,
        input: &Input,
        utxos: &Prevouts<T>,
        witness: &Witness,
        script_sig: &Script,
    ) -> Result<(), InterpreterCheckInputError> {
        let spk = &input.funding_utxo().expect("have funding utxo").script_pubkey;

        // TODO: Check that this is correct?
        let cltv = input.lock_time();
        // TODO: is this usage of MAX correct?
        let csv = input.sequence.unwrap_or(Sequence::MAX);

        let interpreter =
            Interpreter::from_txdata(spk, script_sig, witness, csv, cltv).map_err(|error| {
                InterpreterCheckInputError::Constructor { input_index: index, error }
            })?;

        let iter = interpreter.iter(secp, unsigned_tx, index, utxos);
        // TODO: Ok to just return the first satisfaction error?
        if let Some(error) = iter.filter_map(Result::err).next() {
            return Err(InterpreterCheckInputError::Satisfaction { input_index: index, error });
        };

        Ok(())
    }
}

pub(crate) trait ItemSize {
    fn size(&self) -> usize;
}

impl<Pk: MiniscriptKey> ItemSize for Placeholder<Pk> {
    fn size(&self) -> usize {
        match self {
            Self::Pubkey(_, size) => *size,
            Self::PubkeyHash(_, size) => *size,
            Self::EcdsaSigPk(_) | Self::EcdsaSigPkHash(_) => 73,
            Self::SchnorrSigPk(_, _, size) | Self::SchnorrSigPkHash(_, _, size) => size + 1, // +1 for the OP_PUSH
            Self::HashDissatisfaction
            | Self::Sha256Preimage(_)
            | Self::Hash256Preimage(_)
            | Self::Ripemd160Preimage(_)
            | Self::Hash160Preimage(_) => 33,
            Self::PushOne => 2, // On legacy this should be 1 ?
            Self::PushZero => 1,
            Self::TapScript(s) => s.len(),
            Self::TapControlBlock(cb) => cb.serialize().len(),
        }
    }
}

impl ItemSize for Vec<u8> {
    fn size(&self) -> usize { self.len() }
}

// Helper function to calculate witness size
pub(crate) fn witness_size<T: ItemSize>(wit: &[T]) -> usize {
    wit.iter().map(T::size).sum::<usize>() + varint_len(wit.len())
}

pub(crate) fn varint_len(n: usize) -> usize { VarInt(n as u64).size() }

/// Error type for Pbst Input
#[derive(Debug)]
pub enum InterpreterCheckError {
    /// Failed to determine lock time for unsigned transaction.
    DetermineLockTime(DetermineLockTimeError),
    /// Interpreter check failed for an input.
    InterpreterCheckInput(InterpreterCheckInputError),
}

impl fmt::Display for InterpreterCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DetermineLockTime(ref e) =>
                write_err!(f, "interpreter check determine locktime"; e),
            Self::InterpreterCheckInput(ref e) =>
                write_err!(f, "interpreter check failed for input"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InterpreterCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DetermineLockTime(ref e) => Some(e),
            Self::InterpreterCheckInput(ref e) => Some(e),
        }
    }
}

impl From<DetermineLockTimeError> for InterpreterCheckError {
    fn from(e: DetermineLockTimeError) -> Self { Self::DetermineLockTime(e) }
}

impl From<InterpreterCheckInputError> for InterpreterCheckError {
    fn from(e: InterpreterCheckInputError) -> Self { Self::InterpreterCheckInput(e) }
}

/// Error type for Pbst Input
#[derive(Debug)]
pub enum InterpreterCheckInputError {
    /// Failed to construct a [`miniscript::Interpreter`].
    Constructor {
        /// Index of the input causing this error.
        input_index: usize,
        /// The interpreter error returned from `rust-miniscript`.
        error: interpreter::Error,
    },
    /// Interpreter satisfaction failed for input.
    Satisfaction {
        /// Index of the input causing this error.
        input_index: usize,
        /// The interpreter error returned from `rust-miniscript`.
        error: interpreter::Error,
    },
}

impl fmt::Display for InterpreterCheckInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Constructor { input_index, ref error } => {
                write_err!(f, "interpreter constructor failed for input {}", input_index; error)
            }
            Self::Satisfaction { input_index, ref error } => {
                write_err!(f, "interpreter satisfaction failed for input {}", input_index; error)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InterpreterCheckInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Constructor { input_index: _, ref error } => Some(error),
            Self::Satisfaction { input_index: _, ref error } => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {

    use bitcoin::bip32::{IntoDerivationPath, Xpriv};
    use bitcoin::{Amount, OutPoint, PublicKey, ScriptBuf, TxOut};

    use super::*;
    use crate::roles::{Creator, Signer};
    use crate::{Input, Output, SignableInput};

    const TEST_XPRIV: &str =
        "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";

    /// Signs `psbt` with the fixture key (`TEST_XPRIV`).
    fn sign(psbt: Psbt) -> Psbt {
        let secp = Secp256k1::new();
        let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
        let inputs_len = psbt.inputs.len();
        let mut signer = Signer::new(psbt).expect("test env, psbt should be well formed");
        let sigs = {
            let mut session = signer.session();
            let inputs: Vec<SignableInput> = (0..inputs_len)
                .map(|x| {
                    session.assume_checked_input(x).expect(
                        "test env, input
                        should be well formed",
                    )
                })
                .collect();
            session.get_all(&inputs, &xpriv, &secp)
        };
        signer
            .apply(sigs)
            .expect("signature created in this same function, should be within bounds")
    }

    /// Builds a signed P2WPKH PSBT: the fixture signed with `TEST_XPRIV`.
    fn signed_psbt() -> Psbt { sign(unsigned_psbt()) }

    /// Builds the unsigned P2WPKH PSBT fixture (before signing).
    fn unsigned_psbt() -> Psbt {
        let secp = Secp256k1::new();
        let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
        let path = "m/0".into_derivation_path().unwrap();
        let pk =
            PublicKey::new(xpriv.derive_priv(&secp, &path).unwrap().to_keypair(&secp).public_key());

        let mut input = Input::new(&OutPoint::null());
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
        });
        input.bip32_derivations.insert(pk, (xpriv.fingerprint(&secp), path));

        Creator::new()
            .constructor_modifiable()
            .input(input)
            .output(Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
            }))
            .expect("fixture output must be valid")
            .psbt()
            .unwrap()
    }

    #[test]
    fn interpreter_check_rejects_tampered_witness() {
        let secp = Secp256k1::verification_only();
        let signed = signed_psbt();
        let pk_bytes = signed.inputs[0].bip32_derivations.keys().next().unwrap().to_bytes();
        let finalizer = Finalizer::new(signed).unwrap();
        let mut finalized = finalizer.finalize(&secp).expect("valid psbt must finalize");

        // A correctly finalized PSBT passes the interpreter check.
        finalized.interpreter_check(&secp).expect("valid finalized psbt must pass");

        // Tamper with the final script witness so the interpreter rejects the input.
        let witness = finalized.inputs[0].final_script_witness.as_mut().unwrap();
        witness.clear();
        witness.push([1u8; 64]); // garbage "signature"
        witness.push(pk_bytes);

        assert!(finalized.interpreter_check(&secp).is_err(), "tampered witness must be rejected");
    }

    #[test]
    fn finalize_skips_already_finalized_input() {
        // A finalized input must pass through the finalizer unchanged.
        let secp = Secp256k1::verification_only();
        let signed = signed_psbt();
        let finalizer = Finalizer::new(signed).unwrap();
        let finalized = finalizer.finalize(&secp).expect("valid psbt must finalize");

        // Finalizing again must leave the already-finalized input untouched.
        let out = Finalizer::new(finalized.clone()).unwrap().finalize(&secp).unwrap();

        assert_eq!(out.inputs[0], finalized.inputs[0]);
    }

    #[test]
    fn finalize_preserves_sequence_used_in_signature() {
        // Sign with a non-default sequence so the signature commits to it.
        let mut unsigned = unsigned_psbt();
        unsigned.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let secp = Secp256k1::verification_only();
        Finalizer::new(sign(unsigned))
            .unwrap()
            .finalize(&secp)
            .expect("finalize must preserve the sequence the signature commits to");
    }

    #[test]
    fn finalize_preserves_lock_time_used_in_signature() {
        // Sign with a required height lock time so the signature commits to the lock time.
        let mut unsigned = unsigned_psbt();
        unsigned.inputs[0].min_height =
            Some(bitcoin::locktime::absolute::Height::from_consensus(800_000).unwrap());
        unsigned.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let secp = Secp256k1::verification_only();
        Finalizer::new(sign(unsigned))
            .unwrap()
            .finalize(&secp)
            .expect("finalize must preserve the lock time the signature commits to");
    }
}
