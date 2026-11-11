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

use alloc::vec::Vec;

use bitcoin::consensus::encode::VarInt;
use miniscript::miniscript::satisfy::Placeholder;
use miniscript::MiniscriptKey;

#[rustfmt::skip]                // Keep public exports separate.
pub use self::role::{InputError, Finalizer, FinalizeError};

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

#[cfg(test)]
mod tests {

    use alloc::format;
    use core::str::FromStr;

    use bitcoin::bip32::{IntoDerivationPath, Xpriv};
    use bitcoin::hashes::Hash as _;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{absolute, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TxOut, Txid};
    use miniscript::{Miniscript, Segwitv0};

    use super::*;
    use crate::map::input::Input;
    use crate::psbt::Psbt;
    use crate::roles::{Creator, Signer};
    use crate::{Count, Output, RequiredHeightLockTime};

    const TEST_XPRIV: &str =
        "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";

    #[test]
    fn new_rejects_taproot_key_sighash_mismatch() {
        let output_key = bitcoin::XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let mut input = Input::new(&OutPoint::null());
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_p2tr(&Secp256k1::verification_only(), output_key, None),
        });
        input.sighash_type = Some(crate::PsbtSighashType::ALL);
        input.tap_key_sig = Some(bitcoin::taproot::Signature {
            signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&[1u8; 64]).unwrap(),
            sighash_type: bitcoin::TapSighashType::Default,
        });
        let psbt = Psbt {
            global: crate::Global {
                input_count: Count::from(1),
                output_count: Count::from(1),
                ..Default::default()
            },
            inputs: alloc::vec![input],
            outputs: alloc::vec![Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            })],
        };

        match Finalizer::new(psbt) {
            Err(FinalizeError::SignatureSighashType(e)) => {
                assert_eq!(e.input_index, 0);
                assert_eq!(e.source, crate::SignatureSource::TapKey);
                assert!(alloc::format!("{}", e).starts_with("input 0 taproot key-spend signature "));
            }
            other => panic!("expected a sighash type error, got {:?}", other),
        }
    }

    #[test]
    fn new_refuses_undeclared_sighash_none() {
        // SIGHASH_NONE commits to no output, so it needs an explicit PSBT_IN_SIGHASH_TYPE.
        let mut psbt = unsigned_psbt();
        psbt.inputs[0].sighash_type = Some(bitcoin::EcdsaSighashType::None.into());
        let mut signed = sign(psbt);
        signed.inputs[0].sighash_type = None;

        assert!(
            matches!(Finalizer::new(signed), Err(FinalizeError::SignatureSighashType(_))),
            "finalizer must reject undeclared SIGHASH_NONE with a sighash type error"
        );
    }

    /// Returns the sighash type error `Finalizer::new` reports for `psbt`.
    fn sighash_type_error(psbt: Psbt) -> crate::SignatureSighashTypeError {
        match Finalizer::new(psbt) {
            Err(FinalizeError::SignatureSighashType(e)) => e,
            other => panic!("expected a sighash type error, got {:?}", other),
        }
    }

    fn ecdsa_sig(sighash_type: bitcoin::EcdsaSighashType) -> bitcoin::ecdsa::Signature {
        bitcoin::ecdsa::Signature {
            signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&[1u8; 64]).unwrap(),
            sighash_type,
        }
    }

    #[test]
    fn new_rejects_ecdsa_sighash_mismatch() {
        let mut psbt = unsigned_psbt();
        let pubkey = PublicKey::from_slice(&[2u8; 33]).unwrap();
        psbt.inputs[0].sighash_type = Some(crate::PsbtSighashType::ALL);
        psbt.inputs[0].partial_sigs.insert(pubkey, ecdsa_sig(bitcoin::EcdsaSighashType::None));

        let error = sighash_type_error(psbt);
        assert_eq!(error.source, crate::SignatureSource::Ecdsa(pubkey));
        assert_eq!(error.declared, Some(crate::PsbtSighashType::ALL));
    }

    #[test]
    fn new_rejects_undeclared_ecdsa_sighash_type() {
        // With no declared type, an ECDSA signature must use SIGHASH_ALL.
        let mut psbt = unsigned_psbt();
        psbt.inputs[0].partial_sigs.insert(
            PublicKey::from_slice(&[2u8; 33]).unwrap(),
            ecdsa_sig(bitcoin::EcdsaSighashType::None),
        );

        let error = sighash_type_error(psbt);
        assert_eq!(error.declared, None);
        assert!(alloc::format!("{}", error).starts_with("input 0 ECDSA signature for "));
    }

    /// Signs `psbt` with the fixture key (`TEST_XPRIV`).
    fn sign(psbt: Psbt) -> Psbt {
        let secp = Secp256k1::new();
        let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
        let mut signer = Signer::new(psbt).expect("test env, psbt should be well formed");
        let sigs = signer.session(|mut session| {
            let inputs =
                session.assume_checked_inputs().expect("test env, inputs should be well formed");
            session.get_all(&inputs, &xpriv, &secp)
        });
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
        Finalizer::interpreter_check(&finalized, &secp).expect("valid finalized psbt must pass");

        // Tamper with the final script witness so the interpreter rejects the input.
        let witness = finalized.inputs[0].final_script_witness.as_mut().unwrap();
        witness.clear();
        witness.push([1u8; 64]); // garbage "signature"
        witness.push(pk_bytes);

        assert!(
            Finalizer::interpreter_check(&finalized, &secp).is_err(),
            "tampered witness must be rejected"
        );
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
            Some(RequiredHeightLockTime::from_consensus(800_000).unwrap());
        unsigned.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let secp = Secp256k1::verification_only();
        Finalizer::new(sign(unsigned))
            .unwrap()
            .finalize(&secp)
            .expect("finalize must preserve the lock time the signature commits to");
    }

    #[test]
    fn finalize_checks_time_lock_against_transaction_lock_time() {
        let secp = Secp256k1::new();
        let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
        let path = "m/0".into_derivation_path().unwrap();
        let sk = xpriv.derive_priv(&secp, &path).unwrap();
        let pk = PublicKey::new(sk.to_keypair(&secp).public_key());
        let origin = (xpriv.fingerprint(&secp), path);
        let time = absolute::Time::from_consensus(1_700_000_000).unwrap();

        let witness_script = Miniscript::<PublicKey, Segwitv0>::from_str(&format!(
            "and_v(v:pk({pk}),after(1700000000))"
        ))
        .unwrap()
        .encode();
        let mut input_0 = Input::new(&OutPoint::new(Txid::all_zeros(), 0));
        input_0.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        });
        input_0.witness_script = Some(witness_script);
        input_0.bip32_derivations.insert(pk, origin.clone());
        input_0.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let mut input_1 = Input::new(&OutPoint::new(Txid::all_zeros(), 1));
        input_1.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
        });
        input_1.bip32_derivations.insert(pk, origin);
        input_1.min_time = Some(time);
        input_1.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input_0)
            .input(input_1)
            .output(Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
            }))
            .expect("fixture output must be valid")
            .psbt()
            .unwrap();
        assert_eq!(psbt.determine_lock_time().unwrap(), absolute::LockTime::from(time));

        let v_secp = Secp256k1::verification_only();
        Finalizer::new(sign(psbt))
            .unwrap()
            .finalize(&v_secp)
            .expect("the transaction lock time meets input 0's time lock");
    }

    #[test]
    fn finalize_rejects_height_lock_in_time_locked_transaction() {
        let secp = Secp256k1::new();
        let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
        let path = "m/0".into_derivation_path().unwrap();
        let sk = xpriv.derive_priv(&secp, &path).unwrap();
        let pk = PublicKey::new(sk.to_keypair(&secp).public_key());
        let origin = (xpriv.fingerprint(&secp), path);
        let time = absolute::Time::from_consensus(1_700_000_000).unwrap();

        let witness_script = Miniscript::<PublicKey, Segwitv0>::from_str(&format!(
            "and_v(v:pk({pk}),after(800000))"
        ))
        .unwrap()
        .encode();
        let mut input_0 = Input::new(&OutPoint::new(Txid::all_zeros(), 0));
        input_0.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        });
        input_0.witness_script = Some(witness_script);
        input_0.bip32_derivations.insert(pk, origin.clone());
        input_0.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let mut input_1 = Input::new(&OutPoint::new(Txid::all_zeros(), 1));
        input_1.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
        });
        input_1.bip32_derivations.insert(pk, origin);
        input_1.min_time = Some(time);
        input_1.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input_0)
            .input(input_1)
            .output(Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
            }))
            .expect("fixture output must be valid")
            .psbt()
            .unwrap();
        assert_eq!(psbt.determine_lock_time().unwrap(), absolute::LockTime::from(time));

        let v_secp = Secp256k1::verification_only();
        let result = Finalizer::new(sign(psbt)).unwrap().finalize(&v_secp);
        assert!(result.is_err(), "a time-based transaction lock time cannot meet a height lock");
    }

    #[test]
    fn finalize_picks_branch_met_by_transaction_lock_time() {
        let secp = Secp256k1::new();
        let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
        let key = |path: &str| {
            let path = path.into_derivation_path().unwrap();
            let sk = xpriv.derive_priv(&secp, &path).unwrap();
            (PublicKey::new(sk.to_keypair(&secp).public_key()), (xpriv.fingerprint(&secp), path))
        };
        let (pk, origin) = key("m/0");
        let (pk_1, origin_1) = key("m/1");
        let time = absolute::Time::from_consensus(1_700_000_000).unwrap();

        // The height branch has the shorter witness, so a satisfier that wrongly takes it
        // as met prefers it.
        let witness_script = Miniscript::<PublicKey, Segwitv0>::from_str(&format!(
            "or_i(and_v(v:pk({pk}),after(1700000000)),and_v(v:pk({pk_1}),after(800000)))"
        ))
        .unwrap()
        .encode();
        let mut input_0 = Input::new(&OutPoint::new(Txid::all_zeros(), 0));
        input_0.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        });
        input_0.witness_script = Some(witness_script);
        input_0.bip32_derivations.insert(pk, origin.clone());
        input_0.bip32_derivations.insert(pk_1, origin_1);
        input_0.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let mut input_1 = Input::new(&OutPoint::new(Txid::all_zeros(), 1));
        input_1.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
        });
        input_1.bip32_derivations.insert(pk, origin);
        input_1.min_time = Some(time);
        input_1.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input_0)
            .input(input_1)
            .output(Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
            }))
            .expect("fixture output must be valid")
            .psbt()
            .unwrap();
        assert_eq!(psbt.determine_lock_time().unwrap(), absolute::LockTime::from(time));

        let v_secp = Secp256k1::verification_only();
        let finalized = Finalizer::new(sign(psbt))
            .unwrap()
            .finalize(&v_secp)
            .expect("the transaction lock time meets input 0's time branch");
        // The witness is `[sig, selector, script]`; `or_i` takes its first, time, branch on 1.
        let witness = finalized.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(witness.nth(1), Some(&[1u8][..]));
    }

    #[test]
    fn finalize_rejects_time_lock_on_input_with_final_sequence() {
        let secp = Secp256k1::new();
        let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
        let path = "m/0".into_derivation_path().unwrap();
        let sk = xpriv.derive_priv(&secp, &path).unwrap();
        let pk = PublicKey::new(sk.to_keypair(&secp).public_key());
        let origin = (xpriv.fingerprint(&secp), path);
        let time = absolute::Time::from_consensus(1_700_000_000).unwrap();

        let witness_script = Miniscript::<PublicKey, Segwitv0>::from_str(&format!(
            "and_v(v:pk({pk}),after(1700000000))"
        ))
        .unwrap()
        .encode();
        let mut input_0 = Input::new(&OutPoint::new(Txid::all_zeros(), 0));
        input_0.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        });
        input_0.witness_script = Some(witness_script);
        input_0.bip32_derivations.insert(pk, origin.clone());
        // A missing sequence is `Sequence::MAX`, under which CLTV fails.

        let mut input_1 = Input::new(&OutPoint::new(Txid::all_zeros(), 1));
        input_1.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
        });
        input_1.bip32_derivations.insert(pk, origin);
        input_1.min_time = Some(time);
        input_1.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input_0)
            .input(input_1)
            .output(Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
            }))
            .expect("fixture output must be valid")
            .psbt()
            .unwrap();
        assert_eq!(psbt.determine_lock_time().unwrap(), absolute::LockTime::from(time));

        let v_secp = Secp256k1::verification_only();
        let result = Finalizer::new(sign(psbt)).unwrap().finalize(&v_secp);
        assert!(result.is_err(), "CLTV fails on an input whose sequence is final");
    }

    #[test]
    fn finalize_rejects_older_on_input_with_final_sequence() {
        // An omitted sequence is `Sequence::MAX`, under which CSV fails.
        let secp = Secp256k1::new();
        let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
        let path = "m/0".into_derivation_path().unwrap();
        let sk = xpriv.derive_priv(&secp, &path).unwrap();
        let pk = PublicKey::new(sk.to_keypair(&secp).public_key());
        let origin = (xpriv.fingerprint(&secp), path);

        let witness_script =
            Miniscript::<PublicKey, Segwitv0>::from_str(&format!("and_v(v:pk({pk}),older(10))"))
                .unwrap()
                .encode();
        let mut input = Input::new(&OutPoint::new(Txid::all_zeros(), 0));
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        });
        input.witness_script = Some(witness_script);
        input.bip32_derivations.insert(pk, origin);
        // Omitted sequence defaults to Sequence::MAX — CSV is disabled, so older(10) fails.

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input)
            .output(Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
            }))
            .expect("fixture output must be valid")
            .psbt()
            .unwrap();

        let v_secp = Secp256k1::verification_only();
        let result = Finalizer::new(sign(psbt)).unwrap().finalize(&v_secp);
        assert!(result.is_err(), "CSV fails on an input whose sequence is final");
    }

    #[test]
    fn finalize_satisfies_older_with_sufficient_sequence() {
        // A sequence of 10 blocks satisfies `older(10)`.
        let secp = Secp256k1::new();
        let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
        let path = "m/0".into_derivation_path().unwrap();
        let sk = xpriv.derive_priv(&secp, &path).unwrap();
        let pk = PublicKey::new(sk.to_keypair(&secp).public_key());
        let origin = (xpriv.fingerprint(&secp), path);

        let witness_script =
            Miniscript::<PublicKey, Segwitv0>::from_str(&format!("and_v(v:pk({pk}),older(10))"))
                .unwrap()
                .encode();
        let mut input = Input::new(&OutPoint::new(Txid::all_zeros(), 0));
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(123_456),
            script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        });
        input.witness_script = Some(witness_script);
        input.bip32_derivations.insert(pk, origin);
        input.sequence = Some(Sequence::from_consensus(10));

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input)
            .output(Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
            }))
            .expect("fixture output must be valid")
            .psbt()
            .unwrap();

        let v_secp = Secp256k1::verification_only();
        Finalizer::new(sign(psbt))
            .unwrap()
            .finalize(&v_secp)
            .expect("the sequence meets the older(10) relative time lock");
    }
}
