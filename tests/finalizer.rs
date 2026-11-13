// SPDX-License-Identifier: CC0-1.0

//! Integration tests for the BIP-370 Finalizer role: assembling final script sigs and witnesses
//! from signed inputs, across the taproot key-spend and script-spend paths.

#![cfg(all(feature = "std", feature = "miniscript"))]

use std::collections::BTreeMap;

use psbt_v2::bitcoin::absolute::LockTime;
use psbt_v2::bitcoin::bip32::KeySource;
use psbt_v2::bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
use psbt_v2::bitcoin::script::Builder;
use psbt_v2::bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use psbt_v2::bitcoin::taproot::{LeafVersion, TaprootBuilder};
use psbt_v2::bitcoin::transaction::Version;
use psbt_v2::bitcoin::{
    Amount, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Transaction, TxIn, TxOut,
};
use psbt_v2::{
    sign_all, Creator, FinalizableInput, FinalizeError, Finalizer, Input, Output, Psbt, Signer,
};

/// Deterministic per-user key material: the key map handed to a signing session together with
/// the user's public key.
fn user(seed: u8) -> (BTreeMap<PublicKey, PrivateKey>, PublicKey) {
    let secp = Secp256k1::new();
    let secret_key = PrivateKey::new(SecretKey::from_slice(&[seed; 32]).unwrap(), Network::Bitcoin);
    let public_key = secret_key.public_key(&secp);
    (BTreeMap::from([(public_key, secret_key)]), public_key)
}

/// Builds the deterministic funding transaction paying `tx_out` at `vout`
fn funding_tx(vout: usize, tx_out: TxOut) -> Transaction {
    let mut output = vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new() }; vout];
    output.push(tx_out);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output,
    }
}

/// A witness-only P2TR key-path input worth 1,000 sats whose internal key is `public_key`'s,
/// recorded in `tap_key_origins`.
fn tr_input(public_key: PublicKey) -> Input {
    let secp = Secp256k1::verification_only();
    let xonly = public_key.inner.x_only_public_key().0;
    let tx_out = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2tr(&secp, xonly, None),
    };
    let funding_tx = funding_tx(0, tx_out.clone());
    let mut input = Input::new(&OutPoint { txid: funding_tx.compute_txid(), vout: 0 });
    input.witness_utxo = Some(tx_out);
    input.tap_internal_key = Some(xonly);
    input.tap_key_origins.insert(xonly, (vec![], KeySource::default()));
    input
}

/// A funded P2WPKH input worth 1,000 sats whose key is recorded in `bip32_derivations`.
fn wpkh_input(public_key: PublicKey, vout: usize) -> Input {
    let tx_out = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().unwrap()),
    };
    let funding_tx = funding_tx(vout, tx_out.clone());
    let mut input = Input::new(&OutPoint { txid: funding_tx.compute_txid(), vout: vout as u32 });
    input.witness_utxo = Some(tx_out);
    input.non_witness_utxo = Some(funding_tx);
    input.bip32_derivations.insert(public_key, KeySource::default());
    input
}

/// Assembles `inputs` into a one-output PSBT via the Creator role
fn unsigned_psbt(inputs: Vec<Input>) -> Psbt {
    let mut constructor = Creator::new().constructor_modifiable();
    for input in inputs {
        constructor = constructor.input(input).expect("lock time must be determinable");
    }
    constructor
        .output(Output::new(TxOut {
            value: Amount::from_sat(900),
            script_pubkey: ScriptBuf::new(),
        }))
        .expect("test fixture output is valid")
        .psbt()
}

// A signed taproot key-path input finalizes to a single-element witness: just the key-spend
// signature.
#[test]
fn finalize_taproot_key_spend() {
    let secp = Secp256k1::new();
    let (keys, public_key) = user(1);

    let psbt = unsigned_psbt(vec![tr_input(public_key)]);
    let mut signer = Signer::new(psbt.try_resolve().unwrap());
    let sigs = signer.session(sign_all(&keys, &secp)).unwrap();
    let psbt = signer.apply(sigs).unwrap().psbt();
    assert!(psbt.inputs[0].tap_key_sig.is_some());

    let finalized = Finalizer::new(psbt.try_resolve().unwrap()).unwrap().finalize(&secp).unwrap();
    assert_eq!(finalized.inputs[0].final_script_witness.as_ref().unwrap().len(), 1);
}

// Two users sign a single taproot script-path input (a 2-of-2 tapscript multisig leaf): the
// fully-signed input finalizes through the taproot script spend.
#[test]
fn finalize_taproot_script_path() {
    let secp = Secp256k1::new();
    let (a_keys, a_public_key) = user(1);
    let (b_keys, b_public_key) = user(2);
    let a_xonly = a_public_key.inner.x_only_public_key().0;
    let b_xonly = b_public_key.inner.x_only_public_key().0;

    let leaf_script = Builder::new()
        .push_x_only_key(&a_xonly)
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&b_xonly)
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUAL)
        .into_script();
    // The internal key is held by nobody: only script-path signatures are possible.
    let internal_key = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf_script.clone())
        .unwrap()
        .finalize(&secp, internal_key)
        .unwrap();
    let tx_out = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
    };
    let funding_tx = funding_tx(0, tx_out.clone());
    let mut input = Input::new(&OutPoint { txid: funding_tx.compute_txid(), vout: 0 });
    input.witness_utxo = Some(tx_out);
    input.non_witness_utxo = Some(funding_tx);
    input.tap_internal_key = Some(internal_key);
    input.tap_merkle_root = spend_info.merkle_root();
    let leaf_hash = leaf_script.tapscript_leaf_hash();
    input.tap_key_origins.insert(a_xonly, (vec![leaf_hash], KeySource::default()));
    input.tap_key_origins.insert(b_xonly, (vec![leaf_hash], KeySource::default()));
    let control_block = spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .expect("leaf was added to the tree");
    input.tap_scripts.insert(control_block, (leaf_script, LeafVersion::TapScript));

    let psbt = unsigned_psbt(vec![input]);

    // User A signs, then user B signs the same leaf on top of it.
    let mut signer = Signer::new(psbt.try_resolve().unwrap());
    let sigs = signer.session(sign_all(&a_keys, &secp)).unwrap();
    let mut signer = signer.apply(sigs).unwrap();
    let sigs = signer.session(sign_all(&b_keys, &secp)).unwrap();
    let psbt = signer.apply(sigs).unwrap().psbt();
    assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 2);

    // The fully-signed script-path input finalizes through the taproot script spend.
    let finalized =
        Finalizer::new(psbt.clone().try_resolve().unwrap()).unwrap().finalize(&secp).unwrap();
    // Witness: [sig_a, sig_b, leaf_script, control_block].
    assert_eq!(finalized.inputs[0].final_script_witness.as_ref().unwrap().len(), 4);

    // The malleable single-input path finalizes the same script spend.
    let finalizer = Finalizer::new(psbt.try_resolve().unwrap()).unwrap();
    let input = finalizer.finalizable_input(0).unwrap().malleable(true).finalize().unwrap();
    assert_eq!(input.final_script_witness.as_ref().unwrap().len(), 4);
}

#[test]
fn finalize_inputs_does_not_validate_all_inputs() {
    let secp = Secp256k1::new();
    let (a_keys, a_public_key) = user(1);

    let psbt = unsigned_psbt(vec![tr_input(a_public_key), wpkh_input(a_public_key, 1)]);
    let mut signer = Signer::new(psbt.try_resolve().unwrap());
    let sigs = signer.session(sign_all(&a_keys, &secp)).unwrap();
    let psbt = signer.apply(sigs).unwrap().psbt();

    let finalizer = Finalizer::new(psbt.try_resolve().unwrap()).unwrap();
    let finalized = finalizer.finalize_inputs(vec![finalizer.finalizable_input(0).unwrap()]);

    // Selecting only input 0 leaves input 1 unfinalized: the interpreter check fails.
    assert!(finalized.is_ok());

    assert!(finalized.as_ref().unwrap()[0].final_script_witness.is_some());
    assert!(finalized.unwrap()[1].final_script_witness.is_none());
}

// A downstream crate must be able to name `FinalizableInput` in its own signatures.
fn finalize_handle(handle: FinalizableInput<'_>) -> Result<Input, FinalizeError> {
    handle.finalize()
}

#[test]
fn finalizable_input_is_exported() {
    let secp = Secp256k1::new();
    let (keys, public_key) = user(1);

    let psbt = unsigned_psbt(vec![tr_input(public_key)]);
    let mut signer = Signer::new(psbt.try_resolve().unwrap());
    let sigs = signer.session(sign_all(&keys, &secp)).unwrap();
    let psbt = signer.apply(sigs).unwrap().psbt();

    let finalizer = Finalizer::new(psbt.try_resolve().unwrap()).unwrap();
    let input = finalize_handle(finalizer.finalizable_input(0).unwrap()).unwrap();
    assert!(input.final_script_witness.is_some());
}

// An already-finalized input has no signing material left, so the strict constructor rejects it
// instead of handing out a handle that can only fail to re-satisfy.
#[test]
fn finalizable_input_rejects_finalized_input() {
    let secp = Secp256k1::new();
    let (keys, public_key) = user(1);

    let psbt = unsigned_psbt(vec![tr_input(public_key)]);
    let mut signer = Signer::new(psbt.try_resolve().unwrap());
    let sigs = signer.session(sign_all(&keys, &secp)).unwrap();
    let psbt = signer.apply(sigs).unwrap().psbt();
    let psbt = Finalizer::new(psbt.try_resolve().unwrap()).unwrap().finalize(&secp).unwrap().psbt();

    let finalizer = Finalizer::new(psbt.try_resolve().unwrap()).unwrap();
    match finalizer.finalizable_input(0) {
        Err(FinalizeError::AlreadyFinalized { input_index }) => assert_eq!(input_index, 0),
        other => panic!("expected AlreadyFinalized, got {:?}", other),
    }
}
