// SPDX-License-Identifier: CC0-1.0

//! Integration tests for the BIP-370 Signer role: user signing workflows across the strict and
//! caller-attested APIs, and an allocation-growth guard for taproot input-set validation.

#![cfg(feature = "std")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;

use psbt_v2::bitcoin::absolute::LockTime;
use psbt_v2::bitcoin::bip32::KeySource;
use psbt_v2::bitcoin::hashes::Hash;
use psbt_v2::bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
use psbt_v2::bitcoin::script::Builder;
use psbt_v2::bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use psbt_v2::bitcoin::sighash::{EcdsaSighashType, TapSighashType};
use psbt_v2::bitcoin::taproot::TaprootBuilder;
use psbt_v2::bitcoin::transaction::Version;
use psbt_v2::bitcoin::{
    ecdsa, Amount, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Transaction, TxIn, TxOut,
    Txid,
};
use psbt_v2::{
    sign_all, sign_all_unchecked, sign_input, sign_input_unchecked, Count, Creator,
    FundingUtxoError, Global, Input, Output, OutputType, Psbt, PsbtSighashType, SignError, Signer,
};

thread_local! {
    // Cumulative requested bytes for only the thread running the operation.
    static ALLOCATED: Cell<Option<usize>> = const { Cell::new(None) };
}

struct CountingAllocator;

fn count(bytes: usize) {
    let _ = ALLOCATED.try_with(|counter| {
        if let Some(total) = counter.get() {
            counter.set(Some(total.saturating_add(bytes)));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count(size);
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn strict_validation_allocations(input_count: u32) -> usize {
    let script = ScriptBuf::new_p2tr(
        &Secp256k1::verification_only(),
        XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        None,
    );
    let inputs = (0..input_count)
        .map(|index| {
            let mut input =
                Input::new(&OutPoint { txid: Txid::from_byte_array([3u8; 32]), vout: index });
            input.witness_utxo =
                Some(TxOut { value: Amount::from_sat(1_000), script_pubkey: script.clone() });
            input
        })
        .collect();
    let psbt = Psbt {
        global: Global {
            input_count: Count::from(input_count as usize),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs,
        outputs: vec![Output::new(TxOut { value: Amount::from_sat(500), script_pubkey: script })],
    };

    // The request has matching counts and ordinary serialized input maps.
    // Exclude fixture construction and decoding from the allocation measurement.
    let mut signer = Signer::new(psbt).unwrap();
    ALLOCATED.with(|counter| counter.set(Some(0)));
    let (len, allocated) = signer.session(|session| {
        let checked = session.signable_inputs();
        std::hint::black_box(&checked);
        let allocated = ALLOCATED.with(|counter| counter.replace(None).unwrap());
        (checked.map(|inputs| inputs.len()), allocated)
    });
    assert_eq!(len.unwrap(), input_count as usize);
    allocated
}

#[test]
fn strict_taproot_validation_has_linear_allocation_growth() {
    let small = strict_validation_allocations(128);
    let large = strict_validation_allocations(512);
    assert!(small > 0);

    // Four times as many fixed-size input maps get an eight-fold allowance.
    // Retaining a complete cloned prevout vector in every signable input would
    // grow allocation approximately sixteen-fold instead.
    assert!(
        large <= small * 8,
        "quadratic prevout allocation: 128 inputs = {small} bytes; 512 inputs = {large} bytes",
    );
}

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

/// How completely the funding UTXO data is recorded on an input.
#[derive(Clone, Copy)]
enum Funding {
    /// Both UTXO forms: strictly verifiable.
    Full,
    /// Witness UTXO only: unverifiable without the caller's attestation.
    WitnessOnly,
}

/// A funded P2WPKH input worth 1,000 sats whose key is recorded in `bip32_derivations`.
fn wpkh_input(public_key: PublicKey, vout: usize, funding: Funding) -> Input {
    let tx_out = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().unwrap()),
    };
    let funding_tx = funding_tx(vout, tx_out.clone());
    let mut input = Input::new(&OutPoint { txid: funding_tx.compute_txid(), vout: vout as u32 });
    input.witness_utxo = Some(tx_out);
    if matches!(funding, Funding::Full) {
        input.non_witness_utxo = Some(funding_tx);
    }
    input.bip32_derivations.insert(public_key, KeySource::default());
    input
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

/// Assembles `inputs` into a one-output PSBT via the Creator role
fn unsigned_psbt(inputs: Vec<Input>) -> Psbt {
    let mut constructor = Creator::new().constructor_modifiable();
    for input in inputs {
        constructor = constructor.input(input);
    }
    constructor
        .output(Output::new(TxOut {
            value: Amount::from_sat(900),
            script_pubkey: ScriptBuf::new(),
        }))
        .expect("test fixture output is valid")
        .psbt()
        .expect("test fixture lock time is determinable")
}

// A user wants to sign a single input for which he holds only the witness UTXO. He has attested the
// UTXO offline, so he uses the assume API.
#[test]
fn assume_signs_witness_only_input() {
    let secp = Secp256k1::new();
    let (keys, public_key) = user(1);

    let psbt = unsigned_psbt(vec![wpkh_input(public_key, 0, Funding::WitnessOnly)]);
    let mut signer = Signer::new(psbt).unwrap();

    // Strictly, a witness-only non-P2TR input cannot be verified.
    assert_eq!(
        signer.session(sign_input(0, &keys, &secp)),
        Err(SignError::FundingUtxo(FundingUtxoError::UnverifiableUtxo))
    );

    // The user attests the funding data out-of-band and signs anyway.
    let sigs = signer.session(sign_input_unchecked(0, &keys, &secp)).unwrap();
    assert_eq!(sigs.len(), 1);
    let psbt = signer.apply([sigs]).unwrap();
    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
}

// Two users create a PSBT:
//
// - input A is witness-only.
// - input B is fully funded.
//
// User B tries to apply strict signing to every input: it fails on A's input.
#[test]
fn strict_sign_all_blocked_by_other_users_input() {
    let secp = Secp256k1::new();
    let (_, a_public_key) = user(1);
    let (b_keys, b_public_key) = user(2);

    let psbt = unsigned_psbt(vec![
        wpkh_input(a_public_key, 0, Funding::WitnessOnly),
        wpkh_input(b_public_key, 1, Funding::Full),
    ]);
    let mut signer = Signer::new(psbt).unwrap();

    // Strict full signing is all-or-nothing: A's unverifiable input blocks everything.
    let errors = signer.session(sign_all(&b_keys, &secp)).unwrap_err();
    assert_eq!(
        errors,
        BTreeMap::from([(0, SignError::FundingUtxo(FundingUtxoError::UnverifiableUtxo))])
    );

    // User B can still strictly sign his own input alone.
    let sigs = signer.session(sign_input(1, &b_keys, &secp)).unwrap();
    let psbt = signer.apply([sigs]).unwrap();
    assert!(psbt.inputs[0].partial_sigs.is_empty());
    assert_eq!(psbt.inputs[1].partial_sigs.len(), 1);
}

// Two users create a PSBT with both inputs fully funded:
//
// - user A signs with the assume API
// - user B signs with strict signing
#[test]
fn mixed_assume_and_strict_signers() {
    let secp = Secp256k1::new();
    let (a_keys, a_public_key) = user(1);
    let (b_keys, b_public_key) = user(2);

    let psbt = unsigned_psbt(vec![
        wpkh_input(a_public_key, 0, Funding::Full),
        wpkh_input(b_public_key, 1, Funding::Full),
    ]);

    // User A trusts his own input and signs with the assume API.
    let psbt = {
        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(|mut session| {
            let input = session.assume_checked_input(0).unwrap();
            session.get_input_sigs(&input, &a_keys, &secp)
        });
        signer.apply([sigs]).unwrap()
    };

    // User B receives the PSBT and strictly signs his own input.
    let mut signer = Signer::new(psbt).unwrap();
    let sigs = signer.session(sign_input(1, &b_keys, &secp)).unwrap();
    let psbt = signer.apply([sigs]).unwrap();

    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    assert_eq!(psbt.inputs[1].partial_sigs.len(), 1);
}

// Two users create a PSBT:
//
// - input A is witness-only
// - input B is fully funded
//
// 1. User B tries to strict sign, fails
// 2. User A updates input A with its full funding transaction
// 3. User B strict signs again.
#[test]
fn strict_sign_succeeds_after_utxo_upgrade() {
    let secp = Secp256k1::new();
    let (_, a_public_key) = user(1);
    let (b_keys, b_public_key) = user(2);

    let psbt = unsigned_psbt(vec![
        wpkh_input(a_public_key, 0, Funding::WitnessOnly),
        wpkh_input(b_public_key, 1, Funding::Full),
    ]);
    let mut signer = Signer::new(psbt).unwrap();

    // Strict signing fails on user A's witness-only input.
    let errors = signer.session(sign_all(&b_keys, &secp)).unwrap_err();
    assert_eq!(
        errors,
        BTreeMap::from([(0, SignError::FundingUtxo(FundingUtxoError::UnverifiableUtxo))])
    );

    // User A updates input 0 with its full funding transaction.
    let mut psbt = signer.psbt();
    psbt.inputs[0].non_witness_utxo = Some(funding_tx(
        0,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&a_public_key.wpubkey_hash().unwrap()),
        },
    ));

    // User B's strict signing now succeeds.
    let mut signer = Signer::new(psbt).unwrap();
    let sigs = signer.session(sign_all(&b_keys, &secp)).unwrap();
    let psbt = signer.apply(sigs).unwrap();
    assert!(psbt.inputs[0].partial_sigs.is_empty());
    assert_eq!(psbt.inputs[1].partial_sigs.len(), 1);
}

// Context: PSBT with a taproot and a P2WPKH input
//
// 1. Try to sign both through the singular API: only signs P2WPKH input, (taproot input needs sign_all)
// 2. Re-signing with sign_all doesn't change P2WPKH input signature. Taproot signature gets added.
#[test]
fn taproot_input_requires_all_signable_inputs() {
    let secp = Secp256k1::new();
    let (a_keys, a_public_key) = user(1);

    let psbt =
        unsigned_psbt(vec![tr_input(a_public_key), wpkh_input(a_public_key, 1, Funding::Full)]);
    let mut signer = Signer::new(psbt).unwrap();

    // Singular: the P2WPKH input signs, but the non-ANYONECANPAY taproot input is rejected: its
    // sighash commits to every input's prevout, which only the complete set carries.
    let singular = signer.session(|mut session| {
        assert_eq!(session.signable_input(0), Err(SignError::AllPrevoutsRequired));
        let wpkh = session.signable_input(1).unwrap();
        session.get_input_sigs(&wpkh, &a_keys, &secp)
    });
    assert_eq!(singular.len(), 1);

    // The complete set makes the whole PSBT signable.
    let all_signatures = signer.session(sign_all(&a_keys, &secp)).unwrap();
    assert_eq!(all_signatures.len(), 2);
    assert_eq!(all_signatures[0].index, 0);
    assert_eq!(all_signatures[0].len(), 1); // P2TR gets signed
    assert_eq!(all_signatures[1], singular); // P2WPKH does not change

    let psbt = signer.apply(all_signatures).unwrap();
    assert!(psbt.inputs[0].tap_key_sig.is_some()); // P2TR gets signed
    assert_eq!(psbt.inputs[1].partial_sigs.len(), 1); // P2WPKH gets signed
}

// Two users sign a single 2-of-2 multisig P2WSH input, each holding only his own key: the other
// key is silently skipped, and user B receives user A's signature and signs on top of it.
#[test]
fn two_users_sign_2_of_2_wsh() {
    let secp = Secp256k1::new();
    let (a_keys, a_public_key) = user(1);
    let (b_keys, b_public_key) = user(2);

    let witness_script = Builder::new()
        .push_int(2)
        .push_key(&a_public_key)
        .push_key(&b_public_key)
        .push_int(2)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    let tx_out = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
    };
    let funding_tx = funding_tx(0, tx_out.clone());
    let mut input = Input::new(&OutPoint { txid: funding_tx.compute_txid(), vout: 0 });
    input.witness_utxo = Some(tx_out);
    input.non_witness_utxo = Some(funding_tx);
    input.witness_script = Some(witness_script);
    input.bip32_derivations.insert(a_public_key, KeySource::default());
    input.bip32_derivations.insert(b_public_key, KeySource::default());

    let psbt = unsigned_psbt(vec![input]);

    // User A signs: only his key is in his key map, B's key is silently skipped.
    let psbt = {
        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(sign_input(0, &a_keys, &secp)).unwrap();
        assert_eq!(sigs.len(), 1);
        signer.apply([sigs]).unwrap()
    };

    // User B receives the PSBT and strictly signs: the existing matching
    // signature does not trip the strict checks.
    let mut signer = Signer::new(psbt).unwrap();
    let sigs = signer.session(sign_input(0, &b_keys, &secp)).unwrap();
    assert_eq!(sigs.len(), 1);
    let psbt = signer.apply([sigs]).unwrap();

    assert_eq!(psbt.inputs[0].partial_sigs.len(), 2);
    assert!(psbt.inputs[0].partial_sigs.contains_key(&a_public_key));
    assert!(psbt.inputs[0].partial_sigs.contains_key(&b_public_key));
}

// Two users sign a single taproot script-path input (a 2-of-2 tapscript multisig leaf), each
// holding only his own key: the other key is silently skipped, and user B receives user A's
// signature and signs the same leaf on top of it.
#[test]
fn two_users_sign_taproot_script_path() {
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

    let psbt = unsigned_psbt(vec![input]);

    // User A signs: only his key is in his key map, B's key is silently skipped.
    let psbt = {
        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(sign_all(&a_keys, &secp)).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].len(), 1);
        signer.apply(sigs).unwrap()
    };
    assert!(psbt.inputs[0].tap_script_sigs.contains_key(&(a_xonly, leaf_hash)));

    // User B receives the PSBT and signs the same leaf: A's existing signature is filtered out
    // instead of duplicated.
    let mut signer = Signer::new(psbt).unwrap();
    let sigs = signer.session(sign_all(&b_keys, &secp)).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].len(), 1);
    let psbt = signer.apply(sigs).unwrap();

    assert_eq!(psbt.inputs[0].tap_script_sigs.len(), 2);
    assert!(psbt.inputs[0].tap_script_sigs.contains_key(&(a_xonly, leaf_hash)));
    assert!(psbt.inputs[0].tap_script_sigs.contains_key(&(b_xonly, leaf_hash)));
}

// A misbehaving earlier signer leaves a signature whose sighash type disagrees with the input's
// declared one: strict signing rejects the input, the assume path still signs.
#[test]
fn sighash_mismatch_strict_rejects_assume_signs() {
    let secp = Secp256k1::new();
    let (keys, public_key) = user(1);

    let mut psbt = unsigned_psbt(vec![wpkh_input(public_key, 0, Funding::Full)]);
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::ALL);
    psbt.inputs[0].partial_sigs.insert(
        public_key,
        ecdsa::Signature {
            signature: psbt_v2::bitcoin::secp256k1::ecdsa::Signature::from_compact(&[1u8; 64])
                .unwrap(),
            sighash_type: EcdsaSighashType::None,
        },
    );

    let mut signer = Signer::new(psbt).unwrap();
    assert_eq!(signer.session(sign_input(0, &keys, &secp)), Err(SignError::SighashMismatch));

    // The assume path only trusts the caller's funding-data attestation and signs: the fresh
    // SIGHASH_ALL signature replaces the mismatching one.
    let sigs = signer.session(sign_input_unchecked(0, &keys, &secp)).unwrap();
    let psbt = signer.apply([sigs]).unwrap();
    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    assert_eq!(psbt.inputs[0].partial_sigs[&public_key].sighash_type, EcdsaSighashType::All);
}

// The witness UTXO and the full funding transaction disagree: both the strict and the assume path
// reject.
#[test]
fn assume_still_rejects_inconsistent_utxos() {
    let secp = Secp256k1::new();
    let (keys, public_key) = user(1);

    let mut psbt = unsigned_psbt(vec![wpkh_input(public_key, 0, Funding::Full)]);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(2_000),
        script_pubkey: ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().unwrap()),
    });

    let mut signer = Signer::new(psbt).unwrap();
    assert_eq!(
        signer.session(sign_input(0, &keys, &secp)),
        Err(SignError::FundingUtxo(FundingUtxoError::MismatchingUtxos))
    );
    assert_eq!(
        signer.session(sign_input_unchecked(0, &keys, &secp)),
        Err(SignError::FundingUtxo(FundingUtxoError::MismatchingUtxos))
    );
}

// An ANYONECANPAY taproot sighash commits to only this input's prevout, so the input may be created
// standalone; the non-ANYONECANPAY default needs the complete input set.
#[test]
fn anyonecanpay_taproot_allowed_standalone() {
    let secp = Secp256k1::new();
    let (keys, public_key) = user(1);

    let mut input = tr_input(public_key);
    input.sighash_type = Some(PsbtSighashType::from(TapSighashType::SinglePlusAnyoneCanPay));
    let psbt = unsigned_psbt(vec![input]); // one output satisfies the SINGLE bound

    let mut signer = Signer::new(psbt).unwrap();
    let sigs = signer.session(|mut session| {
        let signable = session.signable_input(0).unwrap();
        assert_eq!(signable.index(), 0);
        assert_eq!(signable.output_type(), OutputType::Tr);
        session.get_input_sigs(&signable, &keys, &secp)
    });

    assert_eq!(sigs.len(), 1); // P2TR gets signed
    let psbt = signer.apply([sigs]).unwrap();
    assert!(psbt.inputs[0].tap_key_sig.is_some()); // P2TR gets signed
}

// Signing an input for real clears PSBT_GLOBAL_TX_MODIFIABLE (BIP-370).
#[test]
fn apply_clears_tx_modifiable_flags() {
    let secp = Secp256k1::new();
    let (keys, public_key) = user(1);

    let unsigned = unsigned_psbt(vec![wpkh_input(public_key, 0, Funding::Full)]);
    assert!(unsigned.global.tx_modifiable_flags.is_inputs_modifiable());
    assert!(unsigned.global.tx_modifiable_flags.is_outputs_modifiable());
    let mut signer = Signer::new(unsigned).unwrap();
    let sigs = signer.session(sign_input(0, &keys, &secp)).unwrap();
    let signed = signer.apply([sigs]).unwrap();
    assert!(!signed.global.tx_modifiable_flags.is_inputs_modifiable());
    assert!(!signed.global.tx_modifiable_flags.is_outputs_modifiable());

    let unsigned = unsigned_psbt(vec![tr_input(public_key)]);
    assert!(unsigned.global.tx_modifiable_flags.is_inputs_modifiable());
    assert!(unsigned.global.tx_modifiable_flags.is_outputs_modifiable());
    let mut signer = Signer::new(unsigned).unwrap();
    let sigs = signer.session(sign_all(&keys, &secp)).unwrap();
    let signed = signer.apply(sigs).unwrap();
    assert!(signed.inputs[0].tap_key_sig.is_some()); // P2TR gets signed
    assert!(!signed.global.tx_modifiable_flags.is_inputs_modifiable());
    assert!(!signed.global.tx_modifiable_flags.is_outputs_modifiable());
}

// Full strict signing of a PSBT whose inputs are all witness-only fails for every input: the error
// map reports each unverifiable funding UTXO and nothing is signed.
#[test]
fn sign_all_fails_to_sign_all_witness_only() {
    let secp = Secp256k1::new();
    let (a_keys, a_public_key) = user(1);
    let (b_keys, b_public_key) = user(2);
    let mut keys = a_keys;
    keys.extend(b_keys);

    let psbt = unsigned_psbt(vec![
        wpkh_input(a_public_key, 0, Funding::WitnessOnly),
        wpkh_input(b_public_key, 1, Funding::WitnessOnly),
    ]);
    let mut signer = Signer::new(psbt).unwrap();

    let errors = signer.session(sign_all(&keys, &secp)).unwrap_err();
    assert_eq!(
        errors,
        BTreeMap::from([
            (0, SignError::FundingUtxo(FundingUtxoError::UnverifiableUtxo)),
            (1, SignError::FundingUtxo(FundingUtxoError::UnverifiableUtxo)),
        ])
    );
}

// Both inputs arrive witness-only and a single coordinator attested both UTXOs out-of-band: the
// sign_all_unchecked signs every input in one shot.
#[test]
fn sign_all_unchecked_signs_all_witness_only() {
    let secp = Secp256k1::new();
    let (a_keys, a_public_key) = user(1);
    let (b_keys, b_public_key) = user(2);
    let mut keys = a_keys;
    keys.extend(b_keys);

    let psbt = unsigned_psbt(vec![
        wpkh_input(a_public_key, 0, Funding::WitnessOnly),
        wpkh_input(b_public_key, 1, Funding::WitnessOnly),
    ]);
    let mut signer = Signer::new(psbt).unwrap();

    let sigs = signer.session(sign_all_unchecked(&keys, &secp)).unwrap();
    assert_eq!(sigs.len(), 2);
    let psbt = signer.apply(sigs).unwrap();
    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    assert_eq!(psbt.inputs[1].partial_sigs.len(), 1);
}

// 1. User A funds inputs 0 and 2 of a three-input PSBT
// 2. User B funds input 1.
// 3. User A creates standalone signable inputs for exactly his own inputs and signs them in one
//    `get_some` call.
#[test]
fn get_some_signs_user_selected_inputs() {
    let secp = Secp256k1::new();
    let (a_keys, a_public_key) = user(1);
    let (_, b_public_key) = user(2);

    let psbt = unsigned_psbt(vec![
        wpkh_input(a_public_key, 0, Funding::Full),
        wpkh_input(b_public_key, 1, Funding::Full),
        wpkh_input(a_public_key, 2, Funding::Full),
    ]);
    let mut signer = Signer::new(psbt).unwrap();

    let sigs = signer.session(|mut session| {
        let first = session.signable_input(0).unwrap();
        let last = session.signable_input(2).unwrap();
        session.get_some(&[first, last], &a_keys, &secp)
    });
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[0].index, 0);
    assert_eq!(sigs[1].index, 2);
    assert!(sigs.iter().all(|input_sigs| input_sigs.len() == 1));

    let psbt = signer.apply(sigs).unwrap();
    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    assert!(psbt.inputs[1].partial_sigs.is_empty());
    assert_eq!(psbt.inputs[2].partial_sigs.len(), 1);
}
