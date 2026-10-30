// SPDX-License-Identifier: CC0-1.0

//! Integration tests for the Updater role.

#![cfg(feature = "std")]

use psbt_v2::bitcoin::absolute::LockTime;
use psbt_v2::bitcoin::bip32::KeySource;
use psbt_v2::bitcoin::secp256k1::Secp256k1;
use psbt_v2::bitcoin::transaction::Version;
use psbt_v2::bitcoin::{
    Amount, Network, OutPoint, PrivateKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
};
use psbt_v2::{Creator, Input, Output, Psbt, PsbtSighashType, RequiredHeightLockTime, Updater};

/// A funded P2WPKH input worth 10,000 sats.
fn funded_input(seed: u8, vout: u32) -> Input {
    let secp = Secp256k1::new();
    let sk = PrivateKey::new(
        psbt_v2::bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap(),
        Network::Bitcoin,
    );
    let pk = sk.public_key(&secp);
    let funding_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
        }],
    };
    let tx_out = funding_tx.output[vout as usize].clone();
    let mut input = Input::new(&OutPoint { txid: funding_tx.compute_txid(), vout });
    input.witness_utxo = Some(tx_out);
    input
}

/// A two-input, one-output PSBT built via the Creator role.
fn two_party_psbt(input_a: Input, input_b: Input) -> Psbt {
    let destination = TxOut { value: Amount::from_sat(15_000), script_pubkey: ScriptBuf::new() };
    Creator::new()
        .constructor_modifiable()
        .input(input_a)
        .input(input_b)
        .output(Output::new(destination))
        .expect("output must be valid")
        .psbt()
        .expect("lock time must be determinable")
}

/// A basic round-trip: enter the Updater role, mutate inputs, extract the Psbt.
#[test]
fn update_then_extract_psbt() {
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let mut updater = Updater::new(psbt).unwrap();
    updater.update(|view| {
        view.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
        view.inputs[0].sighash_type = Some(PsbtSighashType::ALL);
    });
    let psbt = updater.psbt().unwrap();

    assert_eq!(psbt.inputs[0].sequence, Some(Sequence::ENABLE_LOCKTIME_NO_RBF));
    assert_eq!(psbt.inputs[0].sighash_type, Some(PsbtSighashType::ALL));
    // The second input was not touched.
    assert_eq!(psbt.inputs[1].sequence, None);
}

/// Multiple `update()` calls accumulate mutations across calls.
#[test]
fn multiple_updates_accumulate() {
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let mut updater = Updater::new(psbt).unwrap();
    updater.update(|view| {
        view.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
    });
    updater.update(|view| {
        view.inputs[0].sighash_type = Some(PsbtSighashType::ALL);
        view.inputs[1].sequence = Some(Sequence::ENABLE_RBF_NO_LOCKTIME);
    });
    let psbt = updater.psbt().unwrap();

    assert_eq!(psbt.inputs[0].sequence, Some(Sequence::ENABLE_LOCKTIME_NO_RBF));
    assert_eq!(psbt.inputs[0].sighash_type, Some(PsbtSighashType::ALL));
    assert_eq!(psbt.inputs[1].sequence, Some(Sequence::ENABLE_RBF_NO_LOCKTIME));
}

/// Within a single `update()` closure, the caller can read from one input and write data to another.
#[test]
fn cross_map_read_and_write() {
    let secp = Secp256k1::new();
    let sk = PrivateKey::new(
        psbt_v2::bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        Network::Bitcoin,
    );
    let pk = sk.public_key(&secp);

    let mut input_a = funded_input(1, 0);
    input_a.bip32_derivations.insert(pk, KeySource::default());

    let psbt = two_party_psbt(input_a, funded_input(2, 0));

    let mut updater = Updater::new(psbt).unwrap();
    updater.update(|view| {
        // Read a derivation from input 0, apply the same derivation to input 1.
        let derivations: Vec<_> =
            view.inputs[0].bip32_derivations.iter().map(|(k, v)| (*k, v.clone())).collect();
        for (key, source) in derivations {
            view.inputs[1].bip32_derivations.insert(key, source);
        }
    });
    let psbt = updater.psbt().unwrap();

    assert_eq!(psbt.inputs[1].bip32_derivations.len(), 1);
}

/// `Updater::new` validates that lock time is determinable on entry.
#[test]
fn new_rejects_indeterminate_lock_time() {
    use psbt_v2::bitcoin::absolute;

    let mut psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));
    // Input 0 requires time-based lock time (min_time only).
    psbt.inputs[0].min_time = Some(absolute::Time::from_consensus(500_000_000).unwrap());
    psbt.inputs[0].min_height = None;
    // Input 1 requires height-based lock time (min_height only).
    psbt.inputs[1].min_height = Some(RequiredHeightLockTime::from_consensus(800_000).unwrap());
    psbt.inputs[1].min_time = None;

    let result = Updater::new(psbt);
    assert!(result.is_err());
}

/// `Updater::psbt` re-validates the lock time on exit, a mutation that
/// introduces a conflicting lock-time requirement is caught.
#[test]
fn psbt_rejects_lock_time_made_indeterminate_by_mutation() {
    use psbt_v2::bitcoin::absolute;

    let mut psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));
    // Initially both inputs require height-based lock time (determinable).
    psbt.inputs[0].min_height = Some(RequiredHeightLockTime::from_consensus(800_000).unwrap());
    psbt.inputs[0].min_time = None;
    psbt.inputs[1].min_height = Some(RequiredHeightLockTime::from_consensus(800_000).unwrap());
    psbt.inputs[1].min_time = None;

    let mut updater = Updater::new(psbt).unwrap();

    // Mutate input 1 to require a time-based lock time instead, now we have
    // one input requiring time and another requiring height.
    updater.update(|view| {
        view.inputs[1].min_time = Some(absolute::Time::from_consensus(500_000_000).unwrap());
        view.inputs[1].min_height = None;
    });

    let result = updater.psbt();
    assert!(result.is_err());
}
