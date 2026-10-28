// SPDX-License-Identifier: CC0-1.0

//! Integration tests for PSBT combining.

#![cfg(feature = "std")]

use bitcoin::hashes::Hash as _;
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::SecretKey;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{
    ecdsa, transaction, Amount, Network, OutPoint, PrivateKey, ScriptBuf, Sequence, TxOut, Txid,
};
use psbt_v2::{CombineError, Count, Global, Input, Output, Psbt, PsbtSighashType};

fn outpoint(label: &[u8]) -> OutPoint { OutPoint { txid: Txid::hash(label), vout: 0 } }

fn dummy_output() -> Output {
    Output::new(TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() })
}

fn keypair(byte: u8) -> bitcoin::PublicKey {
    let key = PrivateKey::new(SecretKey::from_slice(&[byte; 32]).unwrap(), Network::Bitcoin);
    key.public_key(&bitcoin::secp256k1::Secp256k1::new())
}

fn make_sig(byte: u8, sighash_type: EcdsaSighashType) -> ecdsa::Signature {
    ecdsa::Signature {
        signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&[byte; 64]).unwrap(),
        sighash_type,
    }
}

#[test]
fn combine_rejects_previous_txid_mismatch() {
    let psbt_a = Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![Input::new(&outpoint(b"a"))],
        outputs: vec![dummy_output()],
    };
    let psbt_b = Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![Input::new(&outpoint(b"b"))],
        outputs: vec![dummy_output()],
    };

    let err = psbt_a.combine_with(psbt_b).unwrap_err();
    assert!(matches!(err, CombineError::Input(_)), "expected Input error, got {:?}", err);
}

#[test]
fn combine_rejects_amount_mismatch() {
    let op = outpoint(b"in");
    let psbt_a = Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![Input::new(&op)],
        outputs: vec![Output::new(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        })],
    };
    let psbt_b = Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![Input::new(&op)],
        outputs: vec![Output::new(TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: ScriptBuf::new(),
        })],
    };

    let err = psbt_a.combine_with(psbt_b).unwrap_err();
    assert!(matches!(err, CombineError::Output(_)), "expected Output error, got {:?}", err);
}

#[test]
fn combine_rejects_tx_version_mismatch() {
    let op = outpoint(b"in");
    let psbt_a = Psbt {
        global: Global {
            tx_version: transaction::Version::ONE,
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![Input::new(&op)],
        outputs: vec![dummy_output()],
    };
    let psbt_b = Psbt {
        global: Global {
            tx_version: transaction::Version::TWO,
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![Input::new(&op)],
        outputs: vec![dummy_output()],
    };

    let err = psbt_a.combine_with(psbt_b).unwrap_err();
    assert!(matches!(err, CombineError::Global(_)), "expected Global error, got {:?}", err);
}

#[test]
fn combine_first_wins_for_option_fields() {
    let op = outpoint(b"in");
    let mut input_a = Input::new(&op);
    input_a.sequence = Some(Sequence::ZERO);
    let mut input_b = Input::new(&op);
    input_b.sequence = Some(Sequence::MAX);

    let psbt_a = Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input_a],
        outputs: vec![dummy_output()],
    };
    let psbt_b = Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input_b],
        outputs: vec![dummy_output()],
    };

    let combined = psbt_a.combine_with(psbt_b).expect("combine should succeed");
    // First PSBT's value wins when both have the same option set.
    assert_eq!(combined.inputs[0].sequence, Some(Sequence::ZERO));
}

#[test]
fn combine_merges_map_fields() {
    let op = outpoint(b"in");
    let pk1 = keypair(1);
    let pk2 = keypair(2);
    let sig1 = make_sig(1, EcdsaSighashType::All);
    let sig2 = make_sig(2, EcdsaSighashType::All);

    let mut input_a = Input::new(&op);
    input_a.partial_sigs.insert(pk1, sig1);
    let mut input_b = Input::new(&op);
    input_b.partial_sigs.insert(pk2, sig2);

    let psbt_a = Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input_a],
        outputs: vec![dummy_output()],
    };
    let psbt_b = Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input_b],
        outputs: vec![dummy_output()],
    };

    let combined = psbt_a.combine_with(psbt_b).expect("combine should succeed");
    assert_eq!(combined.inputs[0].partial_sigs.len(), 2);
    assert!(combined.inputs[0].partial_sigs.contains_key(&pk1));
    assert!(combined.inputs[0].partial_sigs.contains_key(&pk2));
}

#[test]
fn combine_is_commutative_when_no_fields_overlap() {
    let op = outpoint(b"in");
    let mut input_a = Input::new(&op);
    input_a.sequence = Some(Sequence::ZERO);
    let mut input_b = Input::new(&op);
    input_b.sighash_type = Some(PsbtSighashType::ALL);

    let base = || Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![Input::new(&op)],
        outputs: vec![dummy_output()],
    };
    let psbt_a = Psbt { inputs: vec![input_a], ..base() };
    let psbt_b = Psbt { inputs: vec![input_b], ..base() };

    let ab = psbt_a.clone().combine_with(psbt_b.clone()).expect("A+B should succeed");
    let ba = psbt_b.combine_with(psbt_a).expect("B+A should succeed");

    assert_eq!(ab, ba);
}

#[test]
fn combine_errors_when_lock_time_becomes_undeterminable() {
    let op0 = outpoint(b"input 0");
    let op1 = outpoint(b"input 1");

    // PSBT A: input 0 requires time-based lock, input 1 has no lock time fields.
    let mut input_a0 = Input::new(&op0);
    input_a0.min_time = Some(absolute::Time::from_consensus(1_657_048_459).unwrap());
    let input_a1 = Input::new(&op1);

    let psbt_a = Psbt {
        global: Global {
            input_count: Count::from(2),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input_a0, input_a1],
        outputs: vec![dummy_output()],
    };

    // PSBT B: input 0 has no lock time fields, input 1 requires height-based lock.
    let input_b0 = Input::new(&op0);
    let mut input_b1 = Input::new(&op1);
    input_b1.min_height = Some(absolute::Height::from_consensus(800_000).unwrap());

    let psbt_b = Psbt {
        global: Global {
            input_count: Count::from(2),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input_b0, input_b1],
        outputs: vec![dummy_output()],
    };

    assert!(psbt_a.determine_lock_time().is_ok());
    assert!(psbt_b.determine_lock_time().is_ok());

    let err = psbt_a.combine_with(psbt_b).unwrap_err();
    assert!(matches!(err, CombineError::LockTime(_)), "expected LockTime error, got {:?}", err);
}
