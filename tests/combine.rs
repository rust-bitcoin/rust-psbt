// SPDX-License-Identifier: CC0-1.0

//! Integration tests for PSBT combining.

#![cfg(feature = "std")]

use bitcoin::hashes::Hash as _;
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::SecretKey;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{
    ecdsa, transaction, Amount, Network, OutPoint, PrivateKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use psbt_v2::{
    input, CombineError, Count, Global, Input, Output, Psbt, PsbtSighashType,
    RequiredHeightLockTime,
};

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

fn dummy_tx(label: &[u8]) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() }],
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
fn combine_sequence_semantics() {
    let op = outpoint(b"in");

    // Scenario 1: self has no sequence, could end up being the default Sequence::MAX, other
    // explicitly sets a non-default value. Other's value is adopted.
    let input_a = Input::new(&op);
    let mut input_b = Input::new(&op);
    input_b.sequence = Some(Sequence::ZERO);

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
    assert_eq!(
        combined.inputs[0].sequence,
        Some(Sequence::ZERO),
        "None should let other's explicit value through, do not interpret as Sequence::MAX"
    );

    // Scenario 2: self explicitly sets Sequence::MAX (signals finality). Even though MAX is the
    // default when omitted, an explicit MAX is a deliberate choice, other's value must not override
    // it.
    let mut input_a = Input::new(&op);
    input_a.sequence = Some(Sequence::MAX);
    let mut input_b = Input::new(&op);
    input_b.sequence = Some(Sequence::ZERO);

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
    assert_eq!(
        combined.inputs[0].sequence,
        Some(Sequence::MAX),
        "explicit Sequence::MAX must not be overridden"
    );
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
fn combine_rejects_lock_time_type_mismatch() {
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
    input_b1.min_height = Some(RequiredHeightLockTime::from_consensus(800_000).unwrap());

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
    assert!(
        matches!(err, CombineError::LockTimeMismatch { .. }),
        "expected LockTimeMismatch, got {:?}",
        err
    );
}

#[test]
fn combine_rejects_lock_time_value_mismatch() {
    let op = outpoint(b"input 0");

    // PSBT A and PSBT B require height-based locks on the same input, but at
    // different heights. Each is individually determinable; the resolved lock
    // times still differ, so the combination is rejected rather than silently
    // keeping one of the values.
    let mut input_a = Input::new(&op);
    input_a.min_height = Some(RequiredHeightLockTime::from_consensus(700_000).unwrap());

    let mut input_b = Input::new(&op);
    input_b.min_height = Some(RequiredHeightLockTime::from_consensus(800_000).unwrap());

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

    assert!(psbt_a.determine_lock_time().is_ok());
    assert!(psbt_b.determine_lock_time().is_ok());

    let err = psbt_a.combine_with(psbt_b).unwrap_err();
    assert!(
        matches!(err, CombineError::LockTimeMismatch { .. }),
        "expected LockTimeMismatch, got {:?}",
        err
    );
}

#[test]
fn combine_rejects_sequence_mismatch_with_signatures() {
    let op = outpoint(b"in");

    let mut input_a = Input::new(&op);
    input_a.sequence = Some(Sequence::ZERO);
    let mut input_b = Input::new(&op);
    input_b.sequence = Some(Sequence::MAX);
    input_b.partial_sigs.insert(keypair(1), make_sig(1, EcdsaSighashType::All));

    let psbt = |input| Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input],
        outputs: vec![dummy_output()],
    };

    let err = psbt(input_a.clone()).combine_with(psbt(input_b.clone())).unwrap_err();
    assert!(
        matches!(
            err,
            CombineError::SequenceMismatch { input: 0, this, that }
                if this == Sequence::ZERO && that == Sequence::MAX
        ),
        "expected SequenceMismatch, got {:?}",
        err
    );

    // Without signature data a conflicting sequence is not an error; the value in `self` is kept
    // as documented on `Psbt::combine_with`.
    input_b.partial_sigs.clear();
    let combined = psbt(input_a).combine_with(psbt(input_b)).expect("combine should succeed");
    assert_eq!(combined.inputs[0].sequence, Some(Sequence::ZERO));
}

#[test]
fn combine_rejects_sequence_mismatch_on_other_input_with_all_sigs() {
    let op0 = outpoint(b"input 0");
    let op1 = outpoint(b"input 1");

    // Both PSBTs agree on input 0's sequence; input 1's sequence differs. Only PSBT B carries a
    // signature (on input 0): a SIGHASH_ALL signature commits to every input's sequence, so the
    // combination is rejected even though the mismatching input itself has no signatures.
    let input_a0 = Input::new(&op0);
    let mut input_a1 = Input::new(&op1);
    input_a1.sequence = Some(Sequence::ZERO);

    let mut input_b0 = Input::new(&op0);
    input_b0.partial_sigs.insert(keypair(1), make_sig(1, EcdsaSighashType::All));
    let mut input_b1 = Input::new(&op1);
    input_b1.sequence = Some(Sequence::MAX);

    let psbt = |inputs: [Input; 2]| Psbt {
        global: Global {
            input_count: Count::from(2),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: inputs.to_vec(),
        outputs: vec![dummy_output()],
    };

    let err = psbt([input_a0, input_a1]).combine_with(psbt([input_b0, input_b1])).unwrap_err();
    assert!(
        matches!(err, CombineError::SequenceMismatch { input: 1, .. }),
        "expected SequenceMismatch for input 1, got {:?}",
        err
    );
}

#[test]
fn combine_accepts_unset_sequence_with_explicit_max_and_signatures() {
    let op = outpoint(b"in");

    // PSBT_IN_SEQUENCE defaults to Sequence::MAX when omitted (BIP-370), so an unset sequence and
    // an explicit Sequence::MAX are the same effective value and must combine even with sigs.
    let input_a = Input::new(&op);
    let mut input_b = Input::new(&op);
    input_b.sequence = Some(Sequence::MAX);
    input_b.partial_sigs.insert(keypair(1), make_sig(1, EcdsaSighashType::All));

    let psbt = |input| Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input],
        outputs: vec![dummy_output()],
    };

    let combined = psbt(input_a).combine_with(psbt(input_b)).expect("combine should succeed");
    assert_eq!(combined.inputs[0].sequence, Some(Sequence::MAX));
}

#[test]
fn combine_utxo_conflicts() {
    let op = outpoint(b"in");

    let psbt = |input| Psbt {
        global: Global {
            input_count: Count::from(1),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input],
        outputs: vec![dummy_output()],
    };

    // Matching UTXOs combine fine.
    let mut input_a = Input::new(&op);
    input_a.witness_utxo =
        Some(TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() });
    let mut input_b = Input::new(&op);
    input_b.witness_utxo =
        Some(TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() });
    psbt(input_a.clone()).combine_with(psbt(input_b.clone())).expect("equal UTXOs should combine");

    // Conflicting witness UTXOs are rejected: segwit and taproot signatures commit to the spent
    // output's amount.
    input_b.witness_utxo =
        Some(TxOut { value: Amount::from_sat(2_000), script_pubkey: ScriptBuf::new() });
    let err = psbt(input_a).combine_with(psbt(input_b)).unwrap_err();
    assert!(
        matches!(err, CombineError::Input(input::CombineError::WitnessUtxoMismatch { .. })),
        "expected WitnessUtxoMismatch, got {:?}",
        err
    );

    // Conflicting non-witness UTXOs (different funding transactions) are rejected.
    let mut input_a = Input::new(&op);
    input_a.non_witness_utxo = Some(dummy_tx(b"funding tx A"));
    let mut input_b = Input::new(&op);
    input_b.non_witness_utxo = Some(dummy_tx(b"funding tx B"));

    let err = psbt(input_a).combine_with(psbt(input_b)).unwrap_err();
    assert!(
        matches!(err, CombineError::Input(input::CombineError::NonWitnessUtxoMismatch { .. })),
        "expected NonWitnessUtxoMismatch, got {:?}",
        err
    );
}
