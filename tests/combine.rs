// SPDX-License-Identifier: CC0-1.0

//! Integration tests for PSBT combining.

#![cfg(feature = "std")]

use bitcoin::hashes::Hash as _;
use bitcoin::locktime::absolute;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
use psbt_v2::{CombineError, Count, Global, Input, Output, Psbt};

#[test]
fn combine_errors_when_lock_time_becomes_undeterminable() {
    let outpoint0 = OutPoint { txid: Txid::hash(b"input 0"), vout: 0 };
    let outpoint1 = OutPoint { txid: Txid::hash(b"input 1"), vout: 0 };

    let output =
        Output::new(TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() });

    // PSBT A: input 0 requires time-based lock, input 1 has no lock time fields.
    let mut input_a0 = Input::new(&outpoint0);
    input_a0.min_time = Some(absolute::Time::from_consensus(1_657_048_459).unwrap());
    let input_a1 = Input::new(&outpoint1);

    let psbt_a = Psbt {
        global: Global {
            input_count: Count::from(2),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input_a0, input_a1],
        outputs: vec![output.clone()],
    };

    // PSBT B: input 0 has no lock time fields, input 1 requires height-based lock.
    let input_b0 = Input::new(&outpoint0);
    let mut input_b1 = Input::new(&outpoint1);
    input_b1.min_height = Some(absolute::Height::from_consensus(800_000).unwrap());

    let psbt_b = Psbt {
        global: Global {
            input_count: Count::from(2),
            output_count: Count::from(1),
            ..Global::default()
        },
        inputs: vec![input_b0, input_b1],
        outputs: vec![output],
    };

    // Individually both have determinable lock times.
    assert!(psbt_a.determine_lock_time().is_ok());
    assert!(psbt_b.determine_lock_time().is_ok());

    // Combining merges: input 0 gets min_time from A,
    // input 1 gets min_height from B, cross-input conflict.
    let err = psbt_a.combine_with(psbt_b).unwrap_err();
    assert!(matches!(err, CombineError::LockTime(_)), "expected LockTime error, got {:?}", err);
}
