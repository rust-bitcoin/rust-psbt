// SPDX-License-Identifier: CC0-1.0

//! Integration test for the `serde` feature.

#![cfg(all(feature = "std", feature = "serde"))]

use std::collections::BTreeMap;

use psbt_v2::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use psbt_v2::bitcoin::hashes::{sha256d, Hash};
use psbt_v2::bitcoin::key::XOnlyPublicKey;
use psbt_v2::bitcoin::locktime::absolute;
use psbt_v2::bitcoin::taproot::TapNodeHash;
use psbt_v2::bitcoin::{Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TxOut};
use psbt_v2::{
    Count, Global, Input, Key, Output, ProprietaryKey, Psbt, PsbtSighashType,
    RequiredHeightLockTime,
};

/// A populated PSBT survives a JSON serialize-deserialize round-trip.
#[test]
fn round_trip_json() {
    let pk: PublicKey =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".parse().unwrap();
    let xonly: XOnlyPublicKey =
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".parse().unwrap();
    let fp = Fingerprint::from([0xaa; 4]);
    let key_source = (fp, DerivationPath::from(vec![ChildNumber::from_normal_idx(0).unwrap()]));
    let script = ScriptBuf::from(vec![0x51]);
    let utxo = TxOut { value: Amount::from_sat(100_000), script_pubkey: script.clone() };

    let outpoint = OutPoint {
        txid: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".parse().unwrap(),
        vout: 0,
    };

    let mut input = Input::new(&outpoint);
    input.witness_utxo = Some(utxo);
    input.sequence = Some(Sequence::MAX);
    input.min_time = Some(absolute::Time::from_consensus(1_700_000_000).unwrap());
    input.min_height = Some(RequiredHeightLockTime::from_consensus(700_000).unwrap());
    input.sighash_type = Some(PsbtSighashType::ALL);
    input.redeem_script = Some(script.clone());
    input.witness_script = Some(script.clone());
    input.tap_internal_key = Some(xonly);
    input.tap_merkle_root = Some(TapNodeHash::all_zeros());
    input.bip32_derivations = BTreeMap::from([(pk, key_source.clone())]);
    input.hash256_preimages = BTreeMap::from([(sha256d::Hash::all_zeros(), vec![0xdd; 8])]);
    input.proprietaries = BTreeMap::from([(
        ProprietaryKey { prefix: b"test".to_vec(), subtype: 0x01u64, key: vec![0xaa; 2] },
        vec![0xbb; 4],
    )]);
    input.unknowns =
        BTreeMap::from([(Key { type_value: 0xfc, key: vec![0x01; 2] }, vec![0xcc; 4])]);

    let mut output =
        Output::new(TxOut { value: Amount::from_sat(50_000), script_pubkey: script.clone() });
    output.redeem_script = Some(script.clone());
    output.witness_script = Some(script);
    output.tap_internal_key = Some(xonly);
    output.bip32_derivations = BTreeMap::from([(pk, key_source)]);
    output.unknowns =
        BTreeMap::from([(Key { type_value: 0xfd, key: vec![0x02; 2] }, vec![0xee; 4])]);
    output.proprietaries = BTreeMap::from([(
        ProprietaryKey { prefix: b"acme".to_vec(), subtype: 0x00u64, key: vec![0x03; 1] },
        vec![0xff; 3],
    )]);

    let global = Global {
        version: psbt_v2::V2,
        input_count: Count::from(1),
        output_count: Count::from(1),
        unknowns: BTreeMap::from([(Key { type_value: 0xfb, key: vec![0x03; 2] }, vec![0xaa; 4])]),
        proprietaries: BTreeMap::from([(
            ProprietaryKey { prefix: b"rust".to_vec(), subtype: 0x02u64, key: vec![0x04; 1] },
            vec![0xbb; 3],
        )]),
        ..Global::default()
    };

    let psbt = Psbt { global, inputs: vec![input], outputs: vec![output] };

    let json = serde_json::to_string_pretty(&psbt).expect("serialize to JSON");
    let roundtripped: Psbt = serde_json::from_str(&json).expect("deserialize from JSON");
    assert_eq!(psbt, roundtripped, "PSBT round-trip through JSON must be lossless");
}
