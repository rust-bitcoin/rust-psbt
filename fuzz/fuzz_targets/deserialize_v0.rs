// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for PSBT v0 deserialization and serialization round-trips via the v2 interface.

#![no_main]
use libfuzzer_sys::fuzz_target;
use psbt_v2::PsbtV0;

fn do_test(data: (&[u8], &[u8])) {
    let (bytes_a, bytes_b) = data;

    // Deserialize first PSBT v0.
    let Ok(v0_a) = PsbtV0::deserialize(bytes_a) else {
        return;
    };
    let psbt_a = v0_a.into_psbt();

    // Test round-trip. PSBTs decoded from v0 carry no v2-only fields and always have a
    // determinable lock time, so the strict encoder (which fails rather than lose data) must
    // always succeed on them.
    let v0_round = PsbtV0::from_psbt(psbt_a.clone())
        .expect("v0-decoded PSBT must strictly encode");
    let ser = v0_round.serialize();
    let deser = PsbtV0::deserialize(&ser)
        .expect("serialize_v0 output must deserialize")
        .into_psbt();
    let v0_deser = PsbtV0::from_psbt(deser).expect("already serialized once");
    assert_eq!(ser, v0_deser.serialize());

    // Test combining two PSBTs.
    let Ok(v0_b) = PsbtV0::deserialize(bytes_b) else {
        return;
    };
    let psbt_b = v0_b.into_psbt();

    // Combining should be commutative in terms of success/failure.
    let result_ab = psbt_a.clone().combine_with(psbt_b.clone()).is_ok();
    let result_ba = psbt_b.combine_with(psbt_a).is_ok();
    assert_eq!(result_ab, result_ba);
}

fuzz_target!(|data: (&[u8], &[u8])| {
    do_test(data);
});
