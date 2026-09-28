// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for PSBT v0 deserialization and serialization round-trips via the v2 interface.

#![no_main]
use libfuzzer_sys::fuzz_target;
use psbt_v2::Psbt;

fn do_test(data: (&[u8], &[u8])) {
    let (bytes_a, bytes_b) = data;

    // Deserialize first PSBT v0.
    let Ok(psbt_a) = Psbt::deserialize_v0(bytes_a) else {
        return;
    };

    // Test round-trip. PSBTs decoded from v0 carry no v2-only fields and always have a
    // determinable lock time, so the strict encoder (which fails rather than lose data) must
    // always succeed on them.
    let ser = psbt_a.serialize_v0().expect("v0-decoded PSBT must strictly encode");
    let deser = Psbt::deserialize_v0(&ser).expect("serialize_v0 output must deserialize");
    assert_eq!(ser, deser.serialize_v0().expect("already serialized once"));

    // Test combining two PSBTs.
    let Ok(psbt_b) = Psbt::deserialize_v0(bytes_b) else {
        return;
    };

    // Combining should be commutative in terms of success/failure.
    let result_ab = psbt_a.clone().combine_with(psbt_b.clone()).is_ok();
    let result_ba = psbt_b.combine_with(psbt_a).is_ok();
    assert_eq!(result_ab, result_ba);
}

fuzz_target!(|data: (&[u8], &[u8])| {
    do_test(data);
});
