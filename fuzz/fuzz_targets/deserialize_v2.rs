// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for PSBT v2 deserialization and serialization round-trips via the v2 interface.

#![no_main]
use libfuzzer_sys::fuzz_target;
use psbt_v2::Psbt;

fn do_test(data: (&[u8], &[u8])) {
    let (bytes_a, bytes_b) = data;

    // Deserialize first PSBT v2.
    let Ok(psbt_a) = Psbt::deserialize(bytes_a) else {
        return;
    };

    // Test round-trip. The v2 serializer/deserializer must be inverses.
    let ser = psbt_a.serialize();
    let deser = Psbt::deserialize(&ser).expect("serialize output must deserialize");
    assert_eq!(ser, deser.serialize());

    // Test combining two PSBTs.
    let Ok(psbt_b) = Psbt::deserialize(bytes_b) else {
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
