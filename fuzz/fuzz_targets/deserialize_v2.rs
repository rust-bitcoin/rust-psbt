// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for PSBT v2 deserialization and serialization round-trips via the v2 interface.

#![no_main]
use libfuzzer_sys::arbitrary::{self, Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use psbt_v2::Psbt;

/// A pair of deserialized PSBTs produced from fuzz input.
#[derive(Debug)]
struct PsbtPair(Psbt, Psbt);

impl<'a> Arbitrary<'a> for PsbtPair {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Split input into two slices two psbts.
        let split = u.arbitrary_len::<u8>()?;
        let bytes_a = u.bytes(split)?;
        let bytes_b = u.bytes(u.len())?;
        let a =
            Psbt::deserialize_unresolved(bytes_a).map_err(|_| arbitrary::Error::IncorrectFormat)?;
        let b =
            Psbt::deserialize_unresolved(bytes_b).map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(PsbtPair(a, b))
    }
}

fuzz_target!(|data: PsbtPair| {
    let psbt_a = data.0;
    let psbt_b = data.1;

    // Test round-trip. The v2 serializer/deserializer must be inverses.
    let ser = psbt_a.serialize();
    let deser = Psbt::deserialize_unresolved(&ser).expect("serialize output must deserialize");
    assert_eq!(ser, deser.serialize());

    // Combining should be commutative in terms of success/failure.
    let result_ab = psbt_a.clone().combine_with(psbt_b.clone()).is_ok();
    let result_ba = psbt_b.combine_with(psbt_a).is_ok();
    assert_eq!(result_ab, result_ba);
});
