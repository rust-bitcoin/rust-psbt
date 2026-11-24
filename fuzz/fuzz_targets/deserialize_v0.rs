// SPDX-License-Identifier: CC0-1.0

//! Fuzz test for PSBT v0 deserialization and serialization round-trips via the v2 interface.

#![no_main]
use libfuzzer_sys::arbitrary::{self, Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use psbt_v2::PsbtV0;

/// A v0-decoded PSBT produced from fuzz input.
#[derive(Debug)]
struct PsbtV0Arbitrary(psbt_v2::Psbt);

impl<'a> Arbitrary<'a> for PsbtV0Arbitrary {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let psbt = PsbtV0::deserialize(u.bytes(u.len())?)
            .map(|v0| v0.into_psbt())
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(PsbtV0Arbitrary(psbt))
    }
}

fuzz_target!(|data: PsbtV0Arbitrary| {
    let psbt_a = data.0;

    // Test round-trip. PSBTs decoded from v0 carry no v2-only fields and always have a
    // determinable lock time, so the strict encoder (which fails rather than lose data) must
    // always succeed on them.
    let v0_round = PsbtV0::from_psbt(psbt_a.clone()).expect("v0-decoded PSBT must strictly encode");
    let ser = v0_round.serialize();
    let deser =
        PsbtV0::deserialize(&ser).expect("serialize_v0 output must deserialize").into_psbt();
    let v0_deser = PsbtV0::from_psbt(deser).expect("already serialized once");
    assert_eq!(ser, v0_deser.serialize());
});
