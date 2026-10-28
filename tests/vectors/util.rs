//! Test utility functions.

use psbt_v2::{ParsePsbtError, Psbt, PsbtV0};

#[track_caller]
pub fn base64_psbt_v0(s: &str) -> Result<Psbt, ParsePsbtError> {
    PsbtV0::deserialize_base64(s).map(|v0| v0.into_psbt())
}

#[track_caller]
pub fn base64_psbt_v2(s: &str) -> Result<Psbt, ParsePsbtError> { s.parse::<Psbt>() }

#[track_caller]
pub fn assert_valid_v0(base64: &str) {
    if let Err(e) = base64_psbt_v0(base64) {
        println!("Parse PSBT v0 (from base64) error: {:?}\n\n{}\n", e, base64);
        panic!()
    }
}

#[track_caller]
pub fn assert_valid_v2(base64: &str) {
    assert!(base64.parse::<Psbt>().is_ok());
}

#[track_caller]
pub fn assert_invalid_v0(base64: &str) {
    assert!(base64_psbt_v0(base64).is_err());
}

#[track_caller]
pub fn assert_invalid_v2(base64: &str) {
    assert!(base64.parse::<Psbt>().is_err());
}
