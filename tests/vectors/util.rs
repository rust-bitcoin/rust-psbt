//! Test utility functions.

use psbt_v2::bitcoin::hex::{self, FromHex};
use psbt_v2::{DeserializeError, DeserializeV0Error, Psbt};

#[track_caller]
pub fn hex_psbt_v0(s: &str) -> Result<Psbt, DeserializeV0Error> {
    let r: Result<Vec<u8>, hex::HexToBytesError> = Vec::from_hex(s);
    match r {
        Err(_e) => panic!("unable to parse PSBT v0 from hex string {}", s),
        Ok(v) => Psbt::deserialize_v0(&v),
    }
}

#[track_caller]
pub fn hex_psbt_v2(s: &str) -> Result<Psbt, DeserializeError> {
    let r: Result<Vec<u8>, hex::HexToBytesError> = Vec::from_hex(s);
    match r {
        Err(_e) => panic!("unable to parse PSBT v2 from hex string {}", s),
        Ok(v) => Psbt::deserialize(&v),
    }
}

#[track_caller]
pub fn assert_valid_v0(hex: &str, base64: &str) {
    if let Err(e) = hex_psbt_v0(hex) {
        println!("Parse PSBT v0 (from hex) error: {:?}\n\n{}\n", e, hex);
        panic!()
    }
    // If we got this far decoding works so this is basically just a sanity check.
    assert!(Psbt::deserialize_v0_base64(base64).is_ok());
}

#[track_caller]
pub fn assert_valid_v2(hex: Option<&str>, base64: &str) {
    if let Some(h) = hex.filter(|h| !h.is_empty()) {
        assert!(hex_psbt_v2(h).is_ok());
    }
    assert!(base64.parse::<Psbt>().is_ok());
}

#[track_caller]
pub fn assert_invalid_v0(hex: &str, base64: &str) {
    assert!(hex_psbt_v0(hex).is_err());
    assert!(Psbt::deserialize_v0_base64(base64).is_err());
}

#[track_caller]
pub fn assert_invalid_v2(hex: Option<&str>, base64: &str) {
    if let Some(h) = hex.filter(|h| !h.is_empty()) {
        assert!(hex_psbt_v2(h).is_err());
    }
    assert!(base64.parse::<Psbt>().is_err());
}
