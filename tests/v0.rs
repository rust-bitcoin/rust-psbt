// SPDX-License-Identifier: CC0-1.0

//! Integration tests for the PSBT v0 (BIP-174) interface.
//!
//! The crate's primary PSBT interface is v2 (BIP-370), v0 PSBTs are supported through explicit
//! decode/encode entry points.

#![cfg(feature = "std")]

use psbt_v2::bitcoin::absolute::{Height, LockTime};
use psbt_v2::bitcoin::hex::{DisplayHex, FromHex};
use psbt_v2::bitcoin::{Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TxOut};
use psbt_v2::{Constructor, Creator, Input, Modifiable, Output, Psbt, SerializeV0Error, Signer};

const PUBKEY_HEX: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TEST_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const TEST_XPRIV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
/// The BIP-174 "create" test vector (Workflow A step 1). The canonical empty PSBT with two inputs
/// and two outputs, tx version 2, lock time zero, sequences `Sequence::MAX`.
const CREATE_VECTOR_HEX: &str = "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000";

/// BIP-174 deserialize vector "Valid: one P2PKH input and no outputs in PSBT"
/// (unsigned tx lock_time = 1257139).
const LOCKTIME_VECTOR_HEX: &str = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000000000";

/// BIP-174 deserialize vector "Valid: PSBT with unknown types in the inputs".
const UNKNOWN_VECTOR_HEX: &str = "70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a010000000000000af00102030405060708090f0102030405060708090a0b0c0d0e0f0000";

fn make_tx_out(sats: u64) -> TxOut {
    TxOut { value: Amount::from_sat(sats), script_pubkey: ScriptBuf::from(vec![0xab; 4]) }
}

/// Serializes `psbt` as a v0 PSBT then deserializes the bytes back into a v2 PSBT.
fn round_trip_v0(psbt: &Psbt) -> Psbt {
    let bytes = psbt.serialize_v0_lossy().expect("serialize_v0_lossy");
    Psbt::deserialize_v0(&bytes).expect("deserialize_v0")
}

/// A BIP-174 PSBT decodes into the v2 representation with the unsigned
/// transaction's fields redistributed onto the v2 global and per-input maps.
#[test]
fn deserialize_v0_redistributes_unsigned_tx_fields() {
    let bytes = Vec::from_hex(CREATE_VECTOR_HEX).unwrap();
    let psbt = Psbt::deserialize_v0(&bytes).expect("valid v0 PSBT");

    assert_eq!(psbt.global.version, psbt_v2::V2);
    assert_eq!(psbt.global.tx_version, psbt_v2::bitcoin::transaction::Version::TWO);
    assert_eq!(psbt.global.fallback_lock_time, None); // lock time is zero
    assert_eq!(psbt.global.input_count, 2);
    assert_eq!(psbt.global.output_count, 2);
    assert_eq!(psbt.inputs.len(), 2);
    assert_eq!(psbt.outputs.len(), 2);
    assert_eq!(psbt.inputs[0].sequence, Some(Sequence::MAX));
    assert_eq!(psbt.inputs[1].sequence, Some(Sequence::MAX));
}

/// The v0 entry point must reject v2-encoded PSBTs (global version 2).
#[test]
fn deserialize_v0_rejects_v2_psbt() {
    let v2_psbt = Psbt { global: psbt_v2::Global::default(), inputs: vec![], outputs: vec![] };
    assert!(Psbt::deserialize_v0(&v2_psbt.serialize()).is_err());
}

/// A nonzero v0 unsigned-transaction lock time becomes the v2 global fallback
/// lock time (a zero lock time is omitted, since v2 defaults an absent fallback
/// to zero).
#[test]
fn deserialize_v0_preserves_nonzero_lock_time() {
    let bytes = Vec::from_hex(LOCKTIME_VECTOR_HEX).unwrap();
    let psbt = Psbt::deserialize_v0(&bytes).expect("valid v0 PSBT");

    assert_eq!(
        psbt.global.fallback_lock_time,
        Some(LockTime::from(Height::from_consensus(1_257_139).expect("valid height")))
    );
}

/// Unknown v0 keys survive the conversion into the v2 unknowns maps with their raw keys intact.
#[test]
fn deserialize_v0_preserves_unknown_fields() {
    let bytes = Vec::from_hex(UNKNOWN_VECTOR_HEX).unwrap();
    let psbt = Psbt::deserialize_v0(&bytes).expect("valid v0 PSBT");

    // The vector's input carries a single unknown key-value pair.
    assert_eq!(psbt.inputs.len(), 1);
    assert_eq!(psbt.inputs[0].unknowns.len(), 1);
    let (key, value) = psbt.inputs[0].unknowns.iter().next().unwrap();
    assert_eq!(key.type_value, 0xf0);
    assert_eq!(key.key.as_hex().to_string(), "010203040506070809");
    assert_eq!(value.as_hex().to_string(), "0102030405060708090a0b0c0d0e0f");
}

#[cfg(feature = "base64")]
#[test]
fn deserialize_v0_base64_decodes() {
    use psbt_v2::bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};

    let bytes = Vec::from_hex(CREATE_VECTOR_HEX).unwrap();
    let b64 = BASE64_STANDARD.encode(&bytes);

    let from_hex = Psbt::deserialize_v0(&bytes).unwrap();
    let from_base64 = Psbt::deserialize_v0_base64(&b64).expect("valid base64 v0 PSBT");

    assert_eq!(from_base64, from_hex);
}

/// A PSBT decoded from v0 bytes carries no v2-only fields: the strict encoder
/// succeeds on it and re-encodes byte-identically.
#[test]
fn strict_encode_round_trips_v0_decoded_psbt() {
    let bytes = Vec::from_hex(CREATE_VECTOR_HEX).unwrap();
    let psbt = Psbt::deserialize_v0(&bytes).unwrap();

    let encoded = psbt.serialize_v0().expect("v0-decoded PSBT must strictly encode");
    assert_eq!(encoded, bytes);
}

/// A PSBT with v2-only fields fails the strict encoder but succeeds with the
/// lossy one, and the lossy output re-decodes to a strictly-encodable PSBT.
#[test]
fn strict_fails_on_v2_only_fields_lossy_drops_them() {
    // The Constructor marks the PSBT as inputs-and-outputs modifiable, a
    // v2-only global field.
    let psbt = Constructor::<Modifiable>::default()
        .input(Input::new(&OutPoint::null()))
        .output(Output::new(make_tx_out(1)))
        .expect("output must be valid")
        .psbt()
        .unwrap();
    assert_eq!(psbt.global.tx_modifiable_flags & 0b11, 0b11);

    assert!(matches!(psbt.serialize_v0(), Err(SerializeV0Error::Lossy)));

    let v0_bytes = psbt.serialize_v0_lossy().expect("lossy encode");
    let decoded = Psbt::deserialize_v0(&v0_bytes).unwrap();
    // The dropped modifiable flags are gone: the decoded PSBT strictly encodes.
    assert_eq!(decoded.serialize_v0().unwrap(), v0_bytes);
}

/// Per-input fields that have no v0 equivalent (min_time/min_height) surface in
/// the reconstructed v0 unsigned transaction's lock time and thereby in the
/// fallback lock time of a decoded PSBT; sequence survives on the input.
#[test]
fn v2_only_input_fields_surface_in_v0_unsigned_tx() {
    use psbt_v2::bitcoin::absolute;

    let height = absolute::Height::from_consensus(800_000).unwrap();
    let mut input = Input::new(&OutPoint::null());
    input.min_height = Some(height);
    input.sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(Output::new(make_tx_out(1)))
        .expect("output must be valid")
        .psbt()
        .unwrap();

    let parsed = round_trip_v0(&psbt);

    assert_eq!(parsed.global.fallback_lock_time, Some(LockTime::Blocks(height)));
    assert_eq!(parsed.inputs[0].sequence, Some(Sequence::ENABLE_LOCKTIME_NO_RBF));
    assert!(parsed.inputs[0].min_height.is_none()); // dropped as a field
}

/// Signing a PSBT and then converting to v0 preserves the signatures.
#[test]
fn sign_then_convert_preserves_signatures() {
    use psbt_v2::bitcoin::bip32::{IntoDerivationPath, Xpriv, Xpub};
    use psbt_v2::bitcoin::secp256k1::Secp256k1;

    let pk = PUBKEY_HEX.parse::<PublicKey>().unwrap();
    let path = "m/0".into_derivation_path().unwrap();
    let fingerprint = TEST_XPUB.parse::<Xpub>().unwrap().fingerprint();

    let mut input = Input::new(&OutPoint::null());
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(123_456),
        script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
    });
    input.bip32_derivations.insert(pk, (fingerprint, path));

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(Output::new(make_tx_out(1)))
        .expect("output must be valid")
        .psbt()
        .unwrap();

    let secp = Secp256k1::<psbt_v2::bitcoin::secp256k1::All>::new();
    let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
    let (signed, _) = Signer::new(psbt).unwrap().sign(&xpriv, &secp).unwrap();

    let parsed = round_trip_v0(&signed);
    assert_eq!(parsed.inputs[0].partial_sigs, signed.inputs[0].partial_sigs);
}

#[cfg(feature = "base64")]
#[test]
fn base64_encode_lossy_then_decode_round_trips() {
    let bytes = Vec::from_hex(CREATE_VECTOR_HEX).unwrap();
    let psbt = Psbt::deserialize_v0(&bytes).unwrap();

    let b64 = psbt.serialize_v0_base64_lossy().expect("serialize_v0_base64_lossy");
    let decoded = Psbt::deserialize_v0_base64(&b64).expect("deserialize_v0_base64");
    assert_eq!(decoded, psbt);
}
