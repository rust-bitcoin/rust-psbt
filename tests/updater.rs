// SPDX-License-Identifier: CC0-1.0

//! Integration tests for the Updater role.

#![cfg(feature = "std")]

use std::str::FromStr;

use psbt_v2::bitcoin::absolute::LockTime;
use psbt_v2::bitcoin::bip32::{DerivationPath, Fingerprint, KeySource, Xpriv, Xpub};
use psbt_v2::bitcoin::hashes::Hash;
use psbt_v2::bitcoin::key::XOnlyPublicKey;
use psbt_v2::bitcoin::secp256k1::{Secp256k1, SecretKey};
use psbt_v2::bitcoin::taproot::{
    ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TapTree, TaprootBuilder,
};
use psbt_v2::bitcoin::transaction::Version;
use psbt_v2::bitcoin::{
    Amount, Network, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
};
use psbt_v2::{
    CombineError, Creator, Input, Output, ProprietaryKey, Psbt, PsbtSighashType,
    RequiredHeightLockTime, Updater,
};

/// A funded P2WPKH input worth 10,000 sats.
fn funded_input(seed: u8, vout: u32) -> Input {
    let funding_tx = funding_tx(seed);
    let tx_out = funding_tx.output[vout as usize].clone();
    let mut input = Input::new(&OutPoint { txid: funding_tx.compute_txid(), vout });
    input.witness_utxo = Some(tx_out);
    input
}

/// The transaction funding the `funded_input` above.
fn funding_tx(seed: u8) -> Transaction {
    let pk = test_key(seed);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
        }],
    }
}

/// A public key derived from `seed`.
fn test_key(seed: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let sk = PrivateKey::new(SecretKey::from_slice(&[seed; 32]).unwrap(), Network::Bitcoin);
    sk.public_key(&secp)
}

/// A two-input, one-output PSBT built via the Creator role.
fn two_party_psbt(input_a: Input, input_b: Input) -> Psbt {
    let destination = TxOut { value: Amount::from_sat(15_000), script_pubkey: ScriptBuf::new() };
    Creator::new()
        .constructor_modifiable()
        .input(input_a)
        .expect("lock time must be determinable")
        .input(input_b)
        .expect("lock time must be determinable")
        .output(Output::new(destination))
        .expect("output must be valid")
        .psbt()
}

/// A basic round-trip: enter the Updater role, update via a draft, extract the Psbt.
#[test]
fn update_then_extract_psbt() {
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let updater = Updater::new(psbt.try_resolve().unwrap());
    let updater = updater
        .update(|mut draft| {
            draft.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
            draft
        })
        .unwrap();
    let psbt = updater.psbt();

    assert_eq!(psbt.inputs[0].sequence, Some(Sequence::ENABLE_LOCKTIME_NO_RBF));
    // The sighash type was not set by this update, so it remains unset.
    assert_eq!(psbt.inputs[0].sighash_type, None);
    // The second input was not touched.
    assert_eq!(psbt.inputs[1].sequence, None);
}

/// Multiple `update()` calls accumulate updates across calls.
#[test]
fn multiple_updates_accumulate() {
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let updater = Updater::new(psbt.try_resolve().unwrap());

    let updater = updater
        .update(|mut draft| {
            draft.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
            draft
        })
        .unwrap();

    let updater = updater
        .update(|mut draft| {
            draft.inputs[1].sequence = Some(Sequence::ENABLE_RBF_NO_LOCKTIME);
            draft
        })
        .unwrap();

    let psbt = updater.psbt();

    assert_eq!(psbt.inputs[0].sequence, Some(Sequence::ENABLE_LOCKTIME_NO_RBF));
    assert_eq!(psbt.inputs[1].sequence, Some(Sequence::ENABLE_RBF_NO_LOCKTIME));
}

/// A draft can read from one input and write data to another.
#[test]
fn cross_map_read_and_write() {
    let pk = test_key(1);

    let mut input_a = funded_input(1, 0);
    input_a.bip32_derivations.insert(pk, KeySource::default());

    let psbt = two_party_psbt(input_a, funded_input(2, 0));

    let updater = Updater::new(psbt.try_resolve().unwrap());
    let psbt = updater
        .update(|mut draft| {
            // Read a derivation from input 0, apply the same derivation to input 1.
            let derivations: Vec<_> =
                draft.inputs[0].bip32_derivations.iter().map(|(k, v)| (*k, v.clone())).collect();
            for (key, source) in derivations {
                draft.inputs[1].bip32_derivations.insert(key, source);
            }
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.inputs[1].bip32_derivations.len(), 1);
}

/// The updater can set the UTXO, scripts, sequence, and taproot data of an input.
#[test]
fn update_sets_input_fields() {
    let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let updater = Updater::new(psbt.try_resolve().unwrap());
    let mut cb_bytes = vec![0x01u8];
    cb_bytes.extend_from_slice(&xonly.serialize());
    let leaf = TapLeafHash::from_byte_array([12u8; 32]);
    let psbt = updater
        .update(|mut draft| {
            draft.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
            draft.inputs[0].non_witness_utxo = Some(funding_tx(1));
            draft.inputs[0].redeem_script = Some(ScriptBuf::from_bytes(vec![0x51]));
            draft.inputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x52]));
            draft.inputs[0].tap_internal_key = Some(xonly);
            draft.inputs[0].tap_merkle_root = Some(TapNodeHash::from_byte_array([7u8; 32]));
            draft.inputs[0].tap_scripts.insert(
                ControlBlock::decode(&cb_bytes).unwrap(),
                (ScriptBuf::from_bytes(vec![0x53]), LeafVersion::TapScript),
            );
            draft.inputs[0].tap_key_origins.insert(xonly, (vec![leaf], KeySource::default()));
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.inputs[0].sequence, Some(Sequence::ENABLE_LOCKTIME_NO_RBF));
    assert_eq!(psbt.inputs[0].non_witness_utxo, Some(funding_tx(1)));
    assert_eq!(psbt.inputs[0].redeem_script, Some(ScriptBuf::from_bytes(vec![0x51])));
    assert_eq!(psbt.inputs[0].witness_script, Some(ScriptBuf::from_bytes(vec![0x52])));
    assert_eq!(psbt.inputs[0].tap_internal_key, Some(xonly));
    assert_eq!(psbt.inputs[0].tap_merkle_root, Some(TapNodeHash::from_byte_array([7u8; 32])));
    assert_eq!(
        psbt.inputs[0].tap_scripts.get(&ControlBlock::decode(&cb_bytes).unwrap()),
        Some(&(ScriptBuf::from_bytes(vec![0x53]), LeafVersion::TapScript))
    );
    assert_eq!(
        psbt.inputs[0].tap_key_origins.get(&xonly),
        Some(&(vec![leaf], KeySource::default()))
    );
}

/// The witness UTXO can be added to an input that has none set.
#[test]
fn update_sets_witness_utxo() {
    let input_a = Input::new(&OutPoint { txid: funding_tx(1).compute_txid(), vout: 0 });
    let psbt = two_party_psbt(input_a, funded_input(2, 0));

    let updater = Updater::new(psbt.try_resolve().unwrap());
    let psbt = updater
        .update(|mut draft| {
            draft.inputs[0].witness_utxo = Some(funding_tx(1).output[0].clone());
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.inputs[0].witness_utxo, Some(funding_tx(1).output[0].clone()));
}

/// The sighash type of an input is updatable.
#[test]
fn update_sets_sighash_type() {
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let updater = Updater::new(psbt.try_resolve().unwrap());
    let psbt = updater
        .update(|mut draft| {
            draft.inputs[0].sighash_type = Some(PsbtSighashType::ALL);
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.inputs[0].sighash_type, Some(PsbtSighashType::ALL));
}

/// All four BIP-174 hash-preimage maps are updatable.
#[test]
fn update_adds_preimage_maps() {
    use psbt_v2::bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};

    let ripemd160_preimage = b"ripemd160 preimage".to_vec();
    let sha256_preimage = b"sha256 preimage".to_vec();
    let hash160_preimage = b"hash160 preimage".to_vec();
    let hash256_preimage = b"hash256 preimage".to_vec();

    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));
    let updater = Updater::new(psbt.try_resolve().unwrap());

    let psbt = updater
        .update(|mut draft| {
            draft.inputs[0]
                .ripemd160_preimages
                .insert(ripemd160::Hash::hash(&ripemd160_preimage), ripemd160_preimage.clone());
            draft.inputs[0]
                .sha256_preimages
                .insert(sha256::Hash::hash(&sha256_preimage), sha256_preimage.clone());
            draft.inputs[0]
                .hash160_preimages
                .insert(hash160::Hash::hash(&hash160_preimage), hash160_preimage.clone());
            draft.inputs[0]
                .hash256_preimages
                .insert(sha256d::Hash::hash(&hash256_preimage), hash256_preimage.clone());
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(
        psbt.inputs[0].ripemd160_preimages.get(&ripemd160::Hash::hash(&ripemd160_preimage)),
        Some(&ripemd160_preimage)
    );
    assert_eq!(
        psbt.inputs[0].sha256_preimages.get(&sha256::Hash::hash(&sha256_preimage)),
        Some(&sha256_preimage)
    );
    assert_eq!(
        psbt.inputs[0].hash160_preimages.get(&hash160::Hash::hash(&hash160_preimage)),
        Some(&hash160_preimage)
    );
    assert_eq!(
        psbt.inputs[0].hash256_preimages.get(&sha256d::Hash::hash(&hash256_preimage)),
        Some(&hash256_preimage)
    );
}

/// Output fields (scripts, BIP-32 derivations, and taproot data) are updatable.
#[test]
fn update_sets_output_fields() {
    let pk = test_key(4);
    let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
    let leaf = TapLeafHash::from_byte_array([12u8; 32]);
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let updater = Updater::new(psbt.try_resolve().unwrap());
    let psbt = updater
        .update(|mut draft| {
            draft.outputs[0].redeem_script = Some(ScriptBuf::from_bytes(vec![0x51]));
            draft.outputs[0].witness_script = Some(ScriptBuf::from_bytes(vec![0x52]));
            draft.outputs[0].bip32_derivations.insert(pk, KeySource::default());
            draft.outputs[0].tap_internal_key = Some(xonly);
            let mut builder = TaprootBuilder::new();
            builder = builder.add_leaf(0, ScriptBuf::from_bytes(vec![0x51])).unwrap();
            draft.outputs[0].tap_tree = Some(TapTree::try_from(builder).unwrap());
            draft.outputs[0].tap_key_origins.insert(xonly, (vec![leaf], KeySource::default()));
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.outputs[0].redeem_script, Some(ScriptBuf::from_bytes(vec![0x51])));
    assert_eq!(psbt.outputs[0].witness_script, Some(ScriptBuf::from_bytes(vec![0x52])));
    assert_eq!(psbt.outputs[0].bip32_derivations.get(&pk), Some(&KeySource::default()));
    assert_eq!(psbt.outputs[0].tap_internal_key, Some(xonly));
    assert!(psbt.outputs[0].tap_tree.is_some());
    assert_eq!(
        psbt.outputs[0].tap_key_origins.get(&xonly),
        Some(&(vec![leaf], KeySource::default()))
    );
}

/// A field cleared in the draft keeps its value: updates can set and override, but never remove.
#[test]
fn update_does_not_delete_information() {
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let updater = Updater::new(psbt.try_resolve().unwrap());
    let psbt = updater
        .update(|mut draft| {
            draft.inputs[0].witness_utxo = None;
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.inputs[0].witness_utxo, Some(funding_tx(1).output[0].clone()));
}

/// Removing a map entry from the draft keeps the stored value: updates never remove information.
#[test]
fn update_does_not_delete_map_entries() {
    let pk = test_key(1);

    let mut input_a = funded_input(1, 0);
    input_a.bip32_derivations.insert(pk, KeySource::default());

    let psbt = two_party_psbt(input_a, funded_input(2, 0));
    let updater = Updater::new(psbt.try_resolve().unwrap());

    let psbt = updater
        .update(|mut draft| {
            draft.inputs[0].bip32_derivations.remove(&pk);
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.inputs[0].bip32_derivations.get(&pk), Some(&KeySource::default()));
}

/// A map entry already set in the PSBT is preserved even when the draft carries a value for the
/// same key (the BIP-375 zeroed-key-source case), while entries for other keys are added.
#[test]
fn update_preserves_set_map_entries() {
    let pk = test_key(1);
    let path_source: KeySource =
        (Fingerprint::default(), DerivationPath::from_str("m/84'/0'/0'").unwrap());

    let mut input_a = funded_input(1, 0);
    input_a.bip32_derivations.insert(pk, path_source.clone());

    let psbt = two_party_psbt(input_a, funded_input(2, 0));
    let updater = Updater::new(psbt.try_resolve().unwrap());

    let other_pk = test_key(2);
    let psbt = updater
        .update(|mut draft| {
            // BIP-375: an updater that does not want to reveal the fingerprint or derivation path sets
            // the value of the field to zero.
            draft.inputs[0].bip32_derivations.insert(pk, KeySource::default());
            draft.inputs[0].bip32_derivations.insert(other_pk, path_source.clone());
            draft
        })
        .unwrap()
        .psbt();

    // The key source already set in the PSBT is preserved; the draft cannot override it.
    assert_eq!(psbt.inputs[0].bip32_derivations.get(&pk), Some(&path_source));
    // The new derivation is added.
    assert_eq!(psbt.inputs[0].bip32_derivations.get(&other_pk), Some(&path_source));
}

/// A sighash type already set in the PSBT is preserved even when the draft carries a different one.
#[test]
fn update_preserves_existing_sighash_type() {
    let mut input_a = funded_input(1, 0);
    input_a.sighash_type = Some(PsbtSighashType::ALL);

    let psbt = two_party_psbt(input_a, funded_input(2, 0));
    let updater = Updater::new(psbt.try_resolve().unwrap());

    let psbt = updater
        .update(|mut draft| {
            // SIGHASH_NONE (0x02) differs from the pre-set SIGHASH_ALL.
            draft.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(0x02));
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.inputs[0].sighash_type, Some(PsbtSighashType::ALL));
}

/// The draft can add global xpubs and proprietary key-value pairs to the global, input, and
/// output maps.
#[test]
fn update_adds_global_xpubs_and_proprietaries() {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Bitcoin, &[3u8; 32]).unwrap();
    let xpub = Xpub::from_priv(&secp, &xpriv);
    let proprietary =
        ProprietaryKey { prefix: b"test".to_vec(), subtype: 0x01u64, key: vec![0xaa; 2] };

    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));
    let updater = Updater::new(psbt.try_resolve().unwrap());

    let psbt = updater
        .update(|mut draft| {
            draft.global.xpubs.insert(xpub, KeySource::default());
            draft.global.proprietaries.insert(proprietary.clone(), vec![0x42]);
            draft.inputs[0].proprietaries.insert(proprietary.clone(), vec![0x43]);
            draft.outputs[0].proprietaries.insert(proprietary.clone(), vec![0x44]);
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.global.xpubs.get(&xpub), Some(&KeySource::default()));
    assert_eq!(psbt.global.proprietaries.get(&proprietary), Some(&vec![0x42]));
    assert_eq!(psbt.inputs[0].proprietaries.get(&proprietary), Some(&vec![0x43]));
    assert_eq!(psbt.outputs[0].proprietaries.get(&proprietary), Some(&vec![0x44]));
}

/// A sequence change is rejected while any input carries signature data, including a change to a
/// different input: most sighash flags commit to every input's sequence.
#[test]
fn update_rejects_sequence_change_with_existing_signature() {
    use psbt_v2::bitcoin::ecdsa;
    use psbt_v2::bitcoin::sighash::EcdsaSighashType;

    let mut input_a = funded_input(1, 0);
    input_a.partial_sigs.insert(
        test_key(1),
        ecdsa::Signature {
            signature: psbt_v2::bitcoin::secp256k1::ecdsa::Signature::from_compact(&[1u8; 64])
                .unwrap(),
            sighash_type: EcdsaSighashType::All,
        },
    );

    let psbt = two_party_psbt(input_a, funded_input(2, 0));
    let updater = Updater::new(psbt.try_resolve().unwrap());

    // Changing the sequence of the signed input itself.
    let err = updater
        .clone()
        .update(|mut draft| {
            // The sequence is unset in the PSBT, so its effective value is Sequence::MAX
            // (BIP-370); changing it would invalidate the existing signature.
            draft.inputs[0].sequence = Some(Sequence::ZERO);
            draft
        })
        .unwrap_err();
    assert!(matches!(
        err,
        CombineError::SequenceMismatch { input: 0, this, that }
            if this == Sequence::MAX && that == Sequence::ZERO
    ));

    // Changing the sequence of another input: the signature on input 0 commits to it too.
    let err = updater
        .update(|mut draft| {
            draft.inputs[1].sequence = Some(Sequence::ZERO);
            draft
        })
        .unwrap_err();
    assert!(matches!(
        err,
        CombineError::SequenceMismatch { input: 1, this, that }
            if this == Sequence::MAX && that == Sequence::ZERO
    ));
}

/// A draft describing a different transaction shape is rejected.
#[test]
fn update_rejects_mismatched_draft_shape() {
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));
    let updater = Updater::new(psbt.try_resolve().unwrap());

    // Under-sized draft.
    let err = updater
        .clone()
        .update(|mut draft| {
            draft.inputs.pop();
            draft
        })
        .unwrap_err();
    assert!(matches!(err, CombineError::InputsLenMismatch { this: 2, that: 1 }));

    // Over-sized draft.
    let err = updater
        .clone()
        .update(|mut draft| {
            let extra = draft.inputs.last().unwrap().clone();
            draft.inputs.push(extra);
            draft
        })
        .unwrap_err();
    assert!(matches!(err, CombineError::InputsLenMismatch { this: 2, that: 3 }));

    // Under-sized outputs.
    let err = updater
        .clone()
        .update(|mut draft| {
            draft.outputs.pop();
            draft
        })
        .unwrap_err();
    assert!(matches!(err, CombineError::OutputsLenMismatch { this: 1, that: 0 }));

    // Over-sized outputs.
    let err = updater
        .update(|mut draft| {
            let extra = draft.outputs.last().unwrap().clone();
            draft.outputs.push(extra);
            draft
        })
        .unwrap_err();
    assert!(matches!(err, CombineError::OutputsLenMismatch { this: 1, that: 2 }));
}

/// `Updater::new` validates that lock time is determinable on entry.
#[test]
fn new_rejects_indeterminate_lock_time() {
    use psbt_v2::bitcoin::absolute;

    let mut psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));
    // Input 0 requires time-based lock time (min_time only).
    psbt.inputs[0].min_time = Some(absolute::Time::from_consensus(500_000_000).unwrap());
    psbt.inputs[0].min_height = None;
    // Input 1 requires height-based lock time (min_height only).
    psbt.inputs[1].min_height = Some(RequiredHeightLockTime::from_consensus(800_000).unwrap());
    psbt.inputs[1].min_time = None;

    let result = psbt.try_resolve();
    assert!(result.is_err());
}

/// `Updater::id` is stable across updates that change the sequence and across role re-entry.
#[test]
fn id_is_stable_across_updates() {
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let updater = Updater::new(psbt.try_resolve().unwrap());
    let id = updater.id();

    let updater = updater
        .update(|mut draft| {
            draft.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
            draft
        })
        .unwrap();
    assert_eq!(updater.id(), id);

    let psbt = updater.psbt();
    assert_eq!(Updater::new(psbt.try_resolve().unwrap()).id(), id);
}

/// Transitioning directly to the Signer role preserves the updates made through the draft.
#[test]
fn signer_preserves_updates() {
    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));

    let signer = Updater::new(psbt.try_resolve().unwrap())
        .update(|mut draft| {
            draft.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
            draft
        })
        .unwrap()
        .signer();

    assert_eq!(signer.as_psbt().inputs[0].sequence, Some(Sequence::ENABLE_LOCKTIME_NO_RBF));
}

/// The silent-payment output label is updatable (BIP-375 assigns it to the Updater for change
/// detection), while the output info is not.
#[test]
#[cfg(feature = "silent-payments")]
fn update_sets_sp_v0_label() {
    use psbt_v2::bitcoin::CompressedPublicKey;
    use psbt_v2::SpV0Info;

    let info = SpV0Info::new(
        CompressedPublicKey::try_from(test_key(5)).unwrap(),
        CompressedPublicKey::try_from(test_key(6)).unwrap(),
    );

    let mut psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));
    psbt.outputs[0].sp_v0_info = Some(info);

    let updater = Updater::new(psbt.try_resolve().unwrap());
    let psbt = updater
        .update(|mut draft| {
            draft.outputs[0].sp_v0_label = Some(7);
            draft
        })
        .unwrap()
        .psbt();

    assert_eq!(psbt.outputs[0].sp_v0_label, Some(7));
    // The output info is not an Updater field and cannot be changed through the draft.
    assert_eq!(psbt.outputs[0].sp_v0_info, Some(info));
}

/// A label may only be set on an output that has the silent-payment output info (BIP-375).
#[test]
#[cfg(feature = "silent-payments")]
fn update_rejects_sp_v0_label_without_info() {
    use psbt_v2::output;

    let psbt = two_party_psbt(funded_input(1, 0), funded_input(2, 0));
    let err = Updater::new(psbt.try_resolve().unwrap())
        .update(|mut draft| {
            draft.outputs[0].sp_v0_label = Some(7);
            draft
        })
        .unwrap_err();
    assert!(matches!(
        err,
        CombineError::Output(output::CombineError::OutputValidation(
            output::ValidationError::SpLabelWithoutInfo
        ))
    ));
}
