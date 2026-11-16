// SPDX-License-Identifier: CC0-1.0

//! End-to-end test: building an input from a descriptor plan and finalizing it.

#![cfg(all(feature = "std", feature = "miniscript"))]

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, KeySource};
use miniscript::plan::{CanSign, TaprootAvailableLeaves, TaprootCanSign};
use psbt_v2::bitcoin::bip32::{IntoDerivationPath, Xpriv, Xpub};
use psbt_v2::bitcoin::hashes::Hash as _;
use psbt_v2::bitcoin::secp256k1::Secp256k1;
use psbt_v2::bitcoin::{absolute, Amount, OutPoint, PublicKey, ScriptBuf, TxOut, Txid};
use psbt_v2::miniscript::descriptor::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey};
use psbt_v2::miniscript::plan::Assets;
use psbt_v2::{Creator, Finalizer, Input, Output, Psbt, Signer};

const TEST_XPRIV: &str =
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";

/// Signs `psbt` with the fixture key (`TEST_XPRIV`).
fn sign(psbt: Psbt) -> Psbt {
    let secp = Secp256k1::new();
    let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
    let mut signer = Signer::new(psbt.try_resolve().expect("test env, psbt should be well formed"));
    let sigs = signer.session(|mut session| {
        let inputs =
            session.assume_checked_inputs().expect("test env, inputs should be well formed");
        session.get_all(&inputs, &xpriv, &secp)
    });
    signer
        .apply(sigs)
        .expect("signature created in this same function, should be within bounds")
        .psbt()
}

#[test]
fn finalize_satisfies_time_lock_on_from_plan_input() {
    let secp = Secp256k1::new();
    let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
    let xpub = Xpub::from_priv(&secp, &xpriv);
    let time = absolute::Time::from_consensus(1_700_000_000).unwrap();

    // An input built from a plan carrying an absolute timelock: `from_plan` must
    // write everything the finalizer's satisfier needs, including a sequence
    // that enables the lock time.
    let descriptor = Descriptor::<DefiniteDescriptorKey>::from_str(&format!(
        "wsh(and_v(v:pk({}/0/0),after(1700000000)))",
        xpub
    ))
    .unwrap();
    let assets: Assets = descriptor.iter_pk().map(DescriptorPublicKey::from).collect();
    let assets = assets.after(absolute::LockTime::from(time));

    let mut input =
        Input::from_plan(&OutPoint::new(Txid::all_zeros(), 0), &descriptor.plan(&assets).unwrap());
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(123_456),
        script_pubkey: ScriptBuf::new_p2wsh(&input.witness_script.as_ref().unwrap().wscript_hash()),
    });

    let path = "m/0".into_derivation_path().unwrap();
    let pk =
        PublicKey::new(xpriv.derive_priv(&secp, &path).unwrap().to_keypair(&secp).public_key());
    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .expect("lock time must be determinable")
        .output(Output::new(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
        }))
        .expect("fixture output must be valid")
        .psbt();
    assert_eq!(psbt.determine_lock_time().unwrap(), absolute::LockTime::from(time));

    let v_secp = Secp256k1::verification_only();
    Finalizer::new(sign(psbt).try_resolve().unwrap())
        .unwrap()
        .finalize(&v_secp)
        .expect("from_plan must write the sequence an absolute timelock needs");
}

#[test]
fn finalize_satisfies_multi_a_on_from_plan_input() {
    let secp = Secp256k1::new();
    let xpriv = TEST_XPRIV.parse::<Xpriv>().unwrap();
    let xpub = Xpub::from_priv(&secp, &xpriv);

    // A plan spending the `multi_a` leaf: `from_plan` must record every signing
    // key's origin so the signer produces all threshold signatures.
    let descriptor = Descriptor::<DefiniteDescriptorKey>::from_str(&format!(
        "tr({}/0/0,multi_a(2,{}/0/1,{}/0/2))",
        xpub, xpub, xpub
    ))
    .unwrap();

    // Script-spend-only assets force the plan onto the `multi_a` leaf; the
    // internal key is not in the assets, so key spend is impossible.
    let script_spend_only = CanSign {
        ecdsa: false,
        taproot: TaprootCanSign {
            key_spend: false,
            script_spend: TaprootAvailableLeaves::Any,
            sighash_default: true,
        },
    };
    let mut assets = Assets::new();
    for path in ["m/0/1", "m/0/2"] {
        let source =
            KeySource::from((xpriv.fingerprint(&secp), DerivationPath::from_str(path).unwrap()));
        assets.keys.insert((source, script_spend_only.clone()));
    }

    let script_pubkey = descriptor.script_pubkey();
    let mut input =
        Input::from_plan(&OutPoint::new(Txid::all_zeros(), 0), &descriptor.plan(&assets).unwrap());
    input.witness_utxo = Some(TxOut { value: Amount::from_sat(123_456), script_pubkey });

    let path = "m/0".into_derivation_path().unwrap();
    let pk =
        PublicKey::new(xpriv.derive_priv(&secp, &path).unwrap().to_keypair(&secp).public_key());
    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .expect("lock time must be determinable")
        .output(Output::new(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
        }))
        .expect("fixture output must be valid")
        .psbt();

    let v_secp = Secp256k1::verification_only();
    Finalizer::new(sign(psbt).try_resolve().unwrap())
        .unwrap()
        .finalize(&v_secp)
        .expect("from_plan records every multi_a key so the signer completes the input");
}
