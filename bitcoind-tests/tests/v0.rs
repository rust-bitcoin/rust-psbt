// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 (BIP-174) integration tests against a running `bitcoind` instance.
//!
//! Each test exercises a specific transaction type through the v0 codec. The PSBT is built with
//! the v2 API and serialized as v0. `decodepsbt` verifies Core can parse the PSBT envelope, and
//! `sendrawtransaction` verifies Core accepts the extracted tx.

use bitcoind_tests::client::Client;
use psbt::bitcoin::bip32::{IntoDerivationPath, Xpriv, Xpub};
use psbt::bitcoin::secp256k1::Secp256k1;
use psbt::bitcoin::{Address, Amount, OutPoint, ScriptBuf, TxOut};
use psbt::psbt::{Creator, Finalizer, Signer};
use psbt::{Extractor, InputBuilder, OutputBuilder};
use psbt_v2 as psbt;

const TEST_XPRIV: &str =
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const TEST_XPUB: &str =
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

/// A single P2WPKH input spending to a P2WPKH output and a change output.
#[test]
fn p2wpkh() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new()?;
    client.mine_a_block()?;

    // Generate key material.
    let xpriv: Xpriv = TEST_XPRIV.parse()?;
    let xpub: Xpub = TEST_XPUB.parse()?;
    let fingerprint = xpub.fingerprint();
    let path = "m/0".into_derivation_path()?;
    let secp = Secp256k1::new();

    let (cpk, address) = {
        let derived = xpriv.derive_priv(&secp, &path)?;
        let xpub = Xpub::from_priv(&secp, &derived);
        let cpk = xpub.to_pub();
        (cpk, Address::p2wpkh(&cpk, Client::NETWORK))
    };

    // Fund the test address.
    let txid = client.send(Client::ONE_BTC, &address)?;
    client.mine_a_block()?;
    client.assert_balance_is_as_expected()?;

    // Fetch the funded UTXO.
    let tx = client.get_transaction(&txid)?;
    let spk = address.script_pubkey();
    let utxos: Vec<_> =
        tx.output.iter().zip(0u32..).filter(|(out, _)| out.script_pubkey == spk).collect();
    assert_eq!(utxos.len(), 1);
    let (fund, vout) = utxos[0];
    let out_point = OutPoint { txid, vout };

    // Build the PSBT.
    let receiver = client.wallet_address()?;
    let spend_amount = Amount::from_sat(50_000_000);
    let change_amount = fund.value - spend_amount - Client::FEE;

    let spend_output = TxOut { value: spend_amount, script_pubkey: receiver.script_pubkey() };
    let change_output = TxOut { value: change_amount, script_pubkey: address.script_pubkey() };

    let mut input = InputBuilder::new(&out_point).segwit_fund(fund.clone()).build();
    input.bip32_derivations.insert(cpk.into(), (fingerprint, path.clone()));
    input.sequence = Some(psbt::bitcoin::Sequence::MAX);

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(OutputBuilder::new(spend_output).build())?
        .output(OutputBuilder::new(change_output).build())?
        .psbt()?;

    // Sign and finalize the PSBT.
    let (signed, _) = Signer::new(psbt)?.sign(&xpriv, &secp).unwrap();
    let finalized = Finalizer::new(signed)?.finalize(&secp)?;

    // Ask Bitcoin Core to decode the PSBT, proving it can parse the v0 envelope.
    let b64 = finalized.serialize_v0_base64_lossy()?;
    client.decode_psbt(&b64)?;

    // Broadcast the extracted transaction.
    let tx = Extractor::new(finalized)?.extract_tx_unchecked_fee_rate()?;
    client.send_raw_transaction(&tx)?;
    client.mine_a_block()?;
    client.track_receive(spend_amount);
    client.assert_balance_is_as_expected()?;

    Ok(())
}

/// A single P2PKH (legacy) input spending to a P2WPKH output and a change output.
///
/// Exercises the legacy (non-segwit) funding path: `InputBuilder::legacy_fund` and
/// `Address::p2pkh`. The PSBT carries a full `non_witness_utxo` instead of a `witness_utxo`.
#[test]
fn p2pkh() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new()?;
    client.mine_a_block()?;

    // Generate key material.
    let xpriv: Xpriv = TEST_XPRIV.parse()?;
    let xpub: Xpub = TEST_XPUB.parse()?;
    let fingerprint = xpub.fingerprint();
    let path = "m/0".into_derivation_path()?;
    let secp = Secp256k1::new();

    let (cpk, address) = {
        let derived = xpriv.derive_priv(&secp, &path)?;
        let xpub = Xpub::from_priv(&secp, &derived);
        let cpk = xpub.to_pub();
        (cpk, Address::p2pkh(cpk, Client::NETWORK))
    };

    // Fund the test address.
    let txid = client.send(Client::ONE_BTC, &address)?;
    client.mine_a_block()?;
    client.assert_balance_is_as_expected()?;

    // Fetch the funded UTXO and the full funding transaction for legacy spend.
    let tx = client.get_transaction(&txid)?;
    let spk = address.script_pubkey();
    let utxos: Vec<_> =
        tx.output.iter().zip(0u32..).filter(|(out, _)| out.script_pubkey == spk).collect();
    assert_eq!(utxos.len(), 1);
    let (fund, vout) = utxos[0];
    let out_point = OutPoint { txid, vout };

    // Build the PSBT.
    let receiver = client.wallet_address()?;
    let spend_amount = Amount::from_sat(50_000_000);
    let change_amount = fund.value - spend_amount - Client::FEE;

    let spend_output = TxOut { value: spend_amount, script_pubkey: receiver.script_pubkey() };
    let change_output = TxOut { value: change_amount, script_pubkey: address.script_pubkey() };

    let mut input = InputBuilder::new(&out_point).legacy_fund(tx).build();
    input.bip32_derivations.insert(cpk.into(), (fingerprint, path.clone()));
    input.sequence = Some(psbt::bitcoin::Sequence::MAX);

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(OutputBuilder::new(spend_output).build())?
        .output(OutputBuilder::new(change_output).build())?
        .psbt()?;

    // Sign and finalize the PSBT.
    let (signed, _) = Signer::new(psbt)?.sign(&xpriv, &secp).unwrap();
    let finalized = Finalizer::new(signed)?.finalize(&secp)?;

    // Ask Bitcoin Core to decode the PSBT, proving it can parse the v0 envelope.
    let b64 = finalized.serialize_v0_base64_lossy()?;
    client.decode_psbt(&b64)?;

    // Broadcast the extracted transaction.
    let tx = Extractor::new(finalized)?.extract_tx_unchecked_fee_rate()?;
    client.send_raw_transaction(&tx)?;
    client.mine_a_block()?;
    client.track_receive(spend_amount);
    client.assert_balance_is_as_expected()?;

    Ok(())
}

/// Two P2WPKH inputs from distinct derivation paths, spent in a single transaction.
///
/// Exercises multi-input signing where each input has a different BIP-32 derivation path,
/// both derived from the same master key. The `Signer` resolves each input's key independently.
#[test]
fn multiple_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new()?;
    client.mine_a_block()?;

    // Generate key material.
    let xpriv: Xpriv = TEST_XPRIV.parse()?;
    let xpub: Xpub = TEST_XPUB.parse()?;
    let fingerprint = xpub.fingerprint();
    let path0 = "m/0".into_derivation_path()?;
    let path1 = "m/1".into_derivation_path()?;
    let secp = Secp256k1::new();

    let (cpk0, address0) = {
        let derived = xpriv.derive_priv(&secp, &path0)?;
        let xpub = Xpub::from_priv(&secp, &derived);
        let cpk = xpub.to_pub();
        (cpk, Address::p2wpkh(&cpk, Client::NETWORK))
    };
    let (cpk1, address1) = {
        let derived = xpriv.derive_priv(&secp, &path1)?;
        let xpub = Xpub::from_priv(&secp, &derived);
        let cpk = xpub.to_pub();
        (cpk, Address::p2wpkh(&cpk, Client::NETWORK))
    };

    // Fund both addresses.
    let txid0 = client.send(Client::ONE_BTC, &address0)?;
    let txid1 = client.send(Client::ONE_BTC, &address1)?;
    client.mine_a_block()?;
    client.assert_balance_is_as_expected()?;

    // Fetch the first UTXO.
    let tx0 = client.get_transaction(&txid0)?;
    let spk0 = address0.script_pubkey();
    let utxos0: Vec<_> =
        tx0.output.iter().zip(0u32..).filter(|(out, _)| out.script_pubkey == spk0).collect();
    assert_eq!(utxos0.len(), 1);
    let (fund0, vout0) = utxos0[0];
    let out_point0 = OutPoint { txid: txid0, vout: vout0 };

    // Fetch the second UTXO.
    let tx1 = client.get_transaction(&txid1)?;
    let spk1 = address1.script_pubkey();
    let utxos1: Vec<_> =
        tx1.output.iter().zip(0u32..).filter(|(out, _)| out.script_pubkey == spk1).collect();
    assert_eq!(utxos1.len(), 1);
    let (fund1, vout1) = utxos1[0];
    let out_point1 = OutPoint { txid: txid1, vout: vout1 };

    // Build the PSBT.
    let receiver = client.wallet_address()?;
    let total_input = fund0.value + fund1.value;
    let spend_amount = Amount::from_sat(150_000_000);
    let change_amount = total_input - spend_amount - Client::FEE;

    let spend_output = TxOut { value: spend_amount, script_pubkey: receiver.script_pubkey() };
    let change_output = TxOut { value: change_amount, script_pubkey: address0.script_pubkey() };

    let mut input0 = InputBuilder::new(&out_point0).segwit_fund(fund0.clone()).build();
    input0.bip32_derivations.insert(cpk0.into(), (fingerprint, path0.clone()));
    input0.sequence = Some(psbt::bitcoin::Sequence::MAX);

    let mut input1 = InputBuilder::new(&out_point1).segwit_fund(fund1.clone()).build();
    input1.bip32_derivations.insert(cpk1.into(), (fingerprint, path1.clone()));
    input1.sequence = Some(psbt::bitcoin::Sequence::MAX);

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input0)
        .input(input1)
        .output(OutputBuilder::new(spend_output).build())?
        .output(OutputBuilder::new(change_output).build())?
        .psbt()?;

    // Sign and finalize the PSBT.
    let (signed, _) = Signer::new(psbt)?.sign(&xpriv, &secp).unwrap();
    let finalized = Finalizer::new(signed)?.finalize(&secp)?;

    // Ask Bitcoin Core to decode the PSBT, proving it can parse the v0 envelope.
    let b64 = finalized.serialize_v0_base64_lossy()?;
    client.decode_psbt(&b64)?;

    // Broadcast the extracted transaction.
    let tx = Extractor::new(finalized)?.extract_tx_unchecked_fee_rate()?;
    client.send_raw_transaction(&tx)?;
    client.mine_a_block()?;
    client.track_receive(spend_amount);
    client.assert_balance_is_as_expected()?;

    Ok(())
}

/// A single P2SH-P2WPKH (wrapped segwit) input spending to a P2WPKH output and a change output.
///
/// Exercises the nested/wrapped segwit path. The UTXO sits at a P2SH address that wraps a
/// P2WPKH redeem script. The PSBT carries a `witness_utxo` and the finalizer produces both
/// a scriptSig (pushing the redeem script) and a witness.
#[test]
fn p2sh_p2wpkh() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new()?;
    client.mine_a_block()?;

    // Generate key material.
    let xpriv: Xpriv = TEST_XPRIV.parse()?;
    let xpub: Xpub = TEST_XPUB.parse()?;
    let fingerprint = xpub.fingerprint();
    let path = "m/0".into_derivation_path()?;
    let secp = Secp256k1::new();

    let (cpk, address) = {
        let derived = xpriv.derive_priv(&secp, &path)?;
        let xpub = Xpub::from_priv(&secp, &derived);
        let cpk = xpub.to_pub();
        (cpk, Address::p2shwpkh(&cpk, Client::NETWORK))
    };

    // Fund the test address.
    let txid = client.send(Client::ONE_BTC, &address)?;
    client.mine_a_block()?;
    client.assert_balance_is_as_expected()?;

    // Fetch the funded UTXO.
    let tx = client.get_transaction(&txid)?;
    let spk = address.script_pubkey();
    let utxos: Vec<_> =
        tx.output.iter().zip(0u32..).filter(|(out, _)| out.script_pubkey == spk).collect();
    assert_eq!(utxos.len(), 1);
    let (fund, vout) = utxos[0];
    let out_point = OutPoint { txid, vout };

    // Build the PSBT.
    let receiver = client.wallet_address()?;
    let spend_amount = Amount::from_sat(50_000_000);
    let change_amount = fund.value - spend_amount - Client::FEE;

    let spend_output = TxOut { value: spend_amount, script_pubkey: receiver.script_pubkey() };
    let change_output = TxOut { value: change_amount, script_pubkey: address.script_pubkey() };

    let mut input = InputBuilder::new(&out_point).segwit_fund(fund.clone()).build();
    input.redeem_script =
        Some(ScriptBuf::new_p2wpkh(&cpk.wpubkey_hash()));
    input.bip32_derivations.insert(cpk.into(), (fingerprint, path.clone()));
    input.sequence = Some(psbt::bitcoin::Sequence::MAX);

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(OutputBuilder::new(spend_output).build())?
        .output(OutputBuilder::new(change_output).build())?
        .psbt()?;

    // Sign and finalize the PSBT.
    let (signed, _) = Signer::new(psbt)?.sign(&xpriv, &secp).unwrap();
    let finalized = Finalizer::new(signed)?.finalize(&secp)?;

    // Ask Bitcoin Core to decode the PSBT, proving it can parse the v0 envelope.
    let b64 = finalized.serialize_v0_base64_lossy()?;
    client.decode_psbt(&b64)?;

    // Broadcast the extracted transaction.
    let tx = Extractor::new(finalized)?.extract_tx_unchecked_fee_rate()?;
    client.send_raw_transaction(&tx)?;
    client.mine_a_block()?;
    client.track_receive(spend_amount);
    client.assert_balance_is_as_expected()?;

    Ok(())
}

/// A single P2WPKH input with no change output.
///
/// Exercises the single-output PSBT path. When `input == output + fee` exactly, there is no
/// change to return.
#[test]
fn no_change() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new()?;
    client.mine_a_block()?;

    // Generate key material.
    let xpriv: Xpriv = TEST_XPRIV.parse()?;
    let xpub: Xpub = TEST_XPUB.parse()?;
    let fingerprint = xpub.fingerprint();
    let path = "m/0".into_derivation_path()?;
    let secp = Secp256k1::new();

    let (cpk, address) = {
        let derived = xpriv.derive_priv(&secp, &path)?;
        let xpub = Xpub::from_priv(&secp, &derived);
        let cpk = xpub.to_pub();
        (cpk, Address::p2wpkh(&cpk, Client::NETWORK))
    };

    // Fund the test address.
    let txid = client.send(Client::ONE_BTC, &address)?;
    client.mine_a_block()?;
    client.assert_balance_is_as_expected()?;

    // Fetch the funded UTXO.
    let tx = client.get_transaction(&txid)?;
    let spk = address.script_pubkey();
    let utxos: Vec<_> =
        tx.output.iter().zip(0u32..).filter(|(out, _)| out.script_pubkey == spk).collect();
    assert_eq!(utxos.len(), 1);
    let (fund, vout) = utxos[0];
    let out_point = OutPoint { txid, vout };

    // Spend the entire UTXO minus the fee — no change output needed.
    let receiver = client.wallet_address()?;
    let spend_amount = fund.value - Client::FEE;

    let spend_output = TxOut { value: spend_amount, script_pubkey: receiver.script_pubkey() };

    let mut input = InputBuilder::new(&out_point).segwit_fund(fund.clone()).build();
    input.bip32_derivations.insert(cpk.into(), (fingerprint, path.clone()));
    input.sequence = Some(psbt::bitcoin::Sequence::MAX);

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(OutputBuilder::new(spend_output).build())?
        .psbt()?;

    // Sign and finalize the PSBT.
    let (signed, _) = Signer::new(psbt)?.sign(&xpriv, &secp).unwrap();
    let finalized = Finalizer::new(signed)?.finalize(&secp)?;

    // Ask Bitcoin Core to decode the PSBT, proving it can parse the v0 envelope.
    let b64 = finalized.serialize_v0_base64_lossy()?;
    client.decode_psbt(&b64)?;

    // Broadcast the extracted transaction.
    let tx = Extractor::new(finalized)?.extract_tx_unchecked_fee_rate()?;
    client.send_raw_transaction(&tx)?;
    client.mine_a_block()?;
    client.track_receive(spend_amount);
    client.assert_balance_is_as_expected()?;

    Ok(())
}
