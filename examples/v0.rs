//! PSBT v0 codec example.
//!
//! The v2 PSBT format (BIP-370) is the primary interface of this crate. PSBT v0 (BIP-174)
//! PSBTs are supported via explicit decode/encode entry points.
//!
//! This example demonstrates the multi-party flow where the wire format stays v0 throughout:
//! receive a v0 PSBT, work with it through the v2 interface, and hand back a v0 PSBT. It uses
//! the BIP-174 workflow vectors, so the updated PSBT is compared against the expected output
//! of a real BIP-174 update step.

use psbt_v2::bitcoin::bip32::{DerivationPath, Fingerprint};
use psbt_v2::bitcoin::consensus::encode::deserialize;
use psbt_v2::bitcoin::hex::FromHex;
use psbt_v2::bitcoin::{PublicKey, ScriptBuf, Transaction};
use psbt_v2::Psbt;

/// BIP-174 workflow A, step 1 (create): an unsigned PSBT with two inputs and two outputs, as
/// a participant might receive from a coordinator that only supports v0.
const RECEIVED_V0_HEX: &str = "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000";

/// BIP-174 workflow A, step 2 (update): the same PSBT after the Updater adds the UTXOs,
/// scripts, and derivation paths. This is the expected output of the update below.
const EXPECTED_UPDATED_V0_HEX: &str = "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88701042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000";

/// BIP-174 workflow A, step 2 update for input 0: the previous transaction funding input 0.
/// Input 0 is a legacy spend, so the full transaction is provided as the non-witness UTXO.
const INPUT_0_PREV_TX_HEX: &str = "0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000";

/// The 2-of-2 multisig redeem script for input 0.
const INPUT_0_REDEEM_SCRIPT_HEX: &str = "5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae";

/// BIP-174 workflow A, step 2 update for input 1: the previous transaction funding input 1.
/// Input 1 is a segwit spend, so only the spent output is used as the witness UTXO.
const INPUT_1_PREV_TX_HEX: &str = "0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f7965000000";

/// The P2WSH scriptPubKey (redeem script) for input 1.
const INPUT_1_REDEEM_SCRIPT_HEX: &str =
    "00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903";

/// The 2-of-2 multisig witness script for input 1.
const INPUT_1_WITNESS_SCRIPT_HEX: &str = "522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae";

fn main() -> anyhow::Result<()> {
    // Receive a v0 PSBT (e.g., from a coordinator that only speaks BIP-174).
    let received_bytes = Vec::from_hex(RECEIVED_V0_HEX)?;
    println!("received v0 PSBT ({} bytes)\n", received_bytes.len());

    // Decode it into the v2 interface. From here on, everything uses the v2 API.
    let mut psbt = Psbt::deserialize_v0(&received_bytes)?;
    println!(
        "decoded into the v2 interface: {} inputs, {} outputs\n",
        psbt.inputs.len(),
        psbt.outputs.len()
    );

    // Update it (the BIP-174 workflow A step 2): add funding UTXOs, scripts, and derivation
    // paths to each input. The values are the vector's update data.
    let fingerprint = Fingerprint::from_hex("d90c6a4f")?;

    // Input 0: legacy (non-witness) funding.
    let prev_tx_0: Transaction = deserialize(&Vec::from_hex(INPUT_0_PREV_TX_HEX)?)?;
    psbt.inputs[0].non_witness_utxo = Some(prev_tx_0);
    psbt.inputs[0].redeem_script = Some(ScriptBuf::from_hex(INPUT_0_REDEEM_SCRIPT_HEX)?);
    add_derivation(
        &mut psbt.inputs[0].bip32_derivations,
        fingerprint,
        &[
            ("029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f", "m/0'/0'/0'"),
            ("02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7", "m/0'/0'/1'"),
        ],
    )?;

    // Input 1: segwit (witness) funding.
    let prev_tx_1: Transaction = deserialize(&Vec::from_hex(INPUT_1_PREV_TX_HEX)?)?;
    psbt.inputs[1].witness_utxo =
        Some(prev_tx_1.output[psbt.inputs[1].spent_output_index as usize].clone());
    psbt.inputs[1].redeem_script = Some(ScriptBuf::from_hex(INPUT_1_REDEEM_SCRIPT_HEX)?);
    psbt.inputs[1].witness_script = Some(ScriptBuf::from_hex(INPUT_1_WITNESS_SCRIPT_HEX)?);
    add_derivation(
        &mut psbt.inputs[1].bip32_derivations,
        fingerprint,
        &[
            ("03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc", "m/0'/0'/2'"),
            ("023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73", "m/0'/0'/3'"),
        ],
    )?;

    // Output 0 and 1: derivation paths for the change/receive keys.
    add_derivation(
        &mut psbt.outputs[0].bip32_derivations,
        fingerprint,
        &[("03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771", "m/0'/0'/4'")],
    )?;
    add_derivation(
        &mut psbt.outputs[1].bip32_derivations,
        fingerprint,
        &[("027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096", "m/0'/0'/5'")],
    )?;

    let updated_bytes = psbt.into_psbt_v0()?.serialize();
    let expected_bytes = Vec::from_hex(EXPECTED_UPDATED_V0_HEX)?;
    assert_eq!(updated_bytes, expected_bytes, "v2 update must match the BIP-174 step 2 output");
    println!("updated with the v2 roles and re-encoded as v0: matches BIP-174 step 2 vector");

    Ok(())
}

fn add_derivation(
    map: &mut std::collections::BTreeMap<PublicKey, (Fingerprint, DerivationPath)>,
    fingerprint: Fingerprint,
    paths: &[(&str, &str)],
) -> anyhow::Result<()> {
    for (key, path) in paths {
        let pubkey = PublicKey::from_slice(&Vec::from_hex(key)?)?;
        let path = path.parse::<DerivationPath>()?;
        map.insert(pubkey, (fingerprint, path));
    }
    Ok(())
}
