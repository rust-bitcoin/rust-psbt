//! Data driven test vector framework and utilities for BIP standard compliance testing.

#![cfg(all(feature = "std", feature = "base64", feature = "serde", feature = "miniscript"))]
// Intergration test code always appears dead to the compiler, more [information in the Rust Book.](https://doc.rust-lang.org/book/ch11-03-test-organization.html)
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use bitcoin::{Sequence, Transaction};
use psbt_v2::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use psbt_v2::bitcoin::consensus::encode::{deserialize, serialize_hex};
use psbt_v2::bitcoin::hex::FromHex;
use psbt_v2::bitcoin::secp256k1::Secp256k1;
use psbt_v2::bitcoin::{OutPoint, PrivateKey, PublicKey, ScriptBuf, TxOut};
use psbt_v2::psbt::{Constructor, Finalizer, Modifiable, Psbt, Signer};
use psbt_v2::{Extractor, Input, Output, PsbtSighashType};
use serde::{de, Deserialize, Deserializer};

pub mod util;

use util::{
    assert_invalid_v0, assert_invalid_v2, assert_valid_v0, assert_valid_v2, hex_psbt_v0,
    hex_psbt_v2,
};

#[derive(Debug, Deserialize)]
struct PubKeyPath {
    pub key: PublicKey,
    pub path: DerivationPath,
}

#[derive(Debug, Deserialize)]
struct PrivKeyPath {
    pub key: PrivateKey,
    pub path: DerivationPath,
}

fn deserialize_sighash<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<PsbtSighashType>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        None => Ok(None),
        Some(s) => s.parse::<PsbtSighashType>().map(Some).map_err(de::Error::custom),
    }
}

#[derive(Debug, Deserialize)]
struct TestFile {
    cases: Vec<TestCase>,
}

/// Holds the optional hex/base64 encodings of a PSBT.
#[derive(Debug, Deserialize, Default)]
struct PsbtData {
    hex: Option<String>,
    base64: Option<String>,
}

/// Per-input update data for the updater task.
///
/// Matched to a PSBT input by computing `txid(previous_tx)` and finding the
/// input whose `previous_output.txid` equals it.
#[derive(Debug, Deserialize)]
struct InputUpdate {
    /// Consensus-encoded hex of the funding transaction.
    #[serde(default)]
    previous_tx: String,
    /// If true, install the matched output as `witness_utxo`; otherwise
    /// install the whole transaction as `non_witness_utxo`.
    #[serde(default)]
    witness: bool,
    #[serde(default)]
    redeem_script: Option<ScriptBuf>,
    #[serde(default)]
    witness_script: Option<ScriptBuf>,
    #[serde(default)]
    bip32_derivation: Vec<PubKeyPath>,
}

/// Per-output update data for the updater task (positional).
#[derive(Debug, Deserialize, Default)]
struct OutputUpdate {
    #[serde(default)]
    bip32_derivation: Vec<PubKeyPath>,
}

/// Task-specific supplementary data, keyed by the `task` field in the JSON.
#[derive(Debug, Deserialize)]
#[serde(tag = "task", rename_all = "snake_case")]
enum Supplementary {
    FailDeserialize {
        #[serde(default)]
        psbts: Vec<PsbtData>,
    },
    FailSign {
        #[serde(default)]
        psbts: Vec<PsbtData>,
    },
    Deserialize {
        #[serde(default)]
        psbts: Vec<PsbtData>,
    },
    Create {
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
    },
    Update {
        #[serde(default)]
        psbts: Vec<PsbtData>,
        #[serde(default)]
        xpriv: Option<Xpriv>,
        #[serde(default)]
        input_updates: Vec<InputUpdate>,
        #[serde(default)]
        output_updates: Vec<OutputUpdate>,
        #[serde(default, deserialize_with = "deserialize_sighash")]
        sighash: Option<PsbtSighashType>,
    },
    Sign {
        #[serde(default)]
        psbts: Vec<PsbtData>,
        xpriv: Xpriv,
        #[serde(default)]
        seed: Option<PrivateKey>,
        #[serde(default)]
        private_keys: Vec<PrivKeyPath>,
    },
    Combine {
        #[serde(default)]
        psbts: Vec<PsbtData>,
    },
    Finalize {
        #[serde(default)]
        psbts: Vec<PsbtData>,
    },
    Extract {
        #[serde(default)]
        psbts: Vec<PsbtData>,
        tx: String,
    },
    DetermineLockTime {
        #[serde(default)]
        psbts: Vec<PsbtData>,
        expected_lock_time: u32,
    },
    FailDetermineLockTime {
        #[serde(default)]
        psbts: Vec<PsbtData>,
    },
}

#[derive(Debug, Deserialize)]
pub struct TestCase {
    #[serde(alias = "description")]
    pub description: String,
    #[serde(default)]
    version: u8,
    #[serde(default)]
    expected: PsbtData,
    supplementary: Supplementary,
}

impl TestCase {
    fn execute(&self) {
        match &self.supplementary {
            // FailDeserialize: the PSBT must be rejected during parsing.
            Supplementary::FailDeserialize { psbts } =>
                for PsbtData { hex, base64 } in psbts {
                    let base64 = base64.as_deref().expect("fail vector must have base64");
                    match self.version {
                        0 => {
                            let hex = hex.as_deref().expect("v0 fail vector must have hex");
                            assert_invalid_v0(hex, base64);
                        }
                        2 => {
                            assert_invalid_v2(hex.as_deref(), base64);
                        }
                        _ => panic!("unknown PSBT version: {}", self.version),
                    }
                },
            // FailSign: the PSBT must fail the signer validity checks.
            Supplementary::FailSign { psbts } => {
                for PsbtData { hex, base64 } in psbts {
                    let hex = hex.as_deref().expect("fail vector must have hex");
                    let base64 = base64.as_deref().expect("fail vector must have base64");
                    let hex_psbt = hex_psbt_v0(hex).expect("should parse");
                    let base64_psbt = Psbt::deserialize_v0_base64(base64)
                        .expect("base64 must decode when hex decoded");
                    assert_eq!(hex_psbt, base64_psbt);

                    // The BIP-174 signer validity checks run upfront in `sign` (before any
                    // signature is produced), so signing must fail even though we hold no keys.
                    let key_map: BTreeMap<PublicKey, PrivateKey> = BTreeMap::new();
                    let secp = Secp256k1::new();
                    let signer = Signer::new(base64_psbt).expect("lock time must be determinable");
                    assert!(signer.sign(&key_map, &secp).is_err(), "expected sign() to fail");
                }
            }
            // Deserialize: the PSBT must parse successfully.
            Supplementary::Deserialize { psbts } =>
                for PsbtData { hex, base64 } in psbts {
                    let base64 = base64.as_deref().expect("pass vector must have base64");
                    match self.version {
                        0 => {
                            let hex = hex.as_deref().expect("v0 pass vector must have hex");
                            assert_valid_v0(hex, base64);
                        }
                        2 => {
                            assert_valid_v2(hex.as_deref(), base64);
                        }
                        _ => panic!("unknown PSBT version: {}", self.version),
                    }
                },
            // Create: build a PSBT from the given inputs and outputs.
            Supplementary::Create { inputs, outputs } => {
                let expected_hex =
                    self.expected.hex.as_deref().expect("create expected must have hex");

                let mut psbt = Constructor::<Modifiable>::default();
                for prev_out in inputs {
                    let input = Input {
                        sequence: Some(Sequence::MAX),
                        ..Input::new(&OutPoint { txid: prev_out.txid, vout: prev_out.vout })
                    };
                    psbt = psbt.input(input);
                }
                for txout in outputs {
                    psbt = psbt
                        .output(Output::new(txout.clone()))
                        .expect("create task output must be valid");
                }
                let psbt = psbt.psbt().expect("lock time must be determinable");

                let expected_bytes =
                    Vec::from_hex(expected_hex).expect("expected PSBT must be valid hex");
                assert_eq!(psbt.serialize_v0_lossy().expect("v0 encoding"), expected_bytes);
            }
            // Update: apply UTXOs, scripts, BIP-32 derivations, and sighash.
            Supplementary::Update { psbts, xpriv, input_updates, output_updates, sighash } => {
                assert!(!psbts.is_empty(), "update task needs at least one input PSBT");
                let input_hex = psbts[0].hex.as_deref().expect("update input must have hex");
                let mut psbt = hex_psbt_v0(input_hex).expect("update input PSBT must be valid");

                let expected_hex =
                    self.expected.hex.as_deref().expect("update expected must have hex");
                let expected_psbt =
                    hex_psbt_v0(expected_hex).expect("update expected PSBT must be valid");

                let fp = xpriv.map(|xpriv| {
                    let secp = Secp256k1::new();
                    Xpub::from_priv(&secp, &xpriv).fingerprint()
                });

                for u in input_updates {
                    let prev_tx = consensus_tx(&u.previous_tx);
                    let txid = prev_tx.compute_txid();
                    let i = psbt
                        .inputs
                        .iter()
                        .position(|input| input.previous_txid == txid)
                        .expect("input_update previous_tx does not match any PSBT input");
                    let vout = psbt.inputs[i].spent_output_index as usize;
                    if u.witness {
                        psbt.inputs[i].witness_utxo = Some(prev_tx.output[vout].clone());
                    } else {
                        psbt.inputs[i].non_witness_utxo = Some(prev_tx);
                    }
                    if let Some(rs) = &u.redeem_script {
                        psbt.inputs[i].redeem_script = Some(rs.clone());
                    }
                    if let Some(ws) = &u.witness_script {
                        psbt.inputs[i].witness_script = Some(ws.clone());
                    }
                    if !u.bip32_derivation.is_empty() {
                        let fp = fp.expect("bip32_derivation requires xpriv");
                        psbt.inputs[i].bip32_derivations = u
                            .bip32_derivation
                            .iter()
                            .map(|p| (p.key, (fp, p.path.clone())))
                            .collect();
                    }
                }

                for (i, u) in output_updates.iter().enumerate() {
                    if !u.bip32_derivation.is_empty() {
                        let fp = fp.expect("bip32_derivation requires xpriv");
                        psbt.outputs[i].bip32_derivations = u
                            .bip32_derivation
                            .iter()
                            .map(|p| (p.key, (fp, p.path.clone())))
                            .collect();
                    }
                }

                if let Some(sighash) = *sighash {
                    for input in &mut psbt.inputs {
                        input.sighash_type = Some(sighash);
                    }
                }

                assert_eq!(psbt, expected_psbt);
            }
            // Sign: derive keys, sign the PSBT, compare against expected.
            Supplementary::Sign { psbts, xpriv, seed, private_keys } => {
                let secp = Secp256k1::new();
                let xpriv = *xpriv;

                if let Some(sk) = seed {
                    let seeded =
                        Xpriv::new_master(xpriv.network, &sk.inner.secret_bytes()).unwrap();
                    assert_eq!(seeded, xpriv);
                }

                assert!(!psbts.is_empty(), "sign task needs at least one input PSBT");
                let input_hex = psbts[0].hex.as_deref().expect("sign input must have hex");
                let psbt = hex_psbt_v0(input_hex).expect("sign input PSBT must be valid");

                let expected_hex =
                    self.expected.hex.as_deref().expect("sign expected must have hex");
                let expected_psbt =
                    hex_psbt_v0(expected_hex).expect("sign expected PSBT must be valid");

                let mut key_map: BTreeMap<PublicKey, PrivateKey> = BTreeMap::new();

                for PrivKeyPath { key: wif_priv, path } in private_keys {
                    let derived =
                        xpriv.derive_priv(&secp, path).expect("derivation must succeed").to_priv();
                    assert_eq!(
                        *wif_priv, derived,
                        "WIF key in vector must match derivation from canonical xpriv"
                    );
                    key_map.insert(wif_priv.public_key(&secp), *wif_priv);
                }

                let signer = Signer::new(psbt).expect("lock time must be determinable");
                let (psbt, _) = match signer.sign(&key_map, &secp) {
                    Ok(signed) => signed,
                    Err((_, errors)) => panic!("unexpected sign errors: {:?}", errors),
                };
                assert_eq!(psbt, expected_psbt);
            }
            // Combine: merge multiple PSBTs into one.
            Supplementary::Combine { psbts } => {
                assert!(psbts.len() >= 2, "combine task needs at least two input PSBTs");

                let expected_hex =
                    self.expected.hex.as_deref().expect("combine expected must have hex");
                let expected_psbt =
                    hex_psbt_v0(expected_hex).expect("combine expected PSBT must be valid");

                let mut combined =
                    hex_psbt_v0(psbts[0].hex.as_deref().expect("combine input[0] must have hex"))
                        .expect("combine input[0] must be valid");

                for p in &psbts[1..] {
                    let next = hex_psbt_v0(p.hex.as_deref().expect("combine input must have hex"))
                        .expect("combine input must be valid");
                    combined = combined.combine_with(next).expect("combine must succeed");
                }

                assert_eq!(combined, expected_psbt);
            }
            // Finalize: apply final scripts and witnesses.
            Supplementary::Finalize { psbts } => {
                assert!(!psbts.is_empty(), "finalize task needs at least one input PSBT");

                let input_hex = psbts[0].hex.as_deref().expect("finalize input must have hex");
                let psbt = hex_psbt_v0(input_hex).expect("finalize input PSBT must be valid");

                let expected_hex =
                    self.expected.hex.as_deref().expect("finalize expected must have hex");
                let expected_psbt =
                    hex_psbt_v0(expected_hex).expect("finalize expected PSBT must be valid");

                let secp = Secp256k1::verification_only();
                let finalizer = Finalizer::new(psbt).expect("finalizer requirements must be met");
                let psbt = finalizer.finalize(&secp).expect("input psbt must be finalizable");

                assert_eq!(psbt, expected_psbt);
            }
            // Extract: extract the final transaction from a finalized PSBT.
            Supplementary::Extract { psbts, tx: expected_tx_hex } => {
                assert!(!psbts.is_empty(), "extract task needs at least one input PSBT");

                let input_hex = psbts[0].hex.as_deref().expect("extract input must have hex");
                let psbt = hex_psbt_v0(input_hex).expect("extract input PSBT must be valid");

                let extractor = Extractor::new(psbt).expect("extract task PSBT must be finalized");
                let tx = extractor.extract_tx_unchecked_fee_rate().expect("extract must succeed");
                assert_eq!(serialize_hex(&tx), expected_tx_hex.as_str());
            }
            // DetermineLockTime: compute the lock time from the PSBT.
            Supplementary::DetermineLockTime { psbts, expected_lock_time } => {
                let expected_lock_time = *expected_lock_time;
                for PsbtData { hex, base64 } in psbts {
                    let hex = hex.as_deref().expect("determine_lock_time vector must have hex");
                    let base64 =
                        base64.as_deref().expect("determine_lock_time vector must have base64");

                    let psbt = hex_psbt_v2(hex).expect("failed to deserialize PSBT from hex");
                    assert_eq!(
                        psbt,
                        base64
                            .parse::<psbt_v2::psbt::Psbt>()
                            .expect("failed to deserialize from base64")
                    );

                    let got = psbt.determine_lock_time().expect("valid lock time");
                    let want = bitcoin::absolute::LockTime::from_consensus(expected_lock_time);
                    assert_eq!(got, want);
                }
            }
            // FailDetermineLockTime: lock time determination must fail.
            Supplementary::FailDetermineLockTime { psbts } => {
                for PsbtData { hex, base64 } in psbts {
                    let hex =
                        hex.as_deref().expect("fail_determine_lock_time vector must have hex");
                    let base64 = base64
                        .as_deref()
                        .expect("fail_determine_lock_time vector must have base64");

                    let psbt = hex_psbt_v2(hex).expect("failed to deserialize PSBT from hex");
                    assert_eq!(
                        psbt,
                        base64
                            .parse::<psbt_v2::psbt::Psbt>()
                            .expect("failed to deserialize from base64")
                    );

                    assert!(
                        psbt.determine_lock_time().is_err(),
                        "expected determine_lock_time to fail"
                    );
                }
            }
        }
    }
}

/// Decode a consensus-encoded transaction from a hex string.
fn consensus_tx(hex: &str) -> Transaction {
    let bytes = Vec::from_hex(hex).expect("previous_tx must be valid hex");
    deserialize::<Transaction>(&bytes).expect("previous_tx must be a valid transaction")
}

macro_rules! make_check_case {
    ($spec:ident) => {
        pub fn $spec(desc: &str) {
            static CASES: OnceLock<Vec<TestCase>> = OnceLock::new();
            let cases = CASES.get_or_init(|| {
                serde_json::from_str::<TestFile>(include_str!(concat!(
                    "../data/",
                    stringify!($spec),
                    ".json"
                )))
                .expect("failed to deserialize test vectors")
                .cases
            });
            let case = cases.iter().find(|c| c.description == desc).unwrap_or_else(|| {
                panic!("case not found in {} vectors: \"{desc}\"", stringify!($spec))
            });
            case.execute();
        }
    };
}

make_check_case!(bip174);
make_check_case!(bip370);
make_check_case!(bip371);
make_check_case!(bip375);
