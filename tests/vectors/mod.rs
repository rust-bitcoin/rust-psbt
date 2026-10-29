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
use psbt_v2::{
    Constructor, Extractor, Finalizer, Input, Modifiable, Output, PsbtSighashType, PsbtV0, Signer,
    Version,
};
use serde::{de, Deserialize, Deserializer};

pub mod util;

use util::{
    assert_invalid_v0, assert_invalid_v2, assert_valid_v0, assert_valid_v2, base64_psbt_v0,
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

/// Serde helper which parses an optional sighash type from its symbolic name
/// (e.g. `"SIGHASH_ALL"`), used by the `Update` variant's `sighash` field.
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

/// Holds the base64 encoding of a PSBT.
#[derive(Debug, Deserialize)]
struct PsbtData {
    base64: String,
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

/// Task payload, keyed by the operation name (e.g. `deserialize`, `create`).
///
/// The JSON represents this as an object with a single key whose name is the
/// task type; the value under that key holds the task-specific data.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Task {
    FailDeserialize {
        psbt: PsbtData,
    },
    FailSign {
        psbt: PsbtData,
    },
    FailStrictSign {
        psbt: PsbtData,
    },
    Deserialize {
        psbt: PsbtData,
    },
    Create {
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
        expected: PsbtData,
    },
    Update {
        psbt: PsbtData,
        #[serde(default)]
        xpriv: Option<Xpriv>,
        #[serde(default)]
        input_updates: Vec<InputUpdate>,
        #[serde(default)]
        output_updates: Vec<OutputUpdate>,
        #[serde(default, deserialize_with = "deserialize_sighash")]
        sighash: Option<PsbtSighashType>,
        expected: PsbtData,
    },
    StrictSign {
        psbt: PsbtData,
        xpriv: Xpriv,
        #[serde(default)]
        seed: Option<PrivateKey>,
        #[serde(default)]
        private_keys: Vec<PrivKeyPath>,
        expected: PsbtData,
    },
    TrustedSign {
        psbt: PsbtData,
        xpriv: Xpriv,
        #[serde(default)]
        seed: Option<PrivateKey>,
        #[serde(default)]
        private_keys: Vec<PrivKeyPath>,
        expected: PsbtData,
    },
    Combine {
        #[serde(default)]
        psbts: Vec<PsbtData>,
        expected: PsbtData,
    },
    Finalize {
        psbt: PsbtData,
        expected: PsbtData,
    },
    Extract {
        psbt: PsbtData,
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
    version: Version,
    task: Task,
}

impl TestCase {
    fn execute(&self) {
        match &self.task {
            // FailDeserialize: the PSBT must be rejected during parsing.
            Task::FailDeserialize { psbt } => match self.version {
                Version::ZERO => assert_invalid_v0(&psbt.base64),
                Version::TWO => assert_invalid_v2(&psbt.base64),
                _ => panic!("unknown PSBT version: {}", self.version.to_u32()),
            },
            // FailSign: the PSBT must fail the signer validity checks.
            Task::FailSign { psbt } => {
                let psbt =
                    base64_psbt_v0(&psbt.base64).expect("fail sign vector must be valid base64");

                // The BIP-174 signer validity checks run upfront in `sign` (before any
                // signature is produced), so signing must fail even though we hold no keys.
                let inputs_len = psbt.inputs.len();
                let mut signer = Signer::new(psbt).expect("lock time must be determinable");
                let any_err = signer.session(|session| {
                    (0..inputs_len).map(|x| session.signable_input(x)).any(|x| x.is_err())
                });
                assert!(any_err, "expected sign() to fail");
            }
            Task::FailStrictSign { psbt } => {
                let psbt = base64_psbt_v0(&psbt.base64)
                    .expect("fail strict sign vector must be valid base64");

                let input_len = psbt.inputs.len();

                // The BIP-174 strict signer validity checks verify non-P2TR inputs provide the
                // full tx prevout.
                // Under strict signing, inputs with missing full tx prevout must fail while
                // getting the signable inputs.
                let mut signer = Signer::new(psbt).expect("lock time must be determinable");
                let any_err = signer.session(|session| {
                    (0..input_len).any(|idx| session.signable_input(idx).is_err())
                });
                assert!(any_err, "expected signable_input() to fail");
            }
            // Deserialize: the PSBT must parse successfully.
            Task::Deserialize { psbt } => match self.version {
                Version::ZERO => assert_valid_v0(&psbt.base64),
                Version::TWO => assert_valid_v2(&psbt.base64),
                _ => panic!("unknown PSBT version: {}", self.version.to_u32()),
            },
            // Create: build a PSBT from the given inputs and outputs.
            Task::Create { inputs, outputs, expected } => {
                let expected_v0 = PsbtV0::deserialize_base64(&expected.base64)
                    .expect("create expected PSBT must be valid base64");

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

                assert_eq!(
                    PsbtV0::from_psbt(psbt)
                        .expect("BIP-174 test vector PSBT must have resolvable lock time")
                        .serialize(),
                    expected_v0.serialize()
                );
            }
            // Update: apply UTXOs, scripts, BIP-32 derivations, and sighash.
            Task::Update { psbt, xpriv, input_updates, output_updates, sighash, expected } => {
                let mut psbt =
                    base64_psbt_v0(&psbt.base64).expect("update input PSBT must be valid");

                let expected_psbt =
                    base64_psbt_v0(&expected.base64).expect("update expected PSBT must be valid");

                let fp = xpriv.map(|xpriv| {
                    let secp = Secp256k1::new();
                    Xpub::from_priv(&secp, &xpriv).fingerprint()
                });

                for u in input_updates {
                    let prev_tx = {
                        let bytes =
                            Vec::from_hex(&u.previous_tx).expect("previous_tx must be valid hex");
                        deserialize::<Transaction>(&bytes)
                            .expect("previous_tx must be a valid transaction")
                    };
                    let txid = prev_tx.compute_txid();
                    let i = psbt
                        .inputs
                        .iter()
                        .position(|input| input.previous_txid == txid)
                        .expect("input_update previous_tx does not match any PSBT input");
                    let vout = usize::from(psbt.inputs[i].spent_output_index);
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
            Task::StrictSign { psbt, xpriv, seed, private_keys, expected } => {
                let secp = Secp256k1::new();
                let xpriv = *xpriv;

                if let Some(sk) = seed {
                    let seeded =
                        Xpriv::new_master(xpriv.network, &sk.inner.secret_bytes()).unwrap();
                    assert_eq!(seeded, xpriv);
                }

                let psbt = base64_psbt_v0(&psbt.base64).expect("sign input PSBT must be valid");

                let expected_psbt =
                    base64_psbt_v0(&expected.base64).expect("sign expected PSBT must be valid");

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

                let mut signer = Signer::new(psbt).expect("lock time must be determinable");
                let sigs = signer.session(|mut session| {
                    let signable_inputs =
                        session.signable_inputs().expect("inputs are well formed and verifiable");
                    session.get_all(&signable_inputs, &key_map, &secp)
                });
                let psbt = signer.apply(sigs).unwrap();

                assert_eq!(psbt, expected_psbt);
            }
            Task::TrustedSign { psbt, xpriv, seed, private_keys, expected } => {
                let secp = Secp256k1::new();
                let xpriv = *xpriv;

                if let Some(sk) = seed {
                    let seeded =
                        Xpriv::new_master(xpriv.network, &sk.inner.secret_bytes()).unwrap();
                    assert_eq!(seeded, xpriv);
                }

                let psbt = base64_psbt_v0(&psbt.base64).expect("sign input PSBT must be valid");

                let expected_psbt =
                    base64_psbt_v0(&expected.base64).expect("sign expected PSBT must be valid");

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

                let mut signer = Signer::new(psbt).expect("lock time must be determinable");
                let sigs = signer.session(|mut session| {
                    let inputs = session.assume_checked_inputs().expect("inputs are well formed");
                    session.get_all(&inputs, &key_map, &secp)
                });
                let psbt = signer.apply(sigs).unwrap();

                assert_eq!(psbt, expected_psbt);
            }
            // Combine: merge multiple PSBTs into one.
            Task::Combine { psbts, expected } => {
                assert!(psbts.len() >= 2, "combine task needs at least two input PSBTs");

                let expected_psbt =
                    base64_psbt_v0(&expected.base64).expect("combine expected PSBT must be valid");

                let mut combined =
                    base64_psbt_v0(&psbts[0].base64).expect("combine input[0] must be valid");

                for p in &psbts[1..] {
                    let next = base64_psbt_v0(&p.base64).expect("combine input must be valid");
                    combined = combined.combine_with(next).expect("combine must succeed");
                }

                assert_eq!(combined, expected_psbt);
            }
            // Finalize: apply final scripts and witnesses.
            Task::Finalize { psbt, expected } => {
                let psbt = base64_psbt_v0(&psbt.base64).expect("finalize input PSBT must be valid");

                let expected_psbt =
                    base64_psbt_v0(&expected.base64).expect("finalize expected PSBT must be valid");

                let secp = Secp256k1::verification_only();
                let finalizer = Finalizer::new(psbt).expect("finalizer requirements must be met");
                let psbt = finalizer.finalize(&secp).expect("input psbt must be finalizable");

                assert_eq!(psbt, expected_psbt);
            }
            // Extract: extract the final transaction from a finalized PSBT.
            Task::Extract { psbt, tx: expected_tx_hex } => {
                let psbt = base64_psbt_v0(&psbt.base64).expect("extract input PSBT must be valid");

                let extractor = Extractor::new(psbt).expect("extract task PSBT must be finalized");
                let tx = extractor.extract_tx_unchecked_fee_rate().expect("extract must succeed");
                assert_eq!(serialize_hex(&tx), expected_tx_hex.as_str());
            }
            // DetermineLockTime: compute the lock time from the PSBT.
            Task::DetermineLockTime { psbts, expected_lock_time } => {
                let expected_lock_time = *expected_lock_time;
                for PsbtData { base64 } in psbts {
                    let psbt =
                        base64.parse::<psbt_v2::Psbt>().expect("failed to deserialize from base64");

                    let got = psbt.determine_lock_time().expect("valid lock time");
                    let want = bitcoin::absolute::LockTime::from_consensus(expected_lock_time);
                    assert_eq!(got, want);
                }
            }
            // FailDetermineLockTime: lock time determination must fail.
            Task::FailDetermineLockTime { psbts } =>
                for PsbtData { base64 } in psbts {
                    let psbt =
                        base64.parse::<psbt_v2::Psbt>().expect("failed to deserialize from base64");

                    assert!(
                        psbt.determine_lock_time().is_err(),
                        "expected determine_lock_time to fail"
                    );
                },
        }
    }
}

/// Defines a public function `$spec(desc: &str)` that looks up a test case by its
/// exact JSON `description` field and executes it via [`TestCase::execute`].
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
make_check_case!(fuzz);
