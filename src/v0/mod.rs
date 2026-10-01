// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions Version 0 codec.
//!
#![allow(dead_code)]
//! This module is private to the crate: v0 PSBTs are handled through the explicit decode/encode
//! entry points on [`psbt::Psbt`] implemented at the bottom of this file.
//!
//! [`rust-bitcoin`]: <https://github.com/rust-bitcoin/rust-bitcoin>

mod bitcoin;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use ::bitcoin::locktime::absolute;
#[cfg(feature = "silent-payments")]
use ::bitcoin::CompressedPublicKey;

use self::bitcoin::{Input, Output, Psbt};
#[cfg(feature = "silent-payments")]
use crate::consts::{
    PSBT_GLOBAL_SP_DLEQ, PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_IN_SP_DLEQ, PSBT_IN_SP_ECDH_SHARE,
    PSBT_OUT_SP_V0_INFO, PSBT_OUT_SP_V0_LABEL,
};
#[cfg(feature = "silent-payments")]
use crate::dleq::DleqProof;
#[cfg(feature = "silent-payments")]
use crate::encoding::encode_to_vec;
#[cfg(feature = "silent-payments")]
use crate::SpV0Info;
use crate::{psbt, DetermineLockTimeError};

/// Converts a v0 raw key into the equivalent v2 raw key.
fn raw_key_v0_to_v2(k: bitcoin::raw::Key) -> crate::map::Key {
    crate::map::Key { type_value: k.type_value, key: k.key }
}

/// Converts a v0 raw proprietary key into the equivalent v2 raw proprietary key.
fn raw_proprietary_v0_to_v2(k: bitcoin::raw::ProprietaryKey) -> crate::map::ProprietaryKey {
    crate::map::ProprietaryKey { prefix: k.prefix, subtype: k.subtype, key: k.key }
}

/// Converts a v2 raw key into the equivalent v0 raw key.
fn raw_key_v2_to_v0(k: &crate::map::Key) -> bitcoin::raw::Key {
    bitcoin::raw::Key { type_value: k.type_value, key: k.key.clone() }
}

/// Converts a v2 raw proprietary key into the equivalent v0 raw proprietary key.
fn raw_proprietary_v2_to_v0(k: &crate::map::ProprietaryKey) -> bitcoin::raw::ProprietaryKey {
    bitcoin::raw::ProprietaryKey {
        prefix: k.prefix.clone(),
        subtype: k.subtype,
        key: k.key.clone(),
    }
}

/// Converts a v0 [`Psbt`] into a [`psbt::Psbt`].
///
/// This conversion is lossless. Fields that live in the v0 `unsigned_tx` are redistributed to
/// their v2 equivalents.
fn psbt_v0_to_v2(psbt: Psbt) -> psbt::Psbt {
    let Psbt { unsigned_tx, xpub, proprietary, unknown, inputs, outputs, .. } = psbt;

    let fallback_lock_time = if unsigned_tx.lock_time == absolute::LockTime::ZERO {
        None
    } else {
        Some(unsigned_tx.lock_time)
    };

    // Extract v2-only fields that were preserved as unknown keys.
    #[cfg(feature = "silent-payments")]
    let mut sp_ecdh_shares = BTreeMap::new();
    #[cfg(feature = "silent-payments")]
    let mut sp_dleq_proofs = BTreeMap::new();

    // Filter out known silent-payment keys into the structured fields.
    #[cfg(feature = "silent-payments")]
    let unknown = unknown
        .into_iter()
        .filter_map(|(k, v)| match k.type_value {
            PSBT_GLOBAL_SP_ECDH_SHARE if k.key.len() == 33 && v.len() == 33 =>
                match (CompressedPublicKey::from_slice(&k.key), CompressedPublicKey::from_slice(&v))
                {
                    (Ok(scan), Ok(share)) => {
                        sp_ecdh_shares.insert(scan, share);
                        None
                    }
                    _ => Some((k, v)),
                },
            PSBT_GLOBAL_SP_DLEQ if k.key.len() == 33 && v.len() == 64 => match (
                CompressedPublicKey::from_slice(&k.key),
                <[u8; 64]>::try_from(v.as_slice()).map(DleqProof::from),
            ) {
                (Ok(scan), Ok(proof)) => {
                    sp_dleq_proofs.insert(scan, proof);
                    None
                }
                _ => Some((k, v)),
            },
            _ => Some((k, v)),
        })
        .collect::<BTreeMap<_, _>>();

    // Convert remaining keys from v0 to v2 format.
    let unknowns: BTreeMap<_, _> =
        unknown.into_iter().map(|(k, v)| (raw_key_v0_to_v2(k), v)).collect();

    let global = crate::Global {
        version: crate::V2,
        tx_version: unsigned_tx.version,
        fallback_lock_time,
        tx_modifiable_flags: 0,
        input_count: unsigned_tx.input.len(),
        output_count: unsigned_tx.output.len(),
        xpubs: xpub,
        #[cfg(feature = "silent-payments")]
        sp_ecdh_shares,
        #[cfg(feature = "silent-payments")]
        sp_dleq_proofs,
        proprietaries: proprietary
            .into_iter()
            .map(|(k, v)| (raw_proprietary_v0_to_v2(k), v))
            .collect(),
        unknowns,
    };

    let inputs = unsigned_tx
        .input
        .iter()
        .zip(inputs)
        .map(|(txin, input)| {
            #[cfg(feature = "silent-payments")]
            let mut sp_ecdh = BTreeMap::new();
            #[cfg(feature = "silent-payments")]
            let mut sp_dleq = BTreeMap::new();

            // Filter out known silent-payment input keys.
            #[cfg(feature = "silent-payments")]
            let unknown = input
                .unknown
                .into_iter()
                .filter_map(|(k, v)| {
                    match k.type_value {
                        PSBT_IN_SP_ECDH_SHARE if k.key.len() == 33 && v.len() == 33 => {
                            if let (Ok(scan), Ok(share)) = (
                                CompressedPublicKey::from_slice(&k.key),
                                CompressedPublicKey::from_slice(&v),
                            ) {
                                sp_ecdh.insert(scan, share);
                                return None;
                            }
                        }
                        PSBT_IN_SP_DLEQ if k.key.len() == 33 && v.len() == 64 => {
                            if let (Ok(scan), Ok(proof)) = (
                                CompressedPublicKey::from_slice(&k.key),
                                <[u8; 64]>::try_from(v.as_slice()).map(DleqProof::from),
                            ) {
                                sp_dleq.insert(scan, proof);
                                return None;
                            }
                        }
                        _ => {}
                    }
                    Some((k, v))
                })
                .collect::<BTreeMap<_, _>>();
            #[cfg(not(feature = "silent-payments"))]
            let unknown = input.unknown;

            // Convert remaining keys from v0 to v2 format.
            let unknowns: BTreeMap<_, _> =
                unknown.into_iter().map(|(k, v)| (raw_key_v0_to_v2(k), v)).collect();

            crate::Input {
                previous_txid: txin.previous_output.txid,
                spent_output_index: txin.previous_output.vout,
                sequence: Some(txin.sequence),
                min_time: None,
                min_height: None,
                non_witness_utxo: input.non_witness_utxo,
                witness_utxo: input.witness_utxo,
                partial_sigs: input.partial_sigs,
                sighash_type: input.sighash_type,
                redeem_script: input.redeem_script,
                witness_script: input.witness_script,
                bip32_derivations: input.bip32_derivation,
                final_script_sig: input.final_script_sig,
                final_script_witness: input.final_script_witness,
                ripemd160_preimages: input.ripemd160_preimages,
                sha256_preimages: input.sha256_preimages,
                hash160_preimages: input.hash160_preimages,
                hash256_preimages: input.hash256_preimages,
                tap_key_sig: input.tap_key_sig,
                tap_script_sigs: input.tap_script_sigs,
                tap_scripts: input.tap_scripts,
                tap_key_origins: input.tap_key_origins,
                tap_internal_key: input.tap_internal_key,
                tap_merkle_root: input.tap_merkle_root,
                #[cfg(feature = "silent-payments")]
                sp_ecdh_shares: sp_ecdh,
                #[cfg(feature = "silent-payments")]
                sp_dleq_proofs: sp_dleq,
                proprietaries: input
                    .proprietary
                    .into_iter()
                    .map(|(k, v)| (raw_proprietary_v0_to_v2(k), v))
                    .collect(),
                unknowns,
            }
        })
        .collect();

    let outputs = unsigned_tx
        .output
        .into_iter()
        .zip(outputs)
        .map(|(txout, output)| {
            #[cfg(feature = "silent-payments")]
            let mut sp_info = None;
            #[cfg(feature = "silent-payments")]
            let mut sp_label = None;

            // Filter out known silent-payment output keys.
            #[cfg(feature = "silent-payments")]
            let unknown = output
                .unknown
                .into_iter()
                .filter_map(|(k, v)| {
                    match k.type_value {
                        PSBT_OUT_SP_V0_INFO if k.key.is_empty() =>
                            if v.len() == 66 {
                                let mut arr = [0u8; 66];
                                arr.copy_from_slice(&v);
                                if let Ok(info) = SpV0Info::from_byte_array(&arr) {
                                    sp_info = Some(info);
                                    return None;
                                }
                            },
                        PSBT_OUT_SP_V0_LABEL if k.key.is_empty() => {
                            if v.len() == 4 {
                                let mut bytes = [0u8; 4];
                                bytes.copy_from_slice(&v);
                                sp_label = Some(u32::from_le_bytes(bytes));
                            }
                            return None;
                        }
                        _ => {}
                    }
                    Some((k, v))
                })
                .collect::<BTreeMap<_, _>>();
            #[cfg(not(feature = "silent-payments"))]
            let unknown = output.unknown;

            // Convert remaining keys from v0 to v2 format.
            let unknowns: BTreeMap<_, _> =
                unknown.into_iter().map(|(k, v)| (raw_key_v0_to_v2(k), v)).collect();

            crate::Output {
                amount: txout.value,
                script_pubkey: txout.script_pubkey,
                redeem_script: output.redeem_script,
                witness_script: output.witness_script,
                bip32_derivations: output.bip32_derivation,
                tap_internal_key: output.tap_internal_key,
                tap_tree: output.tap_tree,
                tap_key_origins: output.tap_key_origins,
                #[cfg(feature = "silent-payments")]
                sp_v0_info: sp_info,
                #[cfg(feature = "silent-payments")]
                sp_v0_label: sp_label,
                proprietaries: output
                    .proprietary
                    .into_iter()
                    .map(|(k, v)| (raw_proprietary_v0_to_v2(k), v))
                    .collect(),
                unknowns,
            }
        })
        .collect();

    psbt::Psbt { global, inputs, outputs }
}

/// Converts a v2 [`psbt::Input`] into a v0 [`Input`], dropping v2-only fields.
fn input_v2_to_v0(input: &crate::Input) -> Input {
    let base = input.unknowns.iter().map(|(k, v)| (raw_key_v2_to_v0(k), v.clone()));

    #[cfg(feature = "silent-payments")]
    let unknown: BTreeMap<_, Vec<u8>> = {
        let mut map: BTreeMap<_, _> = base.collect();
        for (scan_key, share) in &input.sp_ecdh_shares {
            map.insert(
                bitcoin::raw::Key {
                    type_value: PSBT_IN_SP_ECDH_SHARE,
                    key: scan_key.to_bytes().to_vec(),
                },
                share.to_bytes().to_vec(),
            );
        }
        for (scan_key, proof) in &input.sp_dleq_proofs {
            map.insert(
                bitcoin::raw::Key {
                    type_value: PSBT_IN_SP_DLEQ,
                    key: scan_key.to_bytes().to_vec(),
                },
                proof.as_bytes().to_vec(),
            );
        }
        map
    };
    #[cfg(not(feature = "silent-payments"))]
    let unknown: BTreeMap<_, Vec<u8>> = base.collect();

    Input {
        non_witness_utxo: input.non_witness_utxo.clone(),
        witness_utxo: input.witness_utxo.clone(),
        partial_sigs: input.partial_sigs.clone(),
        sighash_type: input.sighash_type,
        redeem_script: input.redeem_script.clone(),
        witness_script: input.witness_script.clone(),
        bip32_derivation: input.bip32_derivations.clone(),
        final_script_sig: input.final_script_sig.clone(),
        final_script_witness: input.final_script_witness.clone(),
        ripemd160_preimages: input.ripemd160_preimages.clone(),
        sha256_preimages: input.sha256_preimages.clone(),
        hash160_preimages: input.hash160_preimages.clone(),
        hash256_preimages: input.hash256_preimages.clone(),
        tap_key_sig: input.tap_key_sig,
        tap_script_sigs: input.tap_script_sigs.clone(),
        tap_scripts: input.tap_scripts.clone(),
        tap_key_origins: input.tap_key_origins.clone(),
        tap_internal_key: input.tap_internal_key,
        tap_merkle_root: input.tap_merkle_root,
        proprietary: input
            .proprietaries
            .iter()
            .map(|(k, v)| (raw_proprietary_v2_to_v0(k), v.clone()))
            .collect(),
        unknown,
    }
}

/// Converts a v2 [`psbt::Output`] into a v0 [`Output`].
fn output_v2_to_v0(output: &crate::Output) -> Output {
    let base = output.unknowns.iter().map(|(k, v)| (raw_key_v2_to_v0(k), v.clone()));

    #[cfg(feature = "silent-payments")]
    let unknown: BTreeMap<_, Vec<u8>> = {
        let mut map: BTreeMap<_, _> = base.collect();
        if let Some(ref info) = output.sp_v0_info {
            map.insert(
                bitcoin::raw::Key { type_value: PSBT_OUT_SP_V0_INFO, key: Vec::new() },
                encode_to_vec(info),
            );
        }
        if let Some(label) = output.sp_v0_label {
            map.insert(
                bitcoin::raw::Key { type_value: PSBT_OUT_SP_V0_LABEL, key: Vec::new() },
                label.to_le_bytes().to_vec(),
            );
        }
        map
    };
    #[cfg(not(feature = "silent-payments"))]
    let unknown: BTreeMap<_, Vec<u8>> = base.collect();

    Output {
        redeem_script: output.redeem_script.clone(),
        witness_script: output.witness_script.clone(),
        bip32_derivation: output.bip32_derivations.clone(),
        tap_internal_key: output.tap_internal_key,
        tap_tree: output.tap_tree.clone(),
        tap_key_origins: output.tap_key_origins.clone(),
        proprietary: output
            .proprietaries
            .iter()
            .map(|(k, v)| (raw_proprietary_v2_to_v0(k), v.clone()))
            .collect(),
        unknown,
    }
}

/// Describes which v2-only fields were demoted to unknown key-value pairs when encoding a v2 PSBT
/// as v0.
///
/// The silent payments extension ([BIP-375]) defines key types with no v0 semantic
/// equivalent. Rather than dropping these fields, the v0 encoder preserves them as
/// unknown key-value pairs so they survive a round-trip back to v2.
///
/// Fields that are merged into the `unsigned_tx` rather than moved to unknowns, such as
/// `previous_txid`/`amount`/`sequence`, are *not* tracked here.
///
/// The v0 encoding implies construction is complete, inputs and outputs have been set in the
/// unsigned transaction. So `tx_modifiable_flags` is intentionally not preserved since it is
/// construction-phase metadata, not PSBT content.
///
/// [BIP-375]: https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Degraded {
    /// Number of silent payment ECDH shares encoded as unknown global keys (`0x07`).
    pub sp_ecdh_shares: usize,
    /// Number of silent payment DLEQ proofs encoded as unknown global keys from the global map
    /// (`0x08`).
    pub sp_dleq_proofs: usize,
    /// Number of inputs whose silent payment fields were encoded as unknown
    /// per-input keys (`0x1d` / `0x1e`).
    pub sp_dropped_inputs: usize,
    /// Number of outputs whose silent payment fields were encoded as unknown per-output keys
    /// (`0x09` and/or `0x0a` was `Some`).
    pub sp_dropped_outputs: usize,
}

impl Degraded {
    /// Returns `true` if no fields were demoted to unknowns.
    pub fn is_empty(&self) -> bool {
        self.sp_ecdh_shares == 0
            && self.sp_dleq_proofs == 0
            && self.sp_dropped_inputs == 0
            && self.sp_dropped_outputs == 0
    }
}

/// Converts a [`psbt::Psbt`] into a v0 [`Psbt`], reconstructing the unsigned transaction from
/// the v2 fields. v2-only fields without v0 equivalents are preserved as unknown key-value
/// pairs rather than being dropped.
fn psbt_v2_to_v0(psbt: &psbt::Psbt) -> Psbt {
    let unsigned_tx = psbt.unsigned_tx().expect("caller ensures lock time can be determined");
    let inputs = psbt.inputs.iter().map(input_v2_to_v0).collect();
    let outputs = psbt.outputs.iter().map(output_v2_to_v0).collect();

    let global = &psbt.global;
    let proprietary = global
        .proprietaries
        .iter()
        .map(|(k, v)| (raw_proprietary_v2_to_v0(k), v.clone()))
        .collect();
    let base = global.unknowns.iter().map(|(k, v)| (raw_key_v2_to_v0(k), v.clone()));

    #[cfg(feature = "silent-payments")]
    let unknown: BTreeMap<_, Vec<u8>> = {
        let mut map: BTreeMap<_, _> = base.collect();
        for (scan_key, share) in &global.sp_ecdh_shares {
            map.insert(
                bitcoin::raw::Key {
                    type_value: PSBT_GLOBAL_SP_ECDH_SHARE,
                    key: scan_key.to_bytes().to_vec(),
                },
                share.to_bytes().to_vec(),
            );
        }
        for (scan_key, proof) in &global.sp_dleq_proofs {
            map.insert(
                bitcoin::raw::Key {
                    type_value: PSBT_GLOBAL_SP_DLEQ,
                    key: scan_key.to_bytes().to_vec(),
                },
                proof.as_bytes().to_vec(),
            );
        }
        map
    };
    #[cfg(not(feature = "silent-payments"))]
    let unknown: BTreeMap<_, Vec<u8>> = base.collect();

    Psbt {
        unsigned_tx,
        version: 0,
        xpub: global.xpubs.clone(),
        proprietary,
        unknown,
        inputs,
        outputs,
    }
}

impl psbt::Psbt {
    /// Computes which v2 fields will be degraded to unknown keys by a v0 encoding.
    pub fn v0_degraded(&self) -> Degraded {
        #[cfg(feature = "silent-payments")]
        {
            Degraded {
                sp_ecdh_shares: self.global.sp_ecdh_shares.len(),
                sp_dleq_proofs: self.global.sp_dleq_proofs.len(),
                sp_dropped_inputs: self
                    .inputs
                    .iter()
                    .filter(|i| !i.sp_ecdh_shares.is_empty() || !i.sp_dleq_proofs.is_empty())
                    .count(),
                sp_dropped_outputs: self
                    .outputs
                    .iter()
                    .filter(|o| o.sp_v0_info.is_some() || o.sp_v0_label.is_some())
                    .count(),
            }
        }
        #[cfg(not(feature = "silent-payments"))]
        {
            Degraded::default()
        }
    }

    /// Deserializes a PSBT v0 (BIP-174) from raw data.
    ///
    /// This only accepts v0 PSBTs, use [`Self::deserialize`] for v2 PSBTs (BIP-370).
    pub fn deserialize_v0(bytes: &[u8]) -> Result<Self, DeserializeV0Error> {
        let psbt = Psbt::deserialize(bytes).map_err(DeserializeV0Error)?;
        if psbt.version != 0 {
            return Err(DeserializeV0Error(bitcoin::Error::Version(
                "PSBT version number must be 0",
            )));
        }
        Ok(psbt_v0_to_v2(psbt))
    }

    /// Consumes this PSBT and locks it as PSBT v0 (BIP-174).
    ///
    /// v2-only fields without v0 equivalents are preserved as unknown key-value pairs when
    /// encoding. Use [`Self::v0_degraded`] to inspect what was demoted to unknowns.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction lock time cannot be determined from the PSBT's
    /// lock time fields.
    pub fn into_psbt_v0(self) -> Result<crate::psbt::PsbtV0, DetermineLockTimeError> {
        crate::psbt::PsbtV0::from_psbt(self)
    }

    /// Deserializes a PSBT v0 (BIP-174) from a base64 encoded string.
    #[cfg(feature = "base64")]
    pub fn deserialize_v0_base64(s: &str) -> Result<Self, ParsePsbtV0Error> {
        use ::bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};

        let data = BASE64_STANDARD.decode(s).map_err(ParsePsbtV0Error::Base64Encoding)?;
        Self::deserialize_v0(&data).map_err(ParsePsbtV0Error::PsbtEncoding)
    }
}

/// Error deserializing a BIP-174 (PSBT v0) PSBT.
#[derive(Debug)]
pub struct DeserializeV0Error(bitcoin::Error);

impl fmt::Display for DeserializeV0Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "v0 PSBT: {}", self.0) }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializeV0Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

/// Error parsing a BIP-174 (PSBT v0) PSBT from a base64 string.
#[cfg(feature = "base64")]
#[derive(Debug)]
pub enum ParsePsbtV0Error {
    /// Error in the v0 PSBT encoding.
    PsbtEncoding(DeserializeV0Error),
    /// Error in the base64 encoding.
    Base64Encoding(::bitcoin::base64::DecodeError),
}

#[cfg(feature = "base64")]
impl fmt::Display for ParsePsbtV0Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParsePsbtV0Error::*;

        match *self {
            PsbtEncoding(ref e) => write!(f, "error in v0 PSBT encoding: {}", e),
            Base64Encoding(ref e) => write!(f, "error in PSBT base64 encoding: {}", e),
        }
    }
}

#[cfg(all(feature = "std", feature = "base64"))]
impl std::error::Error for ParsePsbtV0Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParsePsbtV0Error::*;

        match *self {
            PsbtEncoding(ref e) => Some(e),
            Base64Encoding(ref e) => Some(e),
        }
    }
}
