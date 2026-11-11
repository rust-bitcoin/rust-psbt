// SPDX-License-Identifier: CC0-1.0

//! The BIP-370 Updater role.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::bip32::{KeySource, Xpub};
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::{ControlBlock, TapLeafHash, TapNodeHash, TapTree};
use bitcoin::{PublicKey, ScriptBuf, Sequence, Transaction, TxOut, Txid};

use crate::encoding::codecs::leaf_script::TapLeafScript;
use crate::error::DetermineLockTimeError;
use crate::input::Input;
use crate::output::Output;
use crate::psbt::{CombineError, Psbt};
use crate::roles::signer::Signer;
use crate::{Global, ProprietaryKey, PsbtSighashType};

/// Implements the BIP-370 Updater role.
///
/// The updater adds information to the PSBT that it has access to. It allows setting any value that
/// has not been set before.
///
/// Ths PSBT stays locktime determinable during the whole life of updater, as locktime fields can
/// only be set by the Creator or the Constructor role.
///
/// The updatable fields are described by [`UpdaterPatch`]: [`Updater::update`] hands a copy of
/// them to the caller's closure and merges the returned patch back in using the combine operation.
/// Once all updates are applied, either extract the [`Psbt`] with [`Updater::psbt`] or
/// transition directly to the [`Signer`] role with [`Updater::signer`].
///
/// # Examples
///
/// ```
/// use psbt_v2::{Creator, Input, Output, Updater};
/// use psbt_v2::bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut};
///
/// let psbt = Creator::new()
///     .constructor_modifiable()
///     .input(Input::new(&OutPoint::default())).expect("lock time must be determinable")
///     .output(Output::new(TxOut {
///         value: Amount::from_sat(10000),
///         script_pubkey: ScriptBuf::new(),
///     }))
///     .expect("output must be valid")
///     .psbt();
///
/// let updater = Updater::new(psbt).expect("lock time must be determinable");
///
/// let updater = updater
///     .update(|mut patch| {
///         patch.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
///         patch.inputs[0].witness_utxo = Some(TxOut {
///             value: Amount::from_sat(100000),
///             script_pubkey: ScriptBuf::new(),
///         });
///         patch
///     })
///     .expect("the patch describes the same transaction");
///
/// let _psbt = updater.psbt().expect("lock time must be determinable");
/// ```
///
/// [`Signer`]: crate::Signer
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Updater(pub(crate) Psbt);

/// The updatable fields of a PSBT.
///
/// Carries the fields assigned to the Updater role by the [BIP-174], [BIP-370], [BIP-373], and
/// [BIP-375] role definitions as well as the [BIP-371] taproot fields, which are assigned to no
/// role and are populated by updaters in practice.
///
/// Fields managed by other roles are absent:
/// - the input and output identities.
/// - the silent-payment ECDH shares, DLEQ proofs, and output info.
/// - signatures.
/// - finalized scripts.
/// - the structural global and lock-time fields.
///
/// Merging a patch never removes information: fields the patch leaves unset are filled from the
/// PSBT being updated, and fields already set in the PSBT are preserved over the patch's values.
///
/// [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#user-content-Updater>
/// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#user-content-Updater>
/// [BIP-371]: <https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki>
/// [BIP-373]: <https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki#user-content-Updater>
/// [BIP-375]: <https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki#user-content-Updater>
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpdaterPatch {
    /// The updatable fields of the global map.
    pub global: GlobalPatch,
    /// The updatable fields of each input, by index.
    pub inputs: Vec<InputPatch>,
    /// The updatable fields of each output, by index.
    pub outputs: Vec<OutputPatch>,
}

/// The Updater-writable fields of the PSBT global map.
/// All other global fields are managed by the Creator, Constructor, and Signer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobalPatch {
    /// Global xpubs used for BIP-32 key derivation.
    pub xpubs: BTreeMap<Xpub, KeySource>,
    /// Proprietary key-value pairs in the global map.
    pub proprietaries: BTreeMap<ProprietaryKey, Vec<u8>>,
}

/// The Updater-writable fields of a PSBT input.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InputPatch {
    /// The sequence number of this input (BIP-370).
    pub sequence: Option<Sequence>,
    /// The non-witness transaction this input spends from (BIP-174).
    pub non_witness_utxo: Option<Transaction>,
    /// The transaction output this input spends from (BIP-174).
    pub witness_utxo: Option<TxOut>,
    /// The sighash type to be used for this input. Signatures for this input
    /// must use the sighash type.
    pub sighash_type: Option<PsbtSighashType>,
    /// The redeem script for this input (BIP-174).
    pub redeem_script: Option<ScriptBuf>,
    /// The witness script for this input (BIP-174).
    pub witness_script: Option<ScriptBuf>,
    /// A map from public keys needed to sign to their corresponding key origins (BIP-174)
    ///
    /// If the updater does not want to reveal the fingerprint or derivation path, it can set the
    /// value of the field to zero.
    pub bip32_derivations: BTreeMap<PublicKey, KeySource>,
    /// Map of RIPEMD160 hashes to their corresponding preimages (BIP-174).
    pub ripemd160_preimages: BTreeMap<ripemd160::Hash, Vec<u8>>,
    /// Map of SHA256 hashes to their corresponding preimages (BIP-174).
    pub sha256_preimages: BTreeMap<sha256::Hash, Vec<u8>>,
    /// Map of HASH160 hashes to their corresponding preimages (BIP-174).
    pub hash160_preimages: BTreeMap<hash160::Hash, Vec<u8>>,
    /// Map of HASH256 hashes to their corresponding preimages (BIP-174).
    pub hash256_preimages: BTreeMap<sha256d::Hash, Vec<u8>>,
    /// Map of control blocks to script version pairs (BIP-371).
    pub tap_scripts: BTreeMap<ControlBlock, TapLeafScript>,
    /// Map of taproot x-only keys to origin info and leaf hashes contained in it (BIP-373).
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// Taproot internal key (BIP-371).
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot merkle root (BIP-371).
    pub tap_merkle_root: Option<TapNodeHash>,
    /// Proprietary key-value pairs for this input (BIP-174).
    pub proprietaries: BTreeMap<ProprietaryKey, Vec<u8>>,
}

/// The Updater-writable fields of a PSBT output.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutputPatch {
    /// The redeem script for this output (BIP-174).
    pub redeem_script: Option<ScriptBuf>,
    /// The witness script for this output (BIP-174).
    pub witness_script: Option<ScriptBuf>,
    /// A map from public keys needed to spend this output to their corresponding master key
    /// fingerprints and derivation paths (BIP-174).
    pub bip32_derivations: BTreeMap<PublicKey, KeySource>,
    /// Taproot internal key (BIP-371).
    pub tap_internal_key: Option<XOnlyPublicKey>,
    /// Taproot output tree (BIP-371).
    pub tap_tree: Option<TapTree>,
    /// Map of taproot x-only keys to origin info and leaf hashes contained in it (BIP-373).
    pub tap_key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, KeySource)>,
    /// The silent-payment v0 output label, used for change detection (BIP-375).
    #[cfg(feature = "silent-payments")]
    pub sp_v0_label: Option<u32>,
    /// Proprietary key-value pairs for this output (BIP-174).
    pub proprietaries: BTreeMap<ProprietaryKey, Vec<u8>>,
}

impl Updater {
    /// Creates an `Updater`.
    ///
    /// An updater can only accept a PSBT that has a valid combination of lock times.
    pub fn new(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let _ = psbt.determine_lock_time()?;
        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Updater guarantees lock time can be determined")
    }

    /// Takes a copy of the updatable fields of the inner [`Psbt`].
    pub(crate) fn patch(&self) -> UpdaterPatch {
        UpdaterPatch {
            global: GlobalPatch {
                xpubs: self.0.global.xpubs.clone(),
                proprietaries: self.0.global.proprietaries.clone(),
            },
            inputs: self
                .0
                .inputs
                .iter()
                .map(|input| InputPatch {
                    sequence: input.sequence,
                    non_witness_utxo: input.non_witness_utxo.clone(),
                    witness_utxo: input.witness_utxo.clone(),
                    sighash_type: input.sighash_type,
                    redeem_script: input.redeem_script.clone(),
                    witness_script: input.witness_script.clone(),
                    bip32_derivations: input.bip32_derivations.clone(),
                    ripemd160_preimages: input.ripemd160_preimages.clone(),
                    sha256_preimages: input.sha256_preimages.clone(),
                    hash160_preimages: input.hash160_preimages.clone(),
                    hash256_preimages: input.hash256_preimages.clone(),
                    tap_scripts: input.tap_scripts.clone(),
                    tap_key_origins: input.tap_key_origins.clone(),
                    tap_internal_key: input.tap_internal_key,
                    tap_merkle_root: input.tap_merkle_root,
                    proprietaries: input.proprietaries.clone(),
                })
                .collect(),
            outputs: self
                .0
                .outputs
                .iter()
                .map(|output| OutputPatch {
                    redeem_script: output.redeem_script.clone(),
                    witness_script: output.witness_script.clone(),
                    bip32_derivations: output.bip32_derivations.clone(),
                    tap_internal_key: output.tap_internal_key,
                    tap_tree: output.tap_tree.clone(),
                    tap_key_origins: output.tap_key_origins.clone(),
                    #[cfg(feature = "silent-payments")]
                    sp_v0_label: output.sp_v0_label,
                    proprietaries: output.proprietaries.clone(),
                })
                .collect(),
        }
    }

    /// Combines the changes made by `f` back into the inner [`Psbt`] using the combine operation.
    ///
    /// `f` receives a copy of the PSBT carrying only the updatable fields and returns the modified
    /// patch, which is merged in via [`Psbt::combine_with`]: a value set by the patch does not
    /// override the value in the PSBT. An update can only set fields that are not set. Fields not
    /// present on the patch are carried over from the PSBT unchanged.
    ///
    /// # Errors
    ///
    /// Combining can fail with any [CombineError] propagated from [`Psbt::combine_with`].
    pub fn update<F>(self, f: F) -> Result<Self, CombineError>
    where
        F: FnOnce(UpdaterPatch) -> UpdaterPatch,
    {
        let patch = f(self.patch());
        if patch.inputs.len() != self.0.inputs.len() {
            return Err(CombineError::InputsLenMismatch {
                this: self.0.inputs.len(),
                that: patch.inputs.len(),
            });
        }
        if patch.outputs.len() != self.0.outputs.len() {
            return Err(CombineError::OutputsLenMismatch {
                this: self.0.outputs.len(),
                that: patch.outputs.len(),
            });
        }
        let delta = Psbt {
            global: Global {
                xpubs: patch.global.xpubs,
                proprietaries: patch.global.proprietaries,
                ..self.0.global.clone()
            },
            inputs: self
                .0
                .inputs
                .iter()
                .zip(patch.inputs)
                .map(|(input, update)| Input {
                    sequence: update.sequence,
                    non_witness_utxo: update.non_witness_utxo,
                    witness_utxo: update.witness_utxo,
                    sighash_type: update.sighash_type,
                    redeem_script: update.redeem_script,
                    witness_script: update.witness_script,
                    bip32_derivations: update.bip32_derivations,
                    ripemd160_preimages: update.ripemd160_preimages,
                    sha256_preimages: update.sha256_preimages,
                    hash160_preimages: update.hash160_preimages,
                    hash256_preimages: update.hash256_preimages,
                    tap_scripts: update.tap_scripts,
                    tap_key_origins: update.tap_key_origins,
                    tap_internal_key: update.tap_internal_key,
                    tap_merkle_root: update.tap_merkle_root,
                    proprietaries: update.proprietaries,
                    ..input.clone()
                })
                .collect(),
            outputs: self
                .0
                .outputs
                .iter()
                .zip(patch.outputs)
                .map(|(output, update)| Output {
                    redeem_script: update.redeem_script,
                    witness_script: update.witness_script,
                    bip32_derivations: update.bip32_derivations,
                    tap_internal_key: update.tap_internal_key,
                    tap_tree: update.tap_tree,
                    tap_key_origins: update.tap_key_origins,
                    #[cfg(feature = "silent-payments")]
                    sp_v0_label: update.sp_v0_label,
                    proprietaries: update.proprietaries,
                    ..output.clone()
                })
                .collect(),
        };

        let combined = self.0.combine_with(delta)?;
        Ok(Self(combined))
    }

    /// Consumes the `Updater` and returns the inner [`Psbt`], re-validating that the lock
    /// time is still determinable after any mutations.
    pub fn psbt(self) -> Result<Psbt, DetermineLockTimeError> {
        let _ = self.0.determine_lock_time()?;
        Ok(self.0)
    }

    /// Transitions directly to the [`Signer`] role after completing all updates.
    pub fn signer(self) -> Result<Signer, DetermineLockTimeError> { Signer::new(self.psbt()?) }
}
