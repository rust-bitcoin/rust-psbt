// SPDX-License-Identifier: CC0-1.0

//! The BIP-370 Updater role.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::bip32::{KeySource, Xpub};
#[cfg(feature = "silent-payments")]
use bitcoin::CompressedPublicKey;
use bitcoin::Txid;

use crate::error::DetermineLockTimeError;
use crate::input::Input;
use crate::output::Output;
use crate::psbt::Psbt;
use crate::roles::signer::Signer;
#[cfg(feature = "silent-payments")]
use crate::DleqProof;
use crate::{Key, ProprietaryKey};

/// Implements the BIP-370 Updater role.
///
/// The updater can set `PSBT_IN_SEQUENCE` (per BIP-370) and add any auxiliary information
/// the signer requires (per BIP-174): witness UTXOs, scripts, BIP-32 derivations, preimages,
/// taproot data, and proprietary or unknown fields. It cannot add or remove inputs or outputs
/// (that is the Constructor role).
///
/// Access to the PSBT is provided through [`Updater::update`], which lends the updatable
/// fields via an [`UpdaterView`] inside a closure. Once all updates are applied, either
/// extract the [`Psbt`] with [`Updater::psbt`] or transition directly to the [`Signer`] role
/// with [`Updater::signer`].
///
/// # Examples
///
/// ```
/// use psbt_v2::{Creator, Input, Output, Updater};
/// use psbt_v2::bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut};
///
/// let psbt = Creator::new()
///     .constructor_modifiable()
///     .input(Input::new(&OutPoint::default()))
///     .output(Output::new(TxOut {
///         value: Amount::from_sat(10000),
///         script_pubkey: ScriptBuf::new(),
///     }))
///     .expect("output must be valid")
///     .psbt()
///     .expect("lock time must be determinable");
///
/// let mut updater = Updater::new(psbt)?;
///
/// updater.update(|view| {
///     view.inputs[0].sequence = Some(Sequence::ENABLE_LOCKTIME_NO_RBF);
///     view.inputs[0].witness_utxo = Some(TxOut {
///         value: Amount::from_sat(100000),
///         script_pubkey: ScriptBuf::new(),
///     });
/// });
///
/// let _psbt = updater.psbt()?;
/// # Ok::<(), psbt_v2::DetermineLockTimeError>(())
/// ```
///
/// [`Signer`]: crate::Signer
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Updater(pub(crate) Psbt);

/// A mutable view of the updatable fields of a PSBT, lent by [`Updater::update`].
///
/// Cannot add or remove inputs/outputs, only the existing slices are exposed.
pub struct UpdaterView<'a> {
    /// Updater-writable fields from the global map (`xpubs`, silent-payment keys, and
    /// proprietary / unknown entries). Structural fields like `input_count` and `tx_version`
    /// are intentionally absent.
    pub global: UpdaterGlobalView<'a>,
    /// Can mutate any field on an input, but cannot add or remove entries.
    pub inputs: &'a mut [Input],
    /// Can mutate any field on an output, but cannot add or remove entries.
    pub outputs: &'a mut [Output],
}

/// Updater-writable fields from the PSBT global map.
///
/// Excludes `input_count`, `output_count`, `tx_version`, `version`, `fallback_lock_time`,
/// and `tx_modifiable_flags` since those are managed by the Creator, Constructor, and Signer.
pub struct UpdaterGlobalView<'a> {
    /// Global xpubs used for BIP-32 key derivation.
    pub xpubs: &'a mut BTreeMap<Xpub, KeySource>,
    /// BIP-375: per-PSBT ECDH shares for silent payments.
    #[cfg(feature = "silent-payments")]
    pub sp_ecdh_shares: &'a mut BTreeMap<CompressedPublicKey, CompressedPublicKey>,
    /// BIP-375: per-PSBT DLEQ proofs for silent payments.
    #[cfg(feature = "silent-payments")]
    pub sp_dleq_proofs: &'a mut BTreeMap<CompressedPublicKey, DleqProof>,
    /// Proprietary key-value pairs in the global map.
    pub proprietaries: &'a mut BTreeMap<ProprietaryKey, Vec<u8>>,
    /// Unknown key-value pairs in the global map.
    pub unknowns: &'a mut BTreeMap<Key, Vec<u8>>,
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

    /// Lends the updatable PSBT fields to `f` through an [`UpdaterView`].
    ///
    /// All inputs, outputs, and updater-writable global fields are available simultaneously,
    /// so callers can read from one to write to another without staging data. The closure
    /// returns whatever value the caller needs; for fallible operations, return `Result` and
    /// use `?` both inside the closure and on `update` itself.
    pub fn update<T>(&mut self, f: impl FnOnce(&mut UpdaterView<'_>) -> T) -> T {
        let mut view = UpdaterView {
            global: UpdaterGlobalView {
                xpubs: &mut self.0.global.xpubs,
                #[cfg(feature = "silent-payments")]
                sp_ecdh_shares: &mut self.0.global.sp_ecdh_shares,
                #[cfg(feature = "silent-payments")]
                sp_dleq_proofs: &mut self.0.global.sp_dleq_proofs,
                proprietaries: &mut self.0.global.proprietaries,
                unknowns: &mut self.0.global.unknowns,
            },
            inputs: &mut self.0.inputs,
            outputs: &mut self.0.outputs,
        };
        f(&mut view)
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
