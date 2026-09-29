// SPDX-License-Identifier: CC0-1.0

//! The BIP-370 Creator role.

use core::marker::PhantomData;

use bitcoin::locktime::absolute;
use bitcoin::transaction;

use crate::global::Global;
use crate::psbt::{Constructor, InputsOnlyModifiable, Modifiable, OutputsOnlyModifiable, Psbt};

/// Implements the BIP-370 Creator role.
///
/// The `Creator` type is only directly needed if one of the following holds:
///
/// - The creator and constructor are separate entities.
/// - You need to set the fallback lock time.
/// - You need to set the sighash single flag.
///
/// If not use the [`Constructor`]  to carry out both roles e.g., `Constructor::<Modifiable>::default()`.
///
/// See `examples/v2-separate-creator-constructor.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Creator(Psbt);

impl Creator {
    /// Creates a new PSBT Creator.
    pub fn new() -> Self {
        let psbt = Psbt {
            global: Global::default(),
            inputs: Default::default(),
            outputs: Default::default(),
        };
        Self(psbt)
    }

    /// Sets the fallback lock time.
    pub fn fallback_lock_time(mut self, fallback: absolute::LockTime) -> Self {
        self.0.global.fallback_lock_time = Some(fallback);
        self
    }

    /// Sets the "has sighash single" flag in then transaction modifiable flags.
    pub fn sighash_single(mut self) -> Self {
        self.0.global.set_sighash_single_flag();
        self
    }

    /// Sets the inputs modifiable bit in the transaction modifiable flags.
    pub fn inputs_modifiable(mut self) -> Self {
        self.0.global.set_inputs_modifiable_flag();
        self
    }

    /// Sets the outputs modifiable bit in the transaction modifiable flags.
    pub fn outputs_modifiable(mut self) -> Self {
        self.0.global.set_outputs_modifiable_flag();
        self
    }

    /// Sets the transaction version.
    ///
    /// You likely do not need this, it is provided for completeness.
    ///
    /// The default is [`transaction::Version::TWO`].
    pub fn transaction_version(mut self, version: transaction::Version) -> Self {
        self.0.global.tx_version = version;
        self
    }

    /// Builds a [`Constructor`] that can add inputs and outputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::{Creator, Constructor, Modifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .outputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<Modifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<Modifiable>::default();
    /// ```
    pub fn constructor_modifiable(self) -> Constructor<Modifiable> {
        let mut psbt = self.0;
        psbt.global.set_inputs_modifiable_flag();
        psbt.global.set_outputs_modifiable_flag();
        Constructor(psbt, PhantomData)
    }

    /// Builds a [`Constructor`] that can only add inputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::{Creator, Constructor, InputsOnlyModifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<InputsOnlyModifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_inputs_only_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<InputsOnlyModifiable>::default();
    /// ```
    pub fn constructor_inputs_only_modifiable(self) -> Constructor<InputsOnlyModifiable> {
        let mut psbt = self.0;
        psbt.global.set_inputs_modifiable_flag();
        psbt.global.clear_outputs_modifiable_flag();
        Constructor(psbt, PhantomData)
    }

    /// Builds a [`Constructor`] that can only add outputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::{Creator, Constructor, OutputsOnlyModifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<OutputsOnlyModifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_outputs_only_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<OutputsOnlyModifiable>::default();
    /// ```
    pub fn constructor_outputs_only_modifiable(self) -> Constructor<OutputsOnlyModifiable> {
        let mut psbt = self.0;
        psbt.global.clear_inputs_modifiable_flag();
        psbt.global.set_outputs_modifiable_flag();
        Constructor(psbt, PhantomData)
    }

    /// Returns the created [`Psbt`].
    ///
    /// This is only required if the Creator and Constructor are separate entities. If the Creator
    /// is also acting as the Constructor use one of the `Self::constructor_foo` functions.
    pub fn psbt(self) -> Psbt { self.0 }
}

impl Default for Creator {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use bitcoin::locktime::absolute;
    use bitcoin::transaction;

    use super::Creator;

    #[test]
    fn fallback_lock_time_is_set() {
        let lock_time = absolute::LockTime::from_consensus(500);
        let psbt = Creator::new().fallback_lock_time(lock_time).psbt();
        assert_eq!(psbt.global.fallback_lock_time, Some(lock_time));
    }

    #[test]
    fn sighash_single_flag_is_set() {
        let psbt = Creator::new().sighash_single().psbt();
        assert!(psbt.global.has_sighash_single());
    }

    #[test]
    fn inputs_modifiable_flag_is_set() {
        let psbt = Creator::new().inputs_modifiable().psbt();
        assert!(psbt.global.is_inputs_modifiable());
    }

    #[test]
    fn outputs_modifiable_flag_is_set() {
        let psbt = Creator::new().outputs_modifiable().psbt();
        assert!(psbt.global.is_outputs_modifiable());
    }

    #[test]
    fn transaction_version_is_set() {
        let psbt = Creator::new().transaction_version(transaction::Version::ONE).psbt();
        assert_eq!(psbt.global.tx_version, transaction::Version::ONE);
    }
}
