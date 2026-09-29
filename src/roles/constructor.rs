// SPDX-License-Identifier: CC0-1.0

//! The BIP-370 Constructor role.

use core::marker::PhantomData;

use crate::error::{
    DetermineLockTimeError, InputsNotModifiableError, OutputsNotModifiableError,
    PsbtNotModifiableError,
};
use crate::input::Input;
use crate::output::{self, Output};
use crate::psbt::{Psbt, Updater};
use crate::roles::Creator;

/// Marker for a `Constructor` with both inputs and outputs modifiable.
pub enum Modifiable {}
/// Marker for a `Constructor` with inputs modifiable.
pub enum InputsOnlyModifiable {}
/// Marker for a `Constructor` with outputs modifiable.
pub enum OutputsOnlyModifiable {}

mod sealed {
    pub trait Mod {}
    impl Mod for super::Modifiable {}
    impl Mod for super::InputsOnlyModifiable {}
    impl Mod for super::OutputsOnlyModifiable {}
}

/// Marker for if either inputs or outputs are modifiable, or both.
pub trait Mod: sealed::Mod + Sync + Send + Sized + Unpin {}

impl Mod for Modifiable {}
impl Mod for InputsOnlyModifiable {}
impl Mod for OutputsOnlyModifiable {}

/// Implements the BIP-370 Constructor role.
///
/// Uses the builder pattern, and generics to make adding inputs and outputs infallible.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Constructor<T>(pub(crate) Psbt, pub(crate) PhantomData<T>);

impl<T: Mod> Constructor<T> {
    /// Marks that the `Psbt` can not have any more inputs added to it.
    pub fn no_more_inputs(mut self) -> Self {
        self.0.global.clear_inputs_modifiable_flag();
        self
    }

    /// Marks that the `Psbt` can not have any more outputs added to it.
    pub fn no_more_outputs(mut self) -> Self {
        self.0.global.clear_outputs_modifiable_flag();
        self
    }

    /// Returns a PSBT [`Updater`] once construction is completed.
    pub fn updater(self) -> Result<Updater, DetermineLockTimeError> {
        self.no_more_inputs().no_more_outputs().psbt().map(Updater)
    }

    /// Returns the [`Psbt`] in its current state.
    ///
    /// This function can be used either to get the [`Psbt`] to pass to another constructor or to
    /// get the [`Psbt`] ready for update if `no_more_inputs` and `no_more_outputs` have already
    /// explicitly been called.
    pub fn psbt(self) -> Result<Psbt, DetermineLockTimeError> {
        let _ = self.0.determine_lock_time()?;
        Ok(self.0)
    }
}

impl Constructor<Modifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, PsbtNotModifiableError> {
        if !psbt.global.is_inputs_modifiable() {
            Err(InputsNotModifiableError.into())
        } else if !psbt.global.is_outputs_modifiable() {
            Err(OutputsNotModifiableError.into())
        } else {
            Ok(Self(psbt, PhantomData))
        }
    }

    /// Adds an input to the PSBT.
    pub fn input(mut self, input: Input) -> Self {
        self.0.inputs.push(input);
        self.0.global.input_count += 1;
        self
    }

    /// Adds an output to the PSBT.
    ///
    /// # Errors
    ///
    /// If `output` breaks the BIP-370 and BIP-375 output rules, see [`Output::validate`].
    pub fn output(mut self, output: Output) -> Result<Self, output::ValidationError> {
        output.validate()?;
        self.0.outputs.push(output);
        self.0.global.output_count += 1;
        Ok(self)
    }
}
// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<Modifiable> {
    fn default() -> Self { Creator::new().constructor_modifiable() }
}

impl Constructor<InputsOnlyModifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, InputsNotModifiableError> {
        if psbt.global.is_inputs_modifiable() {
            Ok(Self(psbt, PhantomData))
        } else {
            Err(InputsNotModifiableError)
        }
    }

    /// Adds an input to the PSBT.
    pub fn input(mut self, input: Input) -> Self {
        self.0.inputs.push(input);
        self.0.global.input_count += 1;
        self
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<InputsOnlyModifiable> {
    fn default() -> Self { Creator::new().constructor_inputs_only_modifiable() }
}

impl Constructor<OutputsOnlyModifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, OutputsNotModifiableError> {
        if psbt.global.is_outputs_modifiable() {
            Ok(Self(psbt, PhantomData))
        } else {
            Err(OutputsNotModifiableError)
        }
    }

    /// Adds an output to the PSBT.
    ///
    /// # Errors
    ///
    /// If `output` breaks the BIP-370 and BIP-375 output rules, see [`Output::validate`].
    pub fn output(mut self, output: Output) -> Result<Self, output::ValidationError> {
        output.validate()?;
        self.0.outputs.push(output);
        self.0.global.output_count += 1;
        Ok(self)
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<OutputsOnlyModifiable> {
    fn default() -> Self { Creator::new().constructor_outputs_only_modifiable() }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};

    use super::{Constructor, InputsOnlyModifiable};
    use crate::input::Input;

    fn dummy_input() -> Input { Input::new(&OutPoint { txid: Txid::all_zeros(), vout: 0 }) }

    #[test]
    fn inputs_only_constructor_input_appends_and_counts() {
        let constructor = Constructor::<InputsOnlyModifiable>::default()
            .input(dummy_input())
            .input(dummy_input());
        assert_eq!(constructor.0.inputs.len(), 2);
        assert_eq!(constructor.0.global.input_count, 2);
    }
}
