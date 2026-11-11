// SPDX-License-Identifier: CC0-1.0

//! The BIP-370 Constructor role.

use core::fmt;
use core::marker::PhantomData;

use bitcoin::locktime::absolute;

use crate::error::{write_err, DetermineLockTimeError};
use crate::input::Input;
use crate::output::{self, Output};
use crate::psbt::Psbt;
use crate::roles::{Creator, Updater};

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

/// Error occurring in the [`Constructor`] role.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConstructError {
    /// The PSBT's inputs modifiable flag is not set.
    InputsNotModifiable,
    /// The PSBT's outputs modifiable flag is not set.
    OutputsNotModifiable,
    /// A conflicting lock-time requirement was detected between inputs.
    LockTime(DetermineLockTimeError),
    /// The output violates BIP-370 or BIP-375 output rules.
    Output(output::ValidationError),
}

impl fmt::Display for ConstructError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputsNotModifiable =>
                write!(f, "PSBT does not have the inputs modifiable flag set"),
            Self::OutputsNotModifiable =>
                write!(f, "PSBT does not have the outputs modifiable flag set"),
            Self::LockTime(ref e) => write_err!(f, "lock time"; e),
            Self::Output(ref e) => write_err!(f, "output validation"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConstructError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LockTime(ref e) => Some(e),
            Self::Output(ref e) => Some(e),
            Self::InputsNotModifiable | Self::OutputsNotModifiable => None,
        }
    }
}

/// Builds a PSBT by adding inputs and outputs.
///
/// Created by [`Creator`](super::Creator) or via `Default`, a `Constructor` is where you
/// populate the PSBT with [`Input`](crate::Input)s and [`Output`](crate::Output)s one at
/// a time. As you add each input, the lock time is validated immediately.
///
/// The type parameter `T` controls which operations are available:
///
/// * [`Modifiable`]: both inputs and outputs can be added.
/// * [`InputsOnlyModifiable`]: only inputs can be added.
/// * [`OutputsOnlyModifiable`]: only outputs can be added.
///
/// When finished, call [`psbt`](Self::psbt) to extract the PSBT, or
/// [`updater`](Self::updater) to move to the next role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Constructor<T>(
    pub(crate) Psbt,
    pub(crate) absolute::LockTime,
    pub(crate) PhantomData<T>,
);

impl<T: Mod> Constructor<T> {
    /// Marks that the `Psbt` can not have any more inputs added to it.
    pub fn no_more_inputs(mut self) -> Self {
        self.0.global.tx_modifiable_flags.clear_inputs_modifiable();
        self
    }

    /// Marks that the `Psbt` can not have any more outputs added to it.
    pub fn no_more_outputs(mut self) -> Self {
        self.0.global.tx_modifiable_flags.clear_outputs_modifiable();
        self
    }

    /// Consumes the `Constructor` and returns the built [`Psbt`].
    pub fn psbt(self) -> Psbt { self.0 }

    /// Consumes the `Constructor` and returns an [`Updater`] ready for the next role.
    pub fn updater(self) -> Updater {
        let this = self.no_more_inputs().no_more_outputs();
        Updater(this.0)
    }
}

impl Constructor<Modifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, ConstructError> {
        if !psbt.global.tx_modifiable_flags.is_inputs_modifiable() {
            return Err(ConstructError::InputsNotModifiable);
        }
        if !psbt.global.tx_modifiable_flags.is_outputs_modifiable() {
            return Err(ConstructError::OutputsNotModifiable);
        }
        let lock_time = psbt.determine_lock_time().map_err(ConstructError::LockTime)?;
        Ok(Self(psbt, lock_time, PhantomData))
    }

    /// Adds an input to the PSBT.
    ///
    /// # Errors
    ///
    /// Returns [`ConstructError::LockTime`] if the new input's lock-time requirement conflicts
    /// with a requirement already imposed by a previously added input.
    pub fn input(mut self, input: Input) -> Result<Self, ConstructError> {
        self.0.inputs.push(input);
        self.0.global.input_count += 1;
        self.1 = self.0.determine_lock_time().map_err(ConstructError::LockTime)?;
        Ok(self)
    }

    /// Adds an output to the PSBT.
    ///
    /// # Errors
    ///
    /// Returns [`ConstructError::Output`] if `output` breaks the BIP-370 or BIP-375 output
    /// rules; see [`Output::validate`].
    pub fn output(mut self, output: Output) -> Result<Self, ConstructError> {
        output.validate().map_err(ConstructError::Output)?;
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
    pub fn new(psbt: Psbt) -> Result<Self, ConstructError> {
        if !psbt.global.tx_modifiable_flags.is_inputs_modifiable() {
            return Err(ConstructError::InputsNotModifiable);
        }
        let lock_time = psbt.determine_lock_time().map_err(ConstructError::LockTime)?;
        Ok(Self(psbt, lock_time, PhantomData))
    }

    /// Adds an input to the PSBT.
    ///
    /// # Errors
    ///
    /// Returns [`ConstructError::LockTime`] if the new input's lock-time requirement conflicts
    /// with a requirement already imposed by a previously added input.
    pub fn input(mut self, input: Input) -> Result<Self, ConstructError> {
        self.0.inputs.push(input);
        self.0.global.input_count += 1;
        self.1 = self.0.determine_lock_time().map_err(ConstructError::LockTime)?;
        Ok(self)
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
    pub fn new(psbt: Psbt) -> Result<Self, ConstructError> {
        if !psbt.global.tx_modifiable_flags.is_outputs_modifiable() {
            return Err(ConstructError::OutputsNotModifiable);
        }
        let lock_time = psbt.determine_lock_time().map_err(ConstructError::LockTime)?;
        Ok(Self(psbt, lock_time, PhantomData))
    }

    /// Adds an output to the PSBT.
    ///
    /// # Errors
    ///
    /// Returns [`ConstructError::Output`] if `output` fails validation.
    pub fn output(mut self, output: Output) -> Result<Self, ConstructError> {
        output.validate().map_err(ConstructError::Output)?;
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
            .expect("lock time must be determinable")
            .input(dummy_input())
            .expect("lock time must be determinable");
        assert_eq!(constructor.0.inputs.len(), 2);
        assert_eq!(usize::from(constructor.0.global.input_count), 2);
    }
}
