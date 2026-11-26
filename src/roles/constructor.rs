// SPDX-License-Identifier: CC0-1.0

//! The BIP-370 Constructor role.

use core::fmt;
use core::marker::PhantomData;

use bitcoin::locktime::absolute;

use crate::error::{write_err, DetermineLockTimeError};
use crate::input::Input;
use crate::map::Count;
use crate::output::{self, Output};
use crate::psbt::{Psbt, ResolvedPsbt};
use crate::roles::{Creator, Updater};

/// Marker for a `Constructor` with both inputs and outputs modifiable.
#[derive(Debug)]
pub enum Modifiable {}
/// Marker for a `Constructor` with inputs modifiable.
#[derive(Debug)]
pub enum InputsOnlyModifiable {}
/// Marker for a `Constructor` with outputs modifiable.
#[derive(Debug)]
pub enum OutputsOnlyModifiable {}
/// Marker for a `Constructor` that has closed both inputs and outputs.
#[derive(Debug)]
pub enum Closed {}

mod sealed {
    pub trait Mod {}
    impl Mod for super::Modifiable {}
    impl Mod for super::InputsOnlyModifiable {}
    impl Mod for super::OutputsOnlyModifiable {}
    impl Mod for super::Closed {}
}

/// Marker for the set of operations a [`Constructor`] supports.
pub trait Mod: sealed::Mod + Sync + Send + Sized + Unpin {}

impl Mod for Modifiable {}
impl Mod for InputsOnlyModifiable {}
impl Mod for OutputsOnlyModifiable {}
impl Mod for Closed {}

/// Error occurring in the [`Constructor`] role.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConstructError {
    /// The PSBT's inputs modifiable flag is not set.
    InputsNotModifiable,
    /// The PSBT's outputs modifiable flag is not set.
    OutputsNotModifiable,
    /// The declared input count does not match the number of input maps.
    InputCountMismatch {
        /// The value of the `PSBT_GLOBAL_INPUT_COUNT` field.
        declared: usize,
        /// The actual number of input maps in the PSBT.
        actual: usize,
    },
    /// The declared output count does not match the number of output maps.
    OutputCountMismatch {
        /// The value of the `PSBT_GLOBAL_OUTPUT_COUNT` field.
        declared: usize,
        /// The actual number of output maps in the PSBT.
        actual: usize,
    },
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
            Self::InputCountMismatch { declared, actual } => write!(
                f,
                "input count mismatch: global declares {declared} inputs but {actual} input maps are present",
            ),
            Self::OutputCountMismatch { declared, actual } => write!(
                f,
                "output count mismatch: global declares {declared} outputs but {actual} output maps are present",
            ),
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
            Self::InputsNotModifiable
            | Self::OutputsNotModifiable
            | Self::InputCountMismatch { .. }
            | Self::OutputCountMismatch { .. } => None,
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
/// * [`Closed`]: inputs and outputs have been closed.
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
    /// Validates both declared counts match the actual maps.
    fn validate(psbt: Psbt) -> Result<(Psbt, absolute::LockTime), ConstructError> {
        let declared_inputs = usize::from(psbt.global.input_count);
        if declared_inputs != psbt.inputs.len() {
            return Err(ConstructError::InputCountMismatch {
                declared: declared_inputs,
                actual: psbt.inputs.len(),
            });
        }
        let declared_outputs = usize::from(psbt.global.output_count);
        if declared_outputs != psbt.outputs.len() {
            return Err(ConstructError::OutputCountMismatch {
                declared: declared_outputs,
                actual: psbt.outputs.len(),
            });
        }
        let lock_time = psbt.determine_lock_time().map_err(ConstructError::LockTime)?;
        Ok((psbt, lock_time))
    }

    /// Consumes the `Constructor` and returns the built [`Psbt`].
    pub fn psbt(self) -> Psbt { self.0 }

    /// Closes inputs and outputs, then returns an [`Updater`].
    pub fn updater(mut self) -> Updater {
        self.0.global.tx_modifiable_flags.clear_inputs_modifiable();
        self.0.global.tx_modifiable_flags.clear_outputs_modifiable();
        Updater(ResolvedPsbt::from_parts(self.0, self.1))
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
        let (psbt, lock_time) = Self::validate(psbt)?;
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
        self.0.global.input_count = Count::from(self.0.inputs.len());
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
        self.0.global.output_count = Count::from(self.0.outputs.len());
        Ok(self)
    }

    /// Closes inputs and transitions to [`Constructor<OutputsOnlyModifiable>`].
    pub fn no_more_inputs(mut self) -> Constructor<OutputsOnlyModifiable> {
        self.0.global.tx_modifiable_flags.clear_inputs_modifiable();
        Constructor(self.0, self.1, PhantomData)
    }

    /// Closes outputs and transitions to [`Constructor<InputsOnlyModifiable>`].
    pub fn no_more_outputs(mut self) -> Constructor<InputsOnlyModifiable> {
        self.0.global.tx_modifiable_flags.clear_outputs_modifiable();
        Constructor(self.0, self.1, PhantomData)
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
        let (psbt, lock_time) = Self::validate(psbt)?;
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
        self.0.global.input_count = Count::from(self.0.inputs.len());
        self.1 = self.0.determine_lock_time().map_err(ConstructError::LockTime)?;
        Ok(self)
    }

    /// Marks that the PSBT can not have any more inputs added to it.
    ///
    /// Closes inputs and transitions to [`Constructor<Closed>`].
    pub fn no_more_inputs(mut self) -> Constructor<Closed> {
        self.0.global.tx_modifiable_flags.clear_inputs_modifiable();
        Constructor(self.0, self.1, PhantomData)
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
        let (psbt, lock_time) = Self::validate(psbt)?;
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
        self.0.global.output_count = Count::from(self.0.outputs.len());
        Ok(self)
    }

    /// Marks that the PSBT can not have any more outputs added to it.
    ///
    /// Closes outputs and transitions to [`Constructor<Closed>`].
    pub fn no_more_outputs(mut self) -> Constructor<Closed> {
        self.0.global.tx_modifiable_flags.clear_outputs_modifiable();
        Constructor(self.0, self.1, PhantomData)
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<OutputsOnlyModifiable> {
    fn default() -> Self { Creator::new().constructor_outputs_only_modifiable() }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Txid};

    use super::*;
    use crate::input::Input;

    fn dummy_input() -> Input { Input::new(&OutPoint { txid: Txid::all_zeros(), vout: 0 }) }

    fn empty_psbt() -> Psbt {
        Psbt { global: crate::Global::default(), inputs: vec![], outputs: vec![] }
    }

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

    #[test]
    fn rejects_input_count_mismatch() {
        let mut psbt = empty_psbt();
        psbt.global.tx_modifiable_flags = crate::TxModifiableFlags::with_inputs_modifiable();
        psbt.global.input_count = Count::from(5); // declares 5, but has 0

        let err = Constructor::<InputsOnlyModifiable>::new(psbt).unwrap_err();
        assert!(
            matches!(err, ConstructError::InputCountMismatch { declared: 5, actual: 0 }),
            "expected InputCountMismatch, got {err:?}"
        );
    }

    #[test]
    fn rejects_output_count_mismatch() {
        let mut psbt = empty_psbt();
        psbt.global.tx_modifiable_flags = crate::TxModifiableFlags::with_outputs_modifiable();
        psbt.global.output_count = Count::from(3); // declares 3, but has 0

        let err = Constructor::<OutputsOnlyModifiable>::new(psbt).unwrap_err();
        assert!(
            matches!(err, ConstructError::OutputCountMismatch { declared: 3, actual: 0 }),
            "expected OutputCountMismatch, got {err:?}"
        );
    }

    #[test]
    fn inputs_only_constructor_rejects_output_count_mismatch() {
        // A corrupt output count must be caught even when only inputs are modifiable.
        let mut psbt = empty_psbt();
        psbt.global.tx_modifiable_flags = crate::TxModifiableFlags::with_inputs_modifiable();
        psbt.global.input_count = Count::from(0); // correct for 0 inputs
        psbt.global.output_count = Count::from(3); // declares 3, but has 0

        let err = Constructor::<InputsOnlyModifiable>::new(psbt).unwrap_err();
        assert!(
            matches!(err, ConstructError::OutputCountMismatch { declared: 3, actual: 0 }),
            "expected OutputCountMismatch, got {err:?}"
        );
    }

    #[test]
    fn outputs_only_constructor_rejects_input_count_mismatch() {
        // A corrupt input count must be caught even when only outputs are modifiable.
        let mut psbt = empty_psbt();
        psbt.global.tx_modifiable_flags = crate::TxModifiableFlags::with_outputs_modifiable();
        psbt.global.input_count = Count::from(5); // declares 5, but has 0
        psbt.global.output_count = Count::from(0); // correct for 0 outputs

        let err = Constructor::<OutputsOnlyModifiable>::new(psbt).unwrap_err();
        assert!(
            matches!(err, ConstructError::InputCountMismatch { declared: 5, actual: 0 }),
            "expected InputCountMismatch, got {err:?}"
        );
    }

    #[test]
    fn count_self_heals_on_input_add() {
        // A PSBT with a bogus count gets repaired when the Constructor adds an input.
        // new() rejects inconsistent PSBTs, so construct via default() then break the count.
        let constructor = Constructor::<InputsOnlyModifiable>::default();
        let mut inner = constructor.0;
        inner.global.input_count = Count::from(usize::MAX);
        let constructor = Constructor::<InputsOnlyModifiable>(inner, constructor.1, constructor.2);

        let result = constructor.input(dummy_input()).expect("lock time");
        assert_eq!(usize::from(result.0.global.input_count), 1);
        assert_eq!(result.0.inputs.len(), 1);
    }

    #[test]
    fn no_more_inputs_on_modifiable_preserves_psbt_and_clears_flag() {
        let constructor =
            Constructor::<Modifiable>::default().input(dummy_input()).expect("lock time");
        let outputs_only = constructor.no_more_inputs();

        assert_eq!(outputs_only.0.inputs.len(), 1);
        assert!(!outputs_only.0.global.tx_modifiable_flags.is_inputs_modifiable());
        assert!(outputs_only.0.global.tx_modifiable_flags.is_outputs_modifiable());
    }

    #[test]
    fn no_more_outputs_on_modifiable_preserves_psbt_and_clears_flag() {
        let constructor =
            Constructor::<Modifiable>::default().output(Output::default()).expect("output");
        let inputs_only = constructor.no_more_outputs();

        assert_eq!(inputs_only.0.outputs.len(), 1);
        assert!(!inputs_only.0.global.tx_modifiable_flags.is_outputs_modifiable());
        assert!(inputs_only.0.global.tx_modifiable_flags.is_inputs_modifiable());
    }

    #[test]
    fn no_more_inputs_on_inputs_only_clears_flag_and_closes() {
        let constructor =
            Constructor::<InputsOnlyModifiable>::default().input(dummy_input()).expect("lock time");
        let closed = constructor.no_more_inputs();

        assert!(!closed.0.global.tx_modifiable_flags.is_inputs_modifiable());
        assert!(!closed.0.global.tx_modifiable_flags.is_outputs_modifiable());
    }

    #[test]
    fn no_more_outputs_on_outputs_only_clears_flag_and_closes() {
        let constructor = Constructor::<OutputsOnlyModifiable>::default()
            .output(Output::default())
            .expect("output");
        let closed = constructor.no_more_outputs();

        assert!(!closed.0.global.tx_modifiable_flags.is_outputs_modifiable());
        assert!(!closed.0.global.tx_modifiable_flags.is_inputs_modifiable());
    }
}
