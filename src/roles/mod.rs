// SPDX-License-Identifier: CC0-1.0

//! BIP-370 roles.

mod constructor;
mod creator;
#[cfg(feature = "miniscript")]
mod finalizer;
mod signer;
mod updater;

pub use constructor::{Constructor, InputsOnlyModifiable, Mod, Modifiable, OutputsOnlyModifiable};
pub use creator::Creator;
#[cfg(feature = "miniscript")]
pub use finalizer::{
    FinalizeError, FinalizeInputError, Finalizer, InputError, InterpreterCheckError,
    InterpreterCheckInputError,
};
pub use signer::Signer;
pub use updater::Updater;
