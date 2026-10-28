// SPDX-License-Identifier: CC0-1.0

//! BIP-370 roles.

mod constructor;
mod creator;
mod extractor;
#[cfg(feature = "miniscript")]
mod finalizer;
mod signer;
mod updater;

pub use constructor::{Constructor, InputsOnlyModifiable, Mod, Modifiable, OutputsOnlyModifiable};
pub use creator::Creator;
pub use extractor::{ExtractError, ExtractTxError, ExtractTxFeeRateError, Extractor};
#[cfg(feature = "miniscript")]
pub use finalizer::{
    FinalizeError, FinalizeInputError, Finalizer, InputError, InterpreterCheckError,
    InterpreterCheckInputError,
};
pub use signer::{
    sign_all, sign_all_unchecked, sign_input, sign_input_unchecked, AllSignableInputs, GetKey,
    GetKeyError, InputSigs, KeyRequest, SignableInput, Signer, SigningErrors, SigningKeys,
    SigningSession,
};
pub use updater::{Updater, UpdaterGlobalView, UpdaterView};
