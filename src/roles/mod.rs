// SPDX-License-Identifier: CC0-1.0

//! BIP-370 roles.

mod constructor;
mod creator;
mod updater;

pub use constructor::{Constructor, InputsOnlyModifiable, Mod, Modifiable, OutputsOnlyModifiable};
pub use creator::Creator;
pub use updater::Updater;
