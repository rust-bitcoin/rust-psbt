// SPDX-License-Identifier: CC0-1.0

//! BIP-370 roles.

mod constructor;
mod creator;

pub use constructor::{Constructor, InputsOnlyModifiable, Mod, Modifiable, OutputsOnlyModifiable};
pub use creator::Creator;
