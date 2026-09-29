// SPDX-License-Identifier: CC0-1.0

//! The BIP-370 Updater role.

use bitcoin::{Sequence, Txid};

use crate::error::{DetermineLockTimeError, IndexOutOfBoundsError};
use crate::psbt::Psbt;

/// Implements the BIP-370 Updater role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Updater(pub(crate) Psbt);

impl Updater {
    /// Creates an `Updater`.
    ///
    /// An updater can only update a PSBT that has a valid combination of lock times.
    pub fn new(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let _ = psbt.determine_lock_time()?;
        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Updater guarantees lock time can be determined")
    }

    /// Updater role, update the sequence number for input at `index`.
    pub fn set_sequence(
        mut self,
        n: Sequence,
        input_index: usize,
    ) -> Result<Self, IndexOutOfBoundsError> {
        let input = self.0.checked_input_mut(input_index)?;
        input.sequence = Some(n);
        Ok(self)
    }

    /// Returns the inner [`Psbt`].
    pub fn psbt(self) -> Psbt { self.0 }
}

impl TryFrom<Psbt> for Updater {
    type Error = DetermineLockTimeError;

    fn try_from(psbt: Psbt) -> Result<Self, Self::Error> { Self::new(psbt) }
}
