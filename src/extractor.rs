// SPDX-License-Identifier: CC0-1.0

//! Implementation of the Extractor role as defined in [BIP-174].
//!
//! # Extractor Role
//!
//! > The Transaction Extractor does not need to know how to interpret scripts in order
//! > to extract the network serialized transaction.
//!
//! It is only possible to extract a transaction from a PSBT _after_ it has been finalized. However
//! the Extractor role may be fulfilled by a separate entity to the Finalizer hence this is a
//! separate module and does not require the "miniscript" feature be enabled.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use core::fmt;

use bitcoin::{FeeRate, Transaction, Txid};

use crate::error::{write_err, FeeError};
use crate::psbt::Psbt;
use crate::DetermineLockTimeError;

/// Implements the BIP-370 Finalized role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Extractor(Psbt);

impl Extractor {
    /// Creates an `Extractor`.
    ///
    /// An extractor can only accept a PSBT that has been finalized.
    ///
    /// # Silent payments
    ///
    /// BIP-375 has the extractor derive every silent payment output script and verify it against
    /// the ECDH shares and DLEQ proofs. That needs BIP-352 output derivation and BIP-374 proof
    /// verification, which this crate does not implement, so with the `silent-payments` feature
    /// it only rejects a silent payment output whose script has not been computed.
    ///
    /// Callers must perform the full verification on the [`Psbt`] before calling this. The
    /// finalizer keeps the ECDH shares and DLEQ proofs but clears the fields that name input
    /// public keys, so those keys have to be recovered as a BIP-352 receiver does, from the
    /// spent outputs and the final scriptSig and witness.
    pub fn new(psbt: Psbt) -> Result<Self, ExtractError> {
        if psbt.inputs.iter().any(|input| !input.is_finalized()) {
            return Err(ExtractError::PsbtNotFinalized);
        }
        let _ = psbt.determine_lock_time()?;
        #[cfg(feature = "silent-payments")]
        if let Some(index) = uncomputed_silent_payment_output(&psbt) {
            return Err(ExtractError::SilentPaymentOutputScriptNotComputed { index });
        }

        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Extractor guarantees lock time can be determined")
    }
}

impl Extractor {
    /// The default `max_fee_rate` value used for extracting transactions with [`Self::extract_tx`].
    ///
    /// As of 2023, even the biggest overpayers during the highest fee markets only paid around
    /// 1000 sats/vByte. 25k sats/vByte is obviously a mistake at this point.
    pub const DEFAULT_MAX_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_u32(25_000);

    /// An alias for [`Self::extract_tx_fee_rate_limit`].
    pub fn extract_tx(&self) -> Result<Transaction, ExtractTxFeeRateError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    ///
    /// ## Errors
    ///
    /// `ExtractTxError` variants will contain either the [`Psbt`] itself or the [`Transaction`]
    /// that was extracted. These can be extracted from the Errors in order to recover.
    /// See the error documentation for info on the variants. In general, it covers large fees.
    pub fn extract_tx_fee_rate_limit(&self) -> Result<Transaction, ExtractTxFeeRateError> {
        self.internal_extract_tx_with_fee_rate_limit(Self::DEFAULT_MAX_FEE_RATE)
    }

    /// Extracts the [`Transaction`] from a [`Psbt`] by filling in the available signature information.
    pub fn extract_tx_with_fee_rate_limit(
        &self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxFeeRateError> {
        self.internal_extract_tx_with_fee_rate_limit(max_fee_rate)
    }

    /// Perform [`Self::extract_tx_fee_rate_limit`] without the fee rate check.
    ///
    /// This can result in a transaction with absurdly high fees. Use with caution.
    #[allow(clippy::result_large_err)]
    pub fn extract_tx_unchecked_fee_rate(&self) -> Result<Transaction, ExtractTxError> {
        self.internal_extract_tx()
    }

    #[inline]
    fn internal_extract_tx_with_fee_rate_limit(
        &self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractTxFeeRateError> {
        let fee = self.0.fee()?;
        let tx = self.internal_extract_tx()?;

        // Now that the extracted Transaction is made, decide how to return it.
        let fee_rate =
            FeeRate::from_sat_per_kwu(fee.to_sat().saturating_mul(1000) / tx.weight().to_wu());
        // Prefer to return an AbsurdFeeRate error when both trigger.
        if fee_rate > max_fee_rate {
            return Err(ExtractTxFeeRateError::FeeTooHigh { fee: fee_rate, max: max_fee_rate });
        }

        Ok(tx)
    }

    /// Extracts a finalized transaction from the [`Psbt`].
    ///
    /// Uses `miniscript` to do interpreter checks.
    #[inline]
    #[allow(clippy::result_large_err)]
    fn internal_extract_tx(&self) -> Result<Transaction, ExtractTxError> {
        if !self.0.is_finalized() {
            return Err(ExtractTxError::Unfinalized);
        }

        let lock_time = self.0.determine_lock_time()?;

        #[cfg(feature = "silent-payments")]
        if let Some(index) = uncomputed_silent_payment_output(&self.0) {
            return Err(ExtractTxError::SilentPaymentOutputScriptNotComputed { index });
        }

        let tx = Transaction {
            version: self.0.global.tx_version,
            lock_time,
            input: self.0.inputs.iter().map(|input| input.signed_tx_in()).collect(),
            output: self.0.outputs.iter().map(|ouput| ouput.tx_out()).collect(),
        };

        Ok(tx)
    }
}

// BIP-375: "For silent payment capable PSBTs, the transaction extractor should compute all
// output scripts for silent payment codes and verify they are correct using the ECDH shares
// and DLEQ proofs, otherwise fail."
//
// This is the part of that requirement which needs no cryptography: an output carrying
// PSBT_OUT_SP_V0_INFO must have its PSBT_OUT_SCRIPT computed, otherwise extraction would
// produce a transaction with an empty output script. See `Extractor::new` for what callers
// must verify themselves.
#[cfg(feature = "silent-payments")]
fn uncomputed_silent_payment_output(psbt: &Psbt) -> Option<usize> {
    psbt.outputs
        .iter()
        .position(|output| output.sp_v0_info.is_some() && output.script_pubkey.is_empty())
}

/// Error constructing an `Extractor`.
#[derive(Debug)]
pub enum ExtractError {
    /// Attempted to extract tx from an unfinalized PSBT.
    PsbtNotFinalized,
    /// Finalizer must be able to determine the lock time.
    DetermineLockTime(DetermineLockTimeError),
    /// A silent payment output still has no computed output script.
    #[cfg(feature = "silent-payments")]
    SilentPaymentOutputScriptNotComputed {
        /// Index of the offending output.
        index: usize,
    },
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PsbtNotFinalized => write!(f, "attempted to extract tx from an unfinalized PSBT"),
            Self::DetermineLockTime(ref e) =>
                write_err!(f, "extractor must be able to determine the lock time"; e),
            #[cfg(feature = "silent-payments")]
            Self::SilentPaymentOutputScriptNotComputed { index } =>
                write!(f, "silent payment output {} has no computed output script", index),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DetermineLockTime(ref e) => Some(e),
            Self::PsbtNotFinalized => None,
            #[cfg(feature = "silent-payments")]
            Self::SilentPaymentOutputScriptNotComputed { .. } => None,
        }
    }
}

impl From<DetermineLockTimeError> for ExtractError {
    fn from(e: DetermineLockTimeError) -> Self { Self::DetermineLockTime(e) }
}

/// Error caused by fee calculation when extracting a [`Transaction`] from a PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractTxFeeRateError {
    /// Error calculating the fee rate.
    Fee(FeeError),
    /// The calculated fee rate exceeds max.
    FeeTooHigh {
        /// Calculated fee.
        fee: FeeRate,
        /// Maximum allowable fee.
        max: FeeRate,
    },
    /// Error extracting the transaction.
    ExtractTx(ExtractTxError),
}

impl fmt::Display for ExtractTxFeeRateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fee(ref e) => write_err!(f, "fee calculation"; e),
            Self::FeeTooHigh { fee, max } => write!(f, "fee {} is greater than max {}", fee, max),
            Self::ExtractTx(ref e) => write_err!(f, "extract"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractTxFeeRateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fee(ref e) => Some(e),
            Self::ExtractTx(ref e) => Some(e),
            Self::FeeTooHigh { .. } => None,
        }
    }
}

impl From<FeeError> for ExtractTxFeeRateError {
    fn from(e: FeeError) -> Self { Self::Fee(e) }
}

impl From<ExtractTxError> for ExtractTxFeeRateError {
    fn from(e: ExtractTxError) -> Self { Self::ExtractTx(e) }
}

/// Error extracting a [`Transaction`] from a PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractTxError {
    /// Attempted to extract transaction from an unfinalized PSBT.
    Unfinalized,
    /// Failed to determine lock time.
    DetermineLockTime(DetermineLockTimeError),
    /// A silent payment output still has no computed output script.
    #[cfg(feature = "silent-payments")]
    SilentPaymentOutputScriptNotComputed {
        /// Index of the offending output.
        index: usize,
    },
}

impl fmt::Display for ExtractTxError {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result { todo!() }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractTxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { todo!() }
}

impl From<DetermineLockTimeError> for ExtractTxError {
    fn from(e: DetermineLockTimeError) -> Self { Self::DetermineLockTime(e) }
}

#[cfg(test)]
#[cfg(feature = "silent-payments")]
mod tests {
    use alloc::vec;

    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, CompressedPublicKey, OutPoint, ScriptBuf, TxOut, Txid, Witness};

    use super::*;
    use crate::{Global, Input, Output};

    fn finalized_input() -> Input {
        let mut input = Input::new(&OutPoint { txid: Txid::all_zeros(), vout: 0 });
        input.witness_utxo =
            Some(TxOut { value: Amount::from_sat(50_000), script_pubkey: ScriptBuf::new() });
        let mut witness = Witness::new();
        witness.push(vec![0x01; 64]);
        input.final_script_witness = Some(witness);
        input
    }

    fn sp_output(script_pubkey: ScriptBuf) -> Output {
        let mut output = Output::new(TxOut { value: Amount::from_sat(40_000), script_pubkey });
        let key = CompressedPublicKey::from_slice(&[2; 33]).expect("valid compressed public key");
        output.sp_v0_info = Some(crate::SpV0Info::new(key, key));
        output
    }

    fn psbt_with(output: Output) -> Psbt {
        Psbt {
            global: Global { input_count: 1, output_count: 1, ..Global::default() },
            inputs: vec![finalized_input()],
            outputs: vec![output],
        }
    }

    #[test]
    fn extractor_rejects_uncomputed_silent_payment_output_script() {
        let psbt = psbt_with(sp_output(ScriptBuf::new()));

        match Extractor::new(psbt) {
            Err(ExtractError::SilentPaymentOutputScriptNotComputed { index }) =>
                assert_eq!(index, 0),
            other =>
                panic!("expected SilentPaymentOutputScriptNotComputed, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn extract_tx_rejects_uncomputed_silent_payment_output_script() {
        // An `Extractor` deserialized through serde is built without `Extractor::new`.
        let extractor = Extractor(psbt_with(sp_output(ScriptBuf::new())));

        assert_eq!(
            extractor.extract_tx_unchecked_fee_rate(),
            Err(ExtractTxError::SilentPaymentOutputScriptNotComputed { index: 0 })
        );
    }

    #[test]
    fn extractor_accepts_computed_silent_payment_output_script() {
        let script = ScriptBuf::from_hex(
            "51201111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("failed to parse script from hex");
        let psbt = psbt_with(sp_output(script.clone()));

        let tx = Extractor::new(psbt)
            .expect("extractor must accept a computed silent payment output")
            .extract_tx_unchecked_fee_rate()
            .expect("extraction must succeed");

        assert_eq!(tx.output[0].script_pubkey, script);
    }
}
