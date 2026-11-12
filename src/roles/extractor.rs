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
use crate::psbt::ResolvedPsbt;

/// Implements the BIP-370 Extractor role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Extractor(ResolvedPsbt);

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
    pub fn new(psbt: ResolvedPsbt) -> Result<Self, ExtractError> {
        if psbt.inputs.iter().any(|input| !input.is_finalized()) {
            return Err(ExtractError::PsbtNotFinalized);
        }
        #[cfg(feature = "silent-payments")]
        if let Some(index) = uncomputed_silent_payment_output(&psbt) {
            return Err(ExtractError::SilentPaymentOutputScriptNotComputed { index });
        }

        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid { self.0.id() }
}

impl Extractor {
    /// Extracts the finalized [`Transaction`] from the PSBT.
    ///
    /// Use [`extract_tx_with_fee_limit`](Self::extract_tx_with_fee_limit) to additionally
    /// verify that the transaction's fee rate is within a limit.
    pub fn extract_tx(&self) -> Transaction { self.internal_extract_tx() }

    /// Extracts the finalized [`Transaction`] from the PSBT and verifies that
    /// its fee rate does not exceed `max_fee_rate`.
    ///
    /// The fee rate check guards against accidentally extracting a transaction with an
    /// absurdly high fee.
    pub fn extract_tx_with_fee_limit(
        &self,
        max_fee_rate: FeeRate,
    ) -> Result<Transaction, ExtractError> {
        let tx = self.internal_extract_tx();
        let fee = self.0.fee().map_err(ExtractError::Fee)?;
        let fee_rate =
            FeeRate::from_sat_per_kwu(fee.to_sat().saturating_mul(1000) / tx.weight().to_wu());
        if fee_rate > max_fee_rate {
            return Err(ExtractError::FeeTooHigh { fee: fee_rate, max: max_fee_rate });
        }
        Ok(tx)
    }

    /// Builds the finalized transaction from the PSBT.
    ///
    /// This is infallible because [`Self::new`] guarantees the PSBT is finalized, the lock time
    /// has been resolved, and any silent payment output scripts are computed.
    #[inline]
    fn internal_extract_tx(&self) -> Transaction {
        let lock_time = self.0.lock_time();

        Transaction {
            version: self.0.global.tx_version,
            lock_time,
            input: self.0.inputs.iter().map(|input| input.signed_tx_in()).collect(),
            output: self.0.outputs.iter().map(|ouput| ouput.tx_out()).collect(),
        }
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
fn uncomputed_silent_payment_output(psbt: &crate::psbt::Psbt) -> Option<usize> {
    psbt.outputs
        .iter()
        .position(|output| output.sp_v0_info.is_some() && output.script_pubkey.is_empty())
}

/// Error constructing an [`Extractor`] or extracting a transaction from a PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtractError {
    /// Attempted to construct an extractor from an unfinalized PSBT.
    PsbtNotFinalized,
    /// A silent payment output still has no computed output script.
    #[cfg(feature = "silent-payments")]
    SilentPaymentOutputScriptNotComputed {
        /// Index of the offending output.
        index: usize,
    },
    /// Error calculating the fee.
    Fee(FeeError),
    /// The calculated fee rate exceeds the maximum.
    FeeTooHigh {
        /// Calculated fee rate.
        fee: FeeRate,
        /// Maximum allowable fee rate.
        max: FeeRate,
    },
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PsbtNotFinalized => write!(f, "attempted to extract tx from an unfinalized PSBT"),
            #[cfg(feature = "silent-payments")]
            Self::SilentPaymentOutputScriptNotComputed { index } =>
                write!(f, "silent payment output {} has no computed output script", index),
            Self::Fee(ref e) => write_err!(f, "fee calculation"; e),
            Self::FeeTooHigh { fee, max } => write!(f, "fee {} is greater than max {}", fee, max),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ExtractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fee(ref e) => Some(e),
            Self::PsbtNotFinalized => None,
            #[cfg(feature = "silent-payments")]
            Self::SilentPaymentOutputScriptNotComputed { .. } => None,
            Self::FeeTooHigh { .. } => None,
        }
    }
}

#[cfg(test)]
#[cfg(feature = "silent-payments")]
mod tests {
    use alloc::vec;

    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, CompressedPublicKey, OutPoint, ScriptBuf, TxOut, Txid, Witness};

    use super::*;
    use crate::psbt::Psbt;
    use crate::{Count, Global, Input, Output};

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
            global: Global {
                input_count: Count::from(1),
                output_count: Count::from(1),
                ..Global::default()
            },
            inputs: vec![finalized_input()],
            outputs: vec![output],
        }
    }

    #[test]
    fn extractor_rejects_uncomputed_silent_payment_output_script() {
        let psbt = psbt_with(sp_output(ScriptBuf::new()));

        match Extractor::new(psbt.try_resolve().unwrap()) {
            Err(ExtractError::SilentPaymentOutputScriptNotComputed { index }) =>
                assert_eq!(index, 0),
            other =>
                panic!("expected SilentPaymentOutputScriptNotComputed, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn extractor_accepts_computed_silent_payment_output_script() {
        let script = ScriptBuf::from_hex(
            "51201111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("failed to parse script from hex");
        let psbt = psbt_with(sp_output(script.clone()));

        let tx = Extractor::new(psbt.try_resolve().unwrap())
            .expect("extractor must accept a computed silent payment output")
            .extract_tx();

        assert_eq!(tx.output[0].script_pubkey, script);
    }
}

#[cfg(test)]
mod fee_rate_tests {
    use alloc::vec;

    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, TxOut, Txid, Witness};

    use super::{ExtractError, Extractor};
    use crate::psbt::Psbt;
    use crate::{Count, Global, Input, Output};

    fn finalized_input() -> Input {
        let mut input = Input::new(&OutPoint { txid: Txid::all_zeros(), vout: 0 });
        input.witness_utxo =
            Some(TxOut { value: Amount::from_sat(50_000), script_pubkey: ScriptBuf::new() });
        let mut witness = Witness::new();
        witness.push(vec![0x01; 64]);
        input.final_script_witness = Some(witness);
        input
    }

    fn plain_output() -> Output {
        Output::new(TxOut { value: Amount::from_sat(40_000), script_pubkey: ScriptBuf::new() })
    }

    fn psbt_with(output: Output) -> Psbt {
        Psbt {
            global: Global {
                input_count: Count::from(1),
                output_count: Count::from(1),
                ..Global::default()
            },
            inputs: vec![finalized_input()],
            outputs: vec![output],
        }
    }

    // Fee is 50_000 - 40_000 = 10_000 sats. The fee rate is computed independently here using the
    // correct formula; mutants that change the `/` operator or the `>` comparison in
    // `extract_tx` produce a different value or control flow.
    #[test]
    fn fee_rate_above_limit_errors() {
        let extractor = Extractor::new(psbt_with(plain_output()).try_resolve().unwrap())
            .expect("finalized psbt");
        let tx = extractor.extract_tx();
        let rate = 10_000_u64.saturating_mul(1000) / tx.weight().to_wu();
        let max = FeeRate::from_sat_per_kwu(rate - 1);

        match extractor.extract_tx_with_fee_limit(max) {
            Err(ExtractError::FeeTooHigh { fee, max: m }) => {
                assert_eq!(fee, FeeRate::from_sat_per_kwu(rate));
                assert_eq!(m, max);
            }
            other => panic!("expected FeeTooHigh, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn fee_rate_equal_to_limit_is_ok() {
        let extractor = Extractor::new(psbt_with(plain_output()).try_resolve().unwrap())
            .expect("finalized psbt");
        let tx = extractor.extract_tx();
        let rate = 10_000_u64.saturating_mul(1000) / tx.weight().to_wu();

        assert!(extractor.extract_tx_with_fee_limit(FeeRate::from_sat_per_kwu(rate)).is_ok());
    }
}
