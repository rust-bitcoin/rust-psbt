// SPDX-License-Identifier: CC0-1.0

//! PSBT Version 2.
//!
//! A second version of the Partially Signed Bitcoin Transaction format and described in [BIP-174].
//!
//! Allows for inputs and outputs to be added to the PSBT after creation.
//!
//! # Roles
//!
//! BIP-174 describes various roles, these are implemented in this module as follows:
//!
//! - The **Creator** role Use the [`Creator`] type - or if creator and constructor are a single entity just use the `Constructor`.
//! - The **Constructor**: Use the [`Constructor`] type.
//! - The **Updater** role: Use the [`Updater`] type and then update additional fields of the [`Psbt`] directly.
//! - The **Signer** role: Use the [`Signer`] type.
//! - The **Finalizer** role: Use the [`Finalizer`] type (requires "miniscript" feature).
//! - The **Extractor** role: Use the [`Extractor`](crate::Extractor) type.
//!
//! To combine PSBTs use either `psbt.combine_with(other)` or `v2::combine(this, that)`.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use bitcoin::hex::DisplayHex;
use bitcoin::locktime::absolute;
#[cfg(feature = "miniscript")]
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{Amount, Sequence, Transaction, TxOut, Txid};
use bitcoin_consensus_encoding::{ArrayDecoder, ArrayEncoder, Decoder, DecoderStatus, Encoder4};

#[cfg(feature = "base64")]
pub use self::display_from_str::ParsePsbtError;
use crate::encoding::{encode_to_vec, PsbtDecode, PsbtEncode};
use crate::error::{
    write_err, DeserializeError, DetermineLockTimeError, FeeError, FundingUtxoError,
    IndexOutOfBoundsError,
};
use crate::global::{self, Global};
use crate::input::{self, Input};
use crate::output::{self, Output};
#[cfg(feature = "miniscript")]
use crate::PartialSigsSighashTypeError;
use crate::PsbtSighashType;

/// The magic bytes that identify a PSBT (`"psbt"` in ASCII).
pub(crate) const PSBT_MAGIC: &[u8; 4] = b"psbt";
/// The byte that separates the magic bytes from the global map (`0xff`).
pub(crate) const PSBT_SEPARATOR: u8 = 0xff;

/// The PSBT magic header, `b"psbt\xff"`, 4-byte ASCII identifier `"psbt"`
/// followed by the `0xff` separator that marks the start of the global map.
pub(crate) const PSBT_MAGIC_BYTES: [u8; 5] = [b'p', b's', b'b', b't', 0xff];

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for the [`PSBT_MAGIC_BYTES`].
    pub(crate) struct MagicEncoder<'e>(ArrayEncoder<5>);
}

bitcoin_consensus_encoding::encoder_newtype! {
    /// Encoder for a complete PSBT v2.
    pub struct PsbtV2Encoder<'e>(
        Encoder4<
            MagicEncoder<'e>,
            global::GlobalMapEncoder<'e>,
            crate::encoding::SliceEncoder<'e, Input>,
            crate::encoding::SliceEncoder<'e, Output>,
        >
    );
}

impl PsbtEncode for Psbt {
    type Encoder<'e> = PsbtV2Encoder<'e>;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        // `<psbt> := <magic> <global-map> <input-map>* <output-map>*`
        PsbtV2Encoder::new(Encoder4::new(
            MagicEncoder::new(ArrayEncoder::without_length_prefix(PSBT_MAGIC_BYTES)),
            self.global.psbt_encoder(),
            crate::encoding::SliceEncoder::without_length_prefix(&self.inputs),
            crate::encoding::SliceEncoder::without_length_prefix(&self.outputs),
        ))
    }
}

/// Decoder for PSBT v2.
#[derive(Debug)]
pub struct PsbtV2Decoder {
    stage: DecoderStage,
}

/// The state of the PSBT v2 decoder.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum DecoderStage {
    /// Decoding the magic bytes (`"psbt"`).
    Magic(ArrayDecoder<4>),
    /// Decoding the separator (`0xff`).
    Separator,
    /// Decoding the global map.
    Global(global::GlobalDecoder),
    /// Decoding the input maps.
    Inputs(Global, input::InputsDecoder),
    /// Decoding the output maps.
    Outputs(Global, Vec<Input>, output::OutputsDecoder),
    /// Done decoding the [`Psbt`].
    Done(Psbt),
    /// Sentinel used during state transitions.
    Errored,
}

impl Decoder for PsbtV2Decoder {
    type Output = Psbt;
    type Error = DeserializeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        loop {
            // Attempt to push bytes into the active decoder, return on success (more bytes required).
            match &mut self.stage {
                DecoderStage::Magic(decoder) => match decoder.push_bytes(bytes) {
                    Ok(status) if status.needs_more() => return Ok(DecoderStatus::NeedsMore),
                    Ok(_) => {}
                    Err(_) => unreachable!("ArrayDecoder never panics in push_bytes"),
                },
                DecoderStage::Separator =>
                    if bytes.is_empty() {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                DecoderStage::Global(decoder) =>
                    if decoder
                        .push_bytes(bytes)
                        .map_err(DeserializeError::DecodeGlobal)?
                        .needs_more()
                    {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                DecoderStage::Inputs(_, decoder) =>
                    if decoder
                        .push_bytes(bytes)
                        .map_err(DeserializeError::DecodeInputs)?
                        .needs_more()
                    {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                DecoderStage::Outputs(_, _, decoder) =>
                    if decoder
                        .push_bytes(bytes)
                        .map_err(DeserializeError::DecodeOutputs)?
                        .needs_more()
                    {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                DecoderStage::Done(_) => return Ok(DecoderStatus::Ready),
                DecoderStage::Errored => {
                    panic!("call to push_bytes() after decoder errored")
                }
            }

            // If the above failed, end the current decoder and go to the next state.
            match core::mem::replace(&mut self.stage, DecoderStage::Errored) {
                DecoderStage::Magic(decoder) => {
                    let magic = decoder.end().expect("magic ready after push_bytes");
                    if magic != *PSBT_MAGIC {
                        return Err(DeserializeError::InvalidMagic(magic));
                    }
                    self.stage = DecoderStage::Separator;
                }
                DecoderStage::Separator => {
                    let sep = bytes[0];
                    *bytes = &bytes[1..];
                    if sep != PSBT_SEPARATOR {
                        return Err(DeserializeError::InvalidSeparator(sep));
                    }
                    self.stage = DecoderStage::Global(global::GlobalDecoder::default());
                }
                DecoderStage::Global(decoder) => {
                    let global = decoder.end().map_err(DeserializeError::DecodeGlobal)?;
                    let input_count = global.input_count;
                    self.stage =
                        DecoderStage::Inputs(global, input::InputsDecoder::new(input_count));
                }
                DecoderStage::Inputs(global, decoder) => {
                    let inputs = decoder.end().map_err(DeserializeError::DecodeInputs)?;
                    let output_count = global.output_count;
                    self.stage = DecoderStage::Outputs(
                        global,
                        inputs,
                        output::OutputsDecoder::new(output_count),
                    );
                }
                DecoderStage::Outputs(global, inputs, decoder) => {
                    let outputs = decoder.end().map_err(DeserializeError::DecodeOutputs)?;
                    self.stage = DecoderStage::Done(Psbt { global, inputs, outputs });
                }
                DecoderStage::Done(..) => return Ok(DecoderStatus::Ready),
                DecoderStage::Errored => unreachable!("checked above"),
            }
        }
    }

    fn end(self) -> Result<Psbt, Self::Error> {
        match self.stage {
            DecoderStage::Done(psbt) => Ok(psbt),
            DecoderStage::Magic(_) => Err(DeserializeError::EarlyEnd("magic")),
            DecoderStage::Separator => Err(DeserializeError::EarlyEnd("separator")),
            DecoderStage::Global(_) => Err(DeserializeError::EarlyEnd("global")),
            DecoderStage::Inputs(..) => Err(DeserializeError::EarlyEnd("inputs")),
            DecoderStage::Outputs(..) => Err(DeserializeError::EarlyEnd("outputs")),
            DecoderStage::Errored => panic!("PsbtV2Decoder ended in Errored state"),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            DecoderStage::Magic(magic) => magic.read_limit(),
            DecoderStage::Separator => 1,
            DecoderStage::Global(dec) => dec.read_limit(),
            DecoderStage::Inputs(_, dec) => dec.read_limit(),
            DecoderStage::Outputs(_, _, dec) => dec.read_limit(),
            DecoderStage::Done(_) | DecoderStage::Errored => 0,
        }
    }
}

impl Default for PsbtV2Decoder {
    fn default() -> Self { Self { stage: DecoderStage::Magic(ArrayDecoder::default()) } }
}

impl PsbtDecode for Psbt {
    type Decoder = PsbtV2Decoder;
}

/// This function is commutative `combine(this, that) = combine(that, this)`.
pub fn combine(this: Psbt, that: Psbt) -> Result<Psbt, CombineError> { this.combine_with(that) }

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Psbt {
    /// The global map.
    pub global: Global,
    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<Output>,
}

impl Psbt {
    // TODO: Add inherent methods to get each of the role types.

    /// Returns this PSBT's unique identification.
    pub(crate) fn id(&self) -> Result<Txid, DetermineLockTimeError> {
        let mut tx = self.unsigned_tx()?;
        // Updaters may change the sequence so to calculate ID we set it to zero.
        tx.input.iter_mut().for_each(|input| input.sequence = Sequence::ZERO);
        tx.output = self.outputs.iter().map(|output| output.id_tx_out()).collect();

        Ok(tx.compute_txid())
    }

    /// Creates an unsigned transaction from the inner [`Psbt`].
    ///
    /// Quidado! this transaction should not be used to determine the ID of
    /// the [`Pbst`], use `Self::id()` instead.
    pub(crate) fn unsigned_tx(&self) -> Result<Transaction, DetermineLockTimeError> {
        let lock_time = self.determine_lock_time()?;

        Ok(Transaction {
            version: self.global.tx_version,
            lock_time,
            input: self.inputs.iter().map(|input| input.unsigned_tx_in()).collect(),
            output: self.outputs.iter().map(|ouput| ouput.tx_out()).collect(),
        })
    }

    /// Determines the lock time as specified in [BIP-370] if it is possible to do so.
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time>
    pub fn determine_lock_time(&self) -> Result<absolute::LockTime, DetermineLockTimeError> {
        let require_time_based_lock_time =
            self.inputs.iter().any(|input| input.requires_time_based_lock_time());
        let require_height_based_lock_time =
            self.inputs.iter().any(|input| input.requires_height_based_lock_time());

        if require_time_based_lock_time && require_height_based_lock_time {
            return Err(DetermineLockTimeError);
        }

        let have_lock_time = self.inputs.iter().any(|input| input.has_lock_time());

        let lock = if have_lock_time {
            let all_inputs_satisfied_with_height_based_lock_time =
                self.inputs.iter().all(|input| input.is_satisfied_with_height_based_lock_time());

            // > The lock time chosen is then the maximum value of the chosen type of lock time.
            if all_inputs_satisfied_with_height_based_lock_time {
                // We either have only height based or we have both, in which case we must use height based.
                let height = self
                    .inputs
                    .iter()
                    .map(|input| input.min_height)
                    .max()
                    .expect("we know we have at least one non-none min_height field")
                    .expect("so we know that max is non-none");
                absolute::LockTime::from(height)
            } else {
                let time = self
                    .inputs
                    .iter()
                    .map(|input| input.min_time)
                    .max()
                    .expect("we know we have at least one non-none min_height field")
                    .expect("so we know that max is non-none");
                absolute::LockTime::from(time)
            }
        } else {
            // > If none of the inputs have a PSBT_IN_REQUIRED_TIME_LOCKTIME and
            // > PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, then PSBT_GLOBAL_FALLBACK_LOCKTIME must be used.
            // > If PSBT_GLOBAL_FALLBACK_LOCKTIME is not provided, then it is assumed to be 0.
            self.global.fallback_lock_time.unwrap_or(absolute::LockTime::ZERO)
        };

        Ok(lock)
    }

    /// Returns true if all inputs for this PSBT have been finalized.
    pub fn is_finalized(&self) -> bool { self.inputs.iter().all(|input| input.is_finalized()) }

    /// Serializes a value as bytes in hex.
    pub fn serialize_hex(&self) -> String { self.serialize().to_lower_hex_string() }

    /// Serializes as raw binary data
    pub fn serialize(&self) -> Vec<u8> { encode_to_vec(self) }

    /// Deserializes a value from raw binary data.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        let mut remaining = bytes;
        crate::encoding::decode_from_slice_unbounded::<Self>(&mut remaining)
    }

    /// Returns an iterator for the funding UTXOs of the psbt
    ///
    /// For each PSBT input that contains UTXO information `Ok` is returned containing that information.
    /// The order of returned items is same as the order of inputs.
    ///
    /// ## Errors
    ///
    /// The function returns error when UTXO information is not present or is invalid.
    pub fn iter_funding_utxos(&self) -> impl Iterator<Item = Result<&TxOut, FundingUtxoError>> {
        self.inputs.iter().map(|input| input.funding_utxo())
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP-174.
    ///
    /// BIP-370 does not include any additional requirements for the Combiner role.
    ///
    /// This function is commutative `A.combine_with(B) = B.combine_with(A)`.
    ///
    /// See [`combine()`] for a non-consuming version of this function.
    pub fn combine_with(mut self, other: Self) -> Result<Self, CombineError> {
        self.global.combine(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs) {
            self_input.combine(other_input)?;
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs) {
            self_output.combine(other_output)?;
        }

        Ok(self)
    }

    /// Sets the PSBT_GLOBAL_TX_MODIFIABLE as required after signing.
    pub(crate) fn clear_tx_modifiable(&mut self, sighash_type: PsbtSighashType) {
        // If the Signer added a signature that does not use SIGHASH_ANYONECANPAY,
        // the Input Modifiable flag must be set to False.
        if !sighash_type.is_anyone_can_pay() {
            self.global.clear_inputs_modifiable_flag();
        }

        // If the Signer added a signature that does not use SIGHASH_NONE,
        // the Outputs Modifiable flag must be set to False.
        if !sighash_type.is_none() {
            self.global.clear_outputs_modifiable_flag();
        }

        // If the Signer added a signature that uses SIGHASH_SINGLE,
        // the Has SIGHASH_SINGLE flag must be set to True.
        if sighash_type.is_single() {
            self.global.set_sighash_single_flag();
        }
    }

    /// Gets a mutable reference to the input at `input_index` after checking that it is a valid index.
    pub(crate) fn checked_input_mut(
        &mut self,
        index: usize,
    ) -> Result<&mut Input, IndexOutOfBoundsError> {
        self.checked_input(index)?;
        Ok(&mut self.inputs[index])
    }

    /// Gets a reference to the input at `index` after checking that it is a valid index.
    pub(crate) fn checked_input(&self, index: usize) -> Result<&Input, IndexOutOfBoundsError> {
        if index >= self.inputs.len() {
            return Err(IndexOutOfBoundsError::Inputs { index, length: self.inputs.len() });
        }
        if index >= self.global.input_count {
            return Err(IndexOutOfBoundsError::Count { index, count: self.global.input_count });
        }
        Ok(&self.inputs[index])
    }

    /// Calculates transaction fee.
    ///
    /// 'Fee' being the amount that will be paid for mining a transaction with the current inputs
    /// and outputs i.e., the difference in value of the total inputs and the total outputs.
    pub fn fee(&self) -> Result<Amount, FeeError> {
        // For the inputs we have to get the value from the input UTXOs.
        let mut input_value: u64 = 0;
        for input in self.iter_funding_utxos() {
            input_value =
                input_value.checked_add(input?.value.to_sat()).ok_or(FeeError::InputOverflow)?;
        }
        // For the outputs we have the value directly in the `Output`.
        let mut output_value: u64 = 0;
        for output in &self.outputs {
            output_value =
                output_value.checked_add(output.amount.to_sat()).ok_or(FeeError::OutputOverflow)?;
        }

        input_value.checked_sub(output_value).map(Amount::from_sat).ok_or(FeeError::Negative)
    }

    /// Checks the sighash types of input partial sigs (ECDSA).
    ///
    /// This can be used at anytime but is primarily used during PSBT finalizing.
    #[cfg(feature = "miniscript")]
    pub(crate) fn check_partial_sigs_sighash_type(
        &self,
    ) -> Result<(), PartialSigsSighashTypeError> {
        for (input_index, input) in self.inputs.iter().enumerate() {
            let target_ecdsa_sighash_ty = match input.sighash_type {
                Some(psbt_hash_ty) => psbt_hash_ty.ecdsa_hash_ty().map_err(|error| {
                    PartialSigsSighashTypeError::NonStandardInputSighashType { input_index, error }
                })?,
                None => EcdsaSighashType::All,
            };

            for (key, ecdsa_sig) in &input.partial_sigs {
                let flag = EcdsaSighashType::from_standard(ecdsa_sig.sighash_type as u32).map_err(
                    |error| PartialSigsSighashTypeError::NonStandardPartialSigsSighashType {
                        input_index,
                        error,
                    },
                )?;
                if target_ecdsa_sighash_ty != flag {
                    return Err(PartialSigsSighashTypeError::WrongSighashFlag {
                        input_index,
                        required: target_ecdsa_sighash_ty,
                        got: flag,
                        pubkey: *key,
                    });
                }
            }
        }
        Ok(())
    }
}

/// The various output types supported by the Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OutputType {
    /// An output of type: pay-to-pubkey or pay-to-pubkey-hash.
    Bare,
    /// A pay-to-witness-pubkey-hash output (P2WPKH).
    Wpkh,
    /// A pay-to-witness-script-hash output (P2WSH).
    Wsh,
    /// A nested segwit output, pay-to-witness-pubkey-hash nested in a pay-to-script-hash.
    ShWpkh,
    /// A nested segwit output, pay-to-witness-script-hash nested in a pay-to-script-hash.
    ShWsh,
    /// A pay-to-script-hash output excluding wrapped segwit (P2SH).
    Sh,
    /// A taproot output (P2TR).
    Tr,
}

impl OutputType {
    /// The signing algorithm used to sign this output type.
    pub fn signing_algorithm(&self) -> SigningAlgorithm {
        match self {
            Self::Bare | Self::Wpkh | Self::Wsh | Self::ShWpkh | Self::ShWsh | Self::Sh =>
                SigningAlgorithm::Ecdsa,
            Self::Tr => SigningAlgorithm::Schnorr,
        }
    }
}

/// Signing algorithms supported by the Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningAlgorithm {
    /// The Elliptic Curve Digital Signature Algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    Ecdsa,
    /// The Schnorr signature algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Schnorr_signature
    Schnorr,
}

/// If the "base64" feature is enabled we implement `Display` and `FromStr` using base64 encoding.
#[cfg(feature = "base64")]
mod display_from_str {
    use core::fmt;
    use core::str::FromStr;

    use bitcoin::base64::display::Base64Display;
    use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};

    use super::*;

    impl fmt::Display for Psbt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", Base64Display::new(&self.serialize(), &BASE64_STANDARD))
        }
    }

    impl FromStr for Psbt {
        type Err = ParsePsbtError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let data = BASE64_STANDARD.decode(s).map_err(ParsePsbtError::Base64Encoding)?;
            Self::deserialize(&data).map_err(ParsePsbtError::PsbtEncoding)
        }
    }

    /// Error encountered during PSBT decoding from Base64 string.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum ParsePsbtError {
        /// Error in internal PSBT data structure.
        PsbtEncoding(DeserializeError),
        /// Error in PSBT Base64 encoding.
        Base64Encoding(bitcoin::base64::DecodeError),
    }

    impl fmt::Display for ParsePsbtError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::PsbtEncoding(ref e) =>
                    write_err!(f, "error in internal PSBT data structure"; e),
                Self::Base64Encoding(ref e) => write_err!(f, "error in PSBT base64 encoding"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParsePsbtError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::PsbtEncoding(e) => Some(e),
                Self::Base64Encoding(e) => Some(e),
            }
        }
    }
}

/// Error combining two input maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// Error while combining the global maps.
    Global(global::CombineError),
    /// Error while combining the input maps.
    Input(input::CombineError),
    /// Error while combining the output maps.
    Output(output::CombineError),
}

impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global(ref e) => write_err!(f, "error while combining the global maps"; e),
            Self::Input(ref e) => write_err!(f, "error while combining the input maps"; e),
            Self::Output(ref e) => write_err!(f, "error while combining the output maps"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Global(ref e) => Some(e),
            Self::Input(ref e) => Some(e),
            Self::Output(ref e) => Some(e),
        }
    }
}

impl From<global::CombineError> for CombineError {
    fn from(e: global::CombineError) -> Self { Self::Global(e) }
}

impl From<input::CombineError> for CombineError {
    fn from(e: input::CombineError) -> Self { Self::Input(e) }
}

impl From<output::CombineError> for CombineError {
    fn from(e: output::CombineError) -> Self { Self::Output(e) }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use ::bitcoin::OutPoint;
    use bitcoin::sighash::EcdsaSighashType;
    use bitcoin::ScriptBuf;

    use super::*;
    use crate::roles::{Constructor, Creator, Modifiable, OutputsOnlyModifiable, Signer};
    use crate::PsbtSighashType;

    fn single_input_psbt() -> Psbt {
        Psbt {
            global: Global { input_count: 1, output_count: 1, ..Global::default() },
            inputs: vec![Input::new(&OutPoint::null())],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            })],
        }
    }

    fn valid_psbt() -> Psbt {
        use crate::bitcoin::hashes::Hash as _;

        Psbt {
            global: Global { input_count: 1, output_count: 1, ..Global::default() },
            inputs: vec![Input::new(&OutPoint {
                txid: Txid::hash(b"some arbitrary bytes"),
                vout: 0x15,
            })],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_hex(
                    "76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac",
                )
                .unwrap(),
            })],
        }
    }

    #[test]
    fn encode_nonempty() {
        let psbt = single_input_psbt();
        let bytes = psbt.serialize();
        assert!(!bytes.is_empty());
        assert_eq!(&bytes[..5], b"psbt\xff", "must start with PSBT magic");
    }

    #[test]
    fn creator_psbt_roundtrip() {
        let psbt = Creator::new().inputs_modifiable().outputs_modifiable().psbt();
        let bytes = psbt.serialize();
        assert_eq!(&bytes[..5], b"psbt\xff");
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode creator PSBT");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn creator_psbt_inputs_modifiable_only_roundtrip() {
        let psbt = Creator::new().inputs_modifiable().psbt();
        let bytes = psbt.serialize();
        assert_eq!(&bytes[..5], b"psbt\xff");
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode creator PSBT");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn creator_psbt_outputs_modifiable_only_roundtrip() {
        let psbt = Creator::new().outputs_modifiable().psbt();
        let bytes = psbt.serialize();
        assert_eq!(&bytes[..5], b"psbt\xff");
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode creator PSBT");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn creator_psbt_no_flags_roundtrip() {
        let psbt = Creator::new().psbt();
        let bytes = psbt.serialize();
        assert_eq!(&bytes[..5], b"psbt\xff");
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode creator PSBT");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn deserialize_one_input_no_outputs() {
        use crate::bitcoin::hashes::Hash as _;
        let psbt = Psbt {
            global: Global { input_count: 1, output_count: 0, ..Global::default() },
            inputs: vec![Input::new(&OutPoint {
                txid: Txid::hash(b"some arbitrary bytes"),
                vout: 0x15,
            })],
            outputs: vec![],
        };
        let bytes = psbt.serialize();
        assert!(!bytes.is_empty());
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode PSBT with 1 input");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn iter_funding_utxos_yields_correct_utxo() {
        let mut psbt = single_input_psbt();
        let tx_out = TxOut { value: Amount::from_sat(5_000), script_pubkey: ScriptBuf::new() };
        psbt.inputs[0].witness_utxo = Some(tx_out.clone());

        let results: Vec<_> = psbt.iter_funding_utxos().collect();
        assert_eq!(results.len(), 1, "should yield exactly one UTXO");
        let utxo = results[0].as_ref().expect("UTXO should be present");
        assert_eq!(**utxo, tx_out, "UTXO should match what was set");
    }

    #[test]
    fn iter_funding_utxos_errors_on_missing_utxo() {
        let psbt = single_input_psbt();
        let results: Vec<_> = psbt.iter_funding_utxos().collect();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err(), "missing UTXO should produce an error");
    }

    #[test]
    fn encode_decode_roundtrip_nonempty() {
        let psbt = valid_psbt();
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("roundtrip decode failed");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn decode_partial_magic_bytes() {
        let psbt = valid_psbt();
        let bytes = psbt.serialize();
        let mut decoder = PsbtV2Decoder::default();

        // Feed 2 bytes at a time — exercises the NeedsMore path in the Magic stage.
        let mut remaining = &bytes[..];
        loop {
            let chunk_size = 2.min(remaining.len());
            let mut chunk = &remaining[..chunk_size];
            let status = decoder.push_bytes(&mut chunk).unwrap();
            let consumed = chunk_size - chunk.len();
            remaining = &remaining[consumed..];
            if status.is_ready() {
                break;
            }
        }
        let decoded = decoder.end().unwrap();
        assert_eq!(decoded.serialize(), bytes);
    }

    #[test]
    fn read_limit_during_incremental_decode() {
        let psbt = valid_psbt();
        let bytes = psbt.serialize();
        let mut decoder = PsbtV2Decoder::default();
        let mut remaining = &bytes[..];

        // Initial read_limit should request at least one byte.
        assert!(decoder.read_limit() > 0);

        // After feeding half the magic bytes, still needs more.
        let mut chunk = &remaining[..2];
        let status = decoder.push_bytes(&mut chunk).unwrap();
        remaining = &remaining[2 - chunk.len()..];
        assert!(status.needs_more());
        assert!(decoder.read_limit() > 0);

        // After feeding the rest, the decoder should finish.
        chunk = remaining;
        let status = decoder.push_bytes(&mut chunk).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);

        let decoded = decoder.end().unwrap();
        assert_eq!(decoded.serialize(), bytes);
    }

    fn output_with_script() -> Output {
        Output::new(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from(vec![0xab; 4]),
        })
    }

    fn output_without_script() -> Output {
        Output::new(TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() })
    }

    /// A silent payment info whose keys are 0x02 followed by `x` repeated, valid for 1 and 2.
    #[cfg(feature = "silent-payments")]
    fn sp_v0_info(x: u8) -> crate::SpV0Info {
        let mut bytes = [x; 33];
        bytes[0] = 0x02;
        let key =
            bitcoin::CompressedPublicKey::from_slice(&bytes).expect("valid compressed public key");
        crate::SpV0Info::new(key, key)
    }

    #[test]
    fn constructor_accepts_output_with_script() {
        let constructor = Constructor::<Modifiable>::default()
            .output(output_with_script())
            .expect("output must be valid");
        assert_eq!(constructor.0.outputs.len(), 1);
        assert_eq!(constructor.0.global.output_count, 1);

        let constructor = Constructor::<OutputsOnlyModifiable>::default()
            .output(output_with_script())
            .expect("output must be valid");
        assert_eq!(constructor.0.outputs.len(), 1);
        assert_eq!(constructor.0.global.output_count, 1);
    }

    #[test]
    fn constructor_accepts_output_with_empty_script() {
        // BIP-370 requires `PSBT_OUT_SCRIPT` to be present, not non-empty
        assert!(
            Constructor::<Modifiable>::default().output(output_without_script()).is_ok(),
            "constructor must accept an output with an empty script pubkey"
        );
        assert!(
            Constructor::<OutputsOnlyModifiable>::default().output(output_without_script()).is_ok(),
            "constructor must accept an output with an empty script pubkey"
        );
    }

    #[test]
    fn unique_id_is_stable_across_sequence_updates() {
        // BIP-370 requires unique identification to carry a sequence of zero because Updaters
        // and Combiners may change PSBT_IN_SEQUENCE. `Psbt::id` zeroes the sequence itself, so
        // the default applied by `Input::unsigned_tx_in` cannot affect the result.
        let baseline = valid_psbt();
        assert!(baseline.inputs[0].sequence.is_none());
        let expected = baseline.id().expect("lock time must be determinable");

        for sequence in [Sequence::ZERO, Sequence::ENABLE_LOCKTIME_NO_RBF, Sequence::MAX] {
            let mut psbt = valid_psbt();
            psbt.inputs[0].sequence = Some(sequence);
            assert_eq!(psbt.id().expect("lock time must be determinable"), expected);
        }
    }

    fn id_for_output(output: Output) -> Txid {
        let mut psbt = single_input_psbt();
        psbt.outputs[0] = output;
        psbt.id().expect("lock time must be determinable")
    }

    #[test]
    fn unique_id_commits_to_non_silent_payment_script_pubkey() {
        let mut output = output_with_script();
        let original_id = id_for_output(output.clone());

        output.script_pubkey = ScriptBuf::from_hex("00140000000000000000000000000000000000000000")
            .expect("failed to parse script from hex");

        assert_ne!(id_for_output(output), original_id);
    }

    #[cfg(feature = "silent-payments")]
    fn sp_output(sp_info: crate::SpV0Info) -> Output {
        let mut output = output_without_script();
        output.sp_v0_info = Some(sp_info);
        output
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn unique_id_ignores_derived_silent_payment_script_pubkey() {
        let output_without_script = sp_output(sp_v0_info(1));

        let mut output_with_script = output_without_script.clone();
        output_with_script.script_pubkey = ScriptBuf::from_hex(
            "51201111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("failed to parse script from hex");

        assert_eq!(id_for_output(output_without_script), id_for_output(output_with_script));
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn unique_id_commits_to_silent_payment_info() {
        assert_ne!(
            id_for_output(sp_output(sp_v0_info(1))),
            id_for_output(sp_output(sp_v0_info(2)))
        );
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn constructor_accepts_underived_silent_payment_output() {
        // BIP-375: the silent payment info stands in for the script until it is derived.
        let mut output = output_without_script();
        output.sp_v0_info = Some(sp_v0_info(2));

        assert!(Constructor::<Modifiable>::default().output(output.clone()).is_ok());
        assert!(Constructor::<OutputsOnlyModifiable>::default().output(output).is_ok());
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn constructor_rejects_silent_payment_label_without_info() {
        let mut output = output_with_script();
        output.sp_v0_label = Some(0);

        assert_eq!(
            Constructor::<Modifiable>::default().output(output).err(),
            Some(output::ValidationError::LabelWithoutInfo)
        );
    }

    /// BIP-375 represents an underived silent payment output by omitting `PSBT_OUT_SCRIPT`,
    /// so a PSBT that arrives without the field has to leave without it too. Writing it back
    /// empty is a PSBT other implementations reject.
    #[cfg(feature = "silent-payments")]
    #[test]
    fn underived_silent_payment_output_round_trips_without_out_script() {
        use ::bitcoin::hashes::Hash as _;

        use crate::consts::PSBT_OUT_SCRIPT;

        let mut output = output_without_script();
        output.sp_v0_info = Some(sp_v0_info(2));

        let mut psbt = single_input_psbt();
        // An all-zeros txid and a zero output index are the "not set yet" sentinels, so a
        // null outpoint does not survive a decode.
        psbt.inputs[0] = Input::new(&OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 1 });
        psbt.outputs = vec![output];

        let encoded = psbt.serialize();
        let decoded = Psbt::deserialize(&encoded).expect("psbt must decode");

        assert!(decoded.outputs[0].script_pubkey.is_empty());

        // A decoded Output cannot tell a missing PSBT_OUT_SCRIPT from an empty one, so inspect
        // the encoded key-value pairs directly.

        let output_encoded = encode_to_vec(&decoded.outputs[0]);
        let mut slice = &output_encoded[..];

        loop {
            use crate::map::error::KeyDecodeError;
            use crate::map::KeyDecoder;

            // Decode key.
            let mut key_decoder = KeyDecoder::default();
            key_decoder.push_bytes(&mut slice).expect("key push_bytes failed");
            let key = match key_decoder.end() {
                Err(KeyDecodeError::Empty) => break,
                Err(e) => panic!("key decode failed: {:?}", e),
                Ok(key) => key,
            };

            assert_ne!(
                key.type_value, PSBT_OUT_SCRIPT,
                "underived silent payment output must not encode PSBT_OUT_SCRIPT"
            );
        }

        assert_eq!(decoded.serialize(), encoded);
    }

    #[test]
    fn clear_tx_modifiable_all_clears_modifiable_flags() {
        let mut psbt = single_input_psbt();
        psbt.global.set_inputs_modifiable_flag();
        psbt.global.set_outputs_modifiable_flag();

        // SIGHASH_ALL: not ANYONECANPAY, not NONE, not SINGLE.
        psbt.clear_tx_modifiable(PsbtSighashType::from(EcdsaSighashType::All));

        assert!(!psbt.global.is_inputs_modifiable());
        assert!(!psbt.global.is_outputs_modifiable());
        assert!(!psbt.global.has_sighash_single());
    }

    #[test]
    fn clear_tx_modifiable_anyone_can_pay_preserves_inputs_modifiable() {
        let mut psbt = single_input_psbt();
        psbt.global.set_inputs_modifiable_flag();

        // SIGHASH_ALL | SIGHASH_ANYONECANPAY.
        psbt.clear_tx_modifiable(PsbtSighashType::from(EcdsaSighashType::AllPlusAnyoneCanPay));

        assert!(psbt.global.is_inputs_modifiable());
    }

    #[test]
    fn clear_tx_modifiable_none_preserves_outputs_modifiable() {
        let mut psbt = single_input_psbt();
        psbt.global.set_outputs_modifiable_flag();

        // SIGHASH_NONE.
        psbt.clear_tx_modifiable(PsbtSighashType::from(EcdsaSighashType::None));

        assert!(psbt.global.is_outputs_modifiable());
    }

    #[test]
    fn clear_tx_modifiable_none_plus_acp_preserves_outputs_modifiable() {
        let mut psbt = single_input_psbt();
        psbt.global.set_outputs_modifiable_flag();

        // SIGHASH_NONE | SIGHASH_ANYONECANPAY: like plain NONE, outputs stay modifiable.
        psbt.clear_tx_modifiable(PsbtSighashType::from(EcdsaSighashType::NonePlusAnyoneCanPay));

        assert!(psbt.global.is_outputs_modifiable());
    }

    #[test]
    fn clear_tx_modifiable_single_plus_acp_sets_has_single_flag() {
        let mut psbt = single_input_psbt();

        // Plain SIGHASH_SINGLE must set the Has SIGHASH_SINGLE flag as well.
        psbt.clear_tx_modifiable(PsbtSighashType::from(EcdsaSighashType::Single));
        assert!(psbt.global.has_sighash_single());

        let mut psbt = single_input_psbt();

        // SIGHASH_SINGLE | SIGHASH_ANYONECANPAY must set the Has SIGHASH_SINGLE flag.
        psbt.clear_tx_modifiable(PsbtSighashType::from(EcdsaSighashType::SinglePlusAnyoneCanPay));

        assert!(psbt.global.has_sighash_single());
    }

    #[test]
    fn ecdsa_clear_tx_modifiable_updates_flags() {
        let mut psbt = single_input_psbt();
        psbt.global.set_inputs_modifiable_flag();
        psbt.global.set_outputs_modifiable_flag();

        let mut signer = Signer::new(psbt).expect("lock time must be determinable");
        signer.ecdsa_clear_tx_modifiable(EcdsaSighashType::All);

        let psbt = signer.psbt();
        assert!(!psbt.global.is_inputs_modifiable());
        assert!(!psbt.global.is_outputs_modifiable());
        assert!(!psbt.global.has_sighash_single());
    }
}
