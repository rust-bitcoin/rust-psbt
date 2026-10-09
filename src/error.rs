// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::bip32::Xpub;
use bitcoin::sighash::{self, EcdsaSighashType, NonStandardSighashTypeError};
use bitcoin::{transaction, PublicKey};
use bitcoin_consensus_encoding::VecDecoderError;

/// Error while deserializing a PSBT.
///
/// This error is returned when deserializing a complete PSBT, not for deserializing parts
/// of it or individual data types.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeserializeError {
    /// Invalid magic bytes, expected the ASCII for "psbt" serialized in most significant byte order.
    InvalidMagic([u8; 4]),
    /// The separator for a PSBT must be `0xff`.
    InvalidSeparator(u8),
    /// Error decoding the global map (v0 or v2).
    DecodeGlobal(crate::map::error::GlobalDecodeError),
    /// Error decoding the input maps sequence.
    DecodeInputs(VecDecoderError<crate::map::error::InputDecodeError>),
    /// Error decoding the output maps sequence.
    DecodeOutputs(VecDecoderError<crate::map::error::OutputDecodeError>),
    /// Called `end()` before decoding finished (truncated or incomplete input).
    EarlyEnd(&'static str),
    /// Bytes remained unconsumed after completing decoding.
    Unconsumed,
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(ref magic) => write!(f, "invalid magic bytes: {:?}", magic),
            Self::InvalidSeparator(separator) => {
                write!(f, "invalid separator byte: 0x{:02x}", separator)
            }
            Self::DecodeGlobal(e) => write!(f, "error decoding global map: {}", e),
            Self::DecodeInputs(e) => write!(f, "error decoding input maps: {}", e),
            Self::DecodeOutputs(e) => write!(f, "error decoding output maps: {}", e),
            Self::EarlyEnd(s) => write!(f, "early end of PSBT (still decoding {})", s),
            Self::Unconsumed => write!(f, "unconsumed bytes after PSBT"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DecodeGlobal(e) => Some(e),
            Self::DecodeInputs(e) => Some(e),
            Self::DecodeOutputs(e) => Some(e),
            Self::InvalidMagic(_)
            | Self::InvalidSeparator(_)
            | Self::EarlyEnd(_)
            | Self::Unconsumed => None,
        }
    }
}

/// Input index out of bounds (actual index, maximum index allowed).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexOutOfBoundsError {
    /// The index is out of bounds for the `psbt.inputs` vector.
    Inputs {
        /// Attempted index access.
        index: usize,
        /// Length of the PBST inputs vector.
        length: usize,
    },
    /// The index greater than the `psbt.global.input_count`.
    Count {
        /// Attempted index access.
        index: usize,
        /// Global input count.
        count: usize,
    },
}

impl fmt::Display for IndexOutOfBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inputs { ref index, ref length } => write!(
                f,
                "index {} is out-of-bounds for PSBT inputs vector length {}",
                index, length
            ),
            Self::Count { ref index, ref count } =>
                write!(f, "index {} is greater global.input_count {}", index, count),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IndexOutOfBoundsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inputs { .. } | Self::Count { .. } => None,
        }
    }
}

/// Errors encountered while calculating the sighash message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// Input index out of bounds.
    IndexOutOfBounds(IndexOutOfBoundsError),
    /// Invalid Sighash type.
    InvalidSighashType,
    /// Missing input utxo.
    MissingInputUtxo,
    /// Missing Redeem script.
    MissingRedeemScript,
    /// Missing spending utxo.
    FundingUtxo(FundingUtxoError),
    /// Missing witness script.
    MissingWitnessScript,
    /// Signing algorithm and key type does not match.
    MismatchedAlgoKey,
    /// Attempted to ECDSA sign a non-ECDSA input.
    NotEcdsa,
    /// The `scriptPubkey` is not a P2WPKH script.
    NotWpkh,
    /// Sighash computation error (segwit v0 input).
    SegwitV0Sighash(transaction::InputsIndexError),
    /// Sighash computation error (p2wpkh input).
    P2wpkhSighash(sighash::P2wpkhError),
    /// Sighash computation error (taproot input).
    TaprootError(sighash::TaprootError),
    /// Unable to determine the output type.
    UnknownOutputType,
    /// Unable to find key.
    KeyNotFound,
    /// Attempt to sign an input with the wrong signing algorithm.
    WrongSigningAlgorithm,
    /// Signing request currently unsupported.
    Unsupported,
    /// Witness input will produce a non-witness signature.
    NonWitnessSig,
    /// Non-witness input has a mismatch between the txid and prevout txid.
    NonWitnessUtxoTxidMismatch,
    /// Redeem script hash did not match the hash in the script_pubkey.
    RedeemScriptMismatch,
    /// Native segwit p2wsh script_pubkey did not match witness script hash.
    WitnessScriptMismatchWsh,
    /// Nested segwit p2wsh script_pubkey did not match redeem script hash.
    WitnessScriptMismatchShWsh,
    /// The signature sighash did not match the sighash provided in the input.
    SighashMismatch,
    /// `SIGHASH_SINGLE` used on an input with no output at the same index.
    SighashSingleMissingOutput,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexOutOfBounds(ref e) => write_err!(f, "index out of bounds"; e),
            Self::InvalidSighashType => write!(f, "invalid sighash type"),
            Self::MissingInputUtxo => write!(f, "missing input utxo in PSBT"),
            Self::MissingRedeemScript => write!(f, "missing redeem script"),
            Self::FundingUtxo(ref e) => write_err!(f, "input funding utxo error"; e),
            Self::MissingWitnessScript => write!(f, "missing witness script"),
            Self::MismatchedAlgoKey => write!(f, "signing algorithm and key type does not match"),
            Self::NotEcdsa => write!(f, "attempted to ECDSA sign a non-ECDSA input"),
            Self::NotWpkh => write!(f, "the scriptPubkey is not a P2WPKH script"),
            Self::SegwitV0Sighash(ref e) => write_err!(f, "segwit v0 sighash"; e),
            Self::P2wpkhSighash(ref e) => write_err!(f, "p2wpkh sighash"; e),
            Self::TaprootError(ref e) => write_err!(f, "taproot sighash"; e),
            Self::UnknownOutputType => write!(f, "unable to determine the output type"),
            Self::KeyNotFound => write!(f, "unable to find key"),
            Self::WrongSigningAlgorithm =>
                write!(f, "attempt to sign an input with the wrong signing algorithm"),
            Self::Unsupported => write!(f, "signing request currently unsupported"),
            Self::NonWitnessSig => write!(f, "witness input will produce a non-witness signature"),
            Self::NonWitnessUtxoTxidMismatch =>
                write!(f, "non-witness input has a mismatch between the txid and prevout txid"),
            Self::RedeemScriptMismatch =>
                write!(f, "redeem script hash did not match the hash in the script_pubkey"),
            Self::WitnessScriptMismatchWsh =>
                write!(f, "native segwit p2wsh script_pubkey did not match witness script hash"),
            Self::WitnessScriptMismatchShWsh =>
                write!(f, "nested segwit p2wsh script_pubkey did not match redeem script hash"),
            Self::SighashMismatch =>
                write!(f, "the signature sighash did not match the sighash provided in the input"),
            Self::SighashSingleMissingOutput =>
                write!(f, "sighash single input has no output at the same index"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SegwitV0Sighash(ref e) => Some(e),
            Self::P2wpkhSighash(ref e) => Some(e),
            Self::TaprootError(ref e) => Some(e),
            Self::IndexOutOfBounds(ref e) => Some(e),
            Self::FundingUtxo(ref e) => Some(e),
            Self::InvalidSighashType
            | Self::MissingInputUtxo
            | Self::MissingRedeemScript
            | Self::MissingWitnessScript
            | Self::MismatchedAlgoKey
            | Self::NotEcdsa
            | Self::NotWpkh
            | Self::UnknownOutputType
            | Self::KeyNotFound
            | Self::WrongSigningAlgorithm
            | Self::Unsupported
            | Self::NonWitnessSig
            | Self::NonWitnessUtxoTxidMismatch
            | Self::RedeemScriptMismatch
            | Self::WitnessScriptMismatchWsh
            | Self::WitnessScriptMismatchShWsh
            | Self::SighashMismatch
            | Self::SighashSingleMissingOutput => None,
        }
    }
}

impl From<sighash::P2wpkhError> for SignError {
    fn from(e: sighash::P2wpkhError) -> Self { Self::P2wpkhSighash(e) }
}

impl From<IndexOutOfBoundsError> for SignError {
    fn from(e: IndexOutOfBoundsError) -> Self { Self::IndexOutOfBounds(e) }
}

impl From<sighash::TaprootError> for SignError {
    fn from(e: sighash::TaprootError) -> Self { Self::TaprootError(e) }
}

impl From<FundingUtxoError> for SignError {
    fn from(e: FundingUtxoError) -> Self { Self::FundingUtxo(e) }
}

/// Error when passing an un-modifiable PSBT to a `Constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PsbtNotModifiableError {
    /// The outputs modifiable flag is not set.
    Outputs(OutputsNotModifiableError),
    /// The inputs modifiable flag is not set.
    Inputs(InputsNotModifiableError),
}

impl fmt::Display for PsbtNotModifiableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Outputs(ref e) => write_err!(f, "outputs not modifiable"; e),
            Self::Inputs(ref e) => write_err!(f, "inputs not modifiable"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PsbtNotModifiableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Outputs(ref e) => Some(e),
            Self::Inputs(ref e) => Some(e),
        }
    }
}

impl From<InputsNotModifiableError> for PsbtNotModifiableError {
    fn from(e: InputsNotModifiableError) -> Self { Self::Inputs(e) }
}

impl From<OutputsNotModifiableError> for PsbtNotModifiableError {
    fn from(e: OutputsNotModifiableError) -> Self { Self::Outputs(e) }
}

/// Error when passing an PSBT with inputs not modifiable to an input adding `Constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InputsNotModifiableError;

impl fmt::Display for InputsNotModifiableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PSBT does not have the inputs modifiable flag set")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputsNotModifiableError {}

/// Error when passing an PSBT with outputs not modifiable to an output adding `Constructor`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutputsNotModifiableError;

impl fmt::Display for OutputsNotModifiableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PSBT does not have the outputs modifiable flag set")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutputsNotModifiableError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// The input is not 100% unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotUnsignedError {
    /// Input has already been finalized.
    Finalized,
    /// Input already has signature data.
    SigData,
}

impl fmt::Display for NotUnsignedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finalized => f.write_str("input has already been finalized"),
            Self::SigData => f.write_str("input already has signature data"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NotUnsignedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Unable to determine lock time, multiple inputs have conflicting locking requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DetermineLockTimeError;

impl fmt::Display for DetermineLockTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "unable to determine lock time, multiple inputs have conflicting locking requirements",
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DetermineLockTimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

// TODO: Consider creating a type that has input_index and E and simplify all these similar error types?
/// Error checking the partials sigs have correct sighash types.
#[derive(Debug)]
pub enum PartialSigsSighashTypeError {
    /// Non-standard sighash type found in `input.sighash_type` field.
    NonStandardInputSighashType {
        /// The input index with the non-standard sighash type.
        input_index: usize,
        /// The non-standard sighash type error.
        error: NonStandardSighashTypeError,
    },
    /// Non-standard sighash type found in `input.partial_sigs`.
    NonStandardPartialSigsSighashType {
        /// The input index with the non-standard sighash type.
        input_index: usize,
        /// The non-standard sighash type error.
        error: NonStandardSighashTypeError,
    },
    /// Wrong sighash flag in partial signature.
    WrongSighashFlag {
        /// The input index with the wrong sighash flag.
        input_index: usize,
        /// The sighash type we got.
        got: EcdsaSighashType,
        /// The sighash type we require.
        required: EcdsaSighashType,
        /// The associated pubkey (key into the `input.partial_sigs` map).
        pubkey: PublicKey,
    },
}

impl fmt::Display for PartialSigsSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonStandardInputSighashType { input_index, ref error } =>
                write_err!(f, "non-standard sighash type for input {} in sighash_type field", input_index; error),
            Self::NonStandardPartialSigsSighashType { input_index, ref error } =>
                write_err!(f, "non-standard sighash type for input {} in partial_sigs", input_index; error),
            Self::WrongSighashFlag { input_index, got, required, pubkey } => write!(
                f,
                "wrong sighash flag for input {} (got: {}, required: {}) pubkey: {}",
                input_index, got, required, pubkey
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PartialSigsSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // TODO: Is this correct for a struct error fields?
        match self {
            Self::NonStandardInputSighashType { input_index: _, ref error } => Some(error),
            Self::NonStandardPartialSigsSighashType { input_index: _, ref error } => Some(error),
            Self::WrongSighashFlag { .. } => None,
        }
    }
}

/// Error combining two PSBTs, global extended public key has inconsistent key sources.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InconsistentKeySourcesError(pub Xpub);

impl fmt::Display for InconsistentKeySourcesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "combining PSBT, key-source conflict for xpub {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InconsistentKeySourcesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// An error while calculating the fee.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeeError {
    /// Funding utxo error for input.
    FundingUtxo(FundingUtxoError),
    /// Integer overflow in fee calculation adding input.
    InputOverflow,
    /// Integer overflow in fee calculation adding output.
    OutputOverflow,
    /// Negative fee.
    Negative,
}

impl fmt::Display for FeeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FundingUtxo(ref e) => write_err!(f, "funding utxo error for input"; e),
            Self::InputOverflow => f.write_str("integer overflow in fee calculation adding input"),
            Self::OutputOverflow =>
                f.write_str("integer overflow in fee calculation adding output"),
            Self::Negative => f.write_str("PSBT has a negative fee which is not allowed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FeeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FundingUtxo(ref e) => Some(e),
            Self::InputOverflow | Self::OutputOverflow | Self::Negative => None,
        }
    }
}

impl From<FundingUtxoError> for FeeError {
    fn from(e: FundingUtxoError) -> Self { Self::FundingUtxo(e) }
}

/// An error getting the funding transaction for this input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FundingUtxoError {
    /// The vout is out of bounds for non-witness transaction.
    OutOfBounds {
        /// The vout used as list index.
        vout: usize,
        /// The length of the utxo list.
        len: usize,
    },
    /// No funding utxo found.
    MissingUtxo,
    /// Witness and non witness utxo were provided, but they do not match.
    MismatchingUtxos,
    /// All non P2TR inputs should provide non witness utxo.
    UnverifiableUtxo,
    /// The non witness utxo provided does not match the prevout txid.
    MismatchingTxid,
}

impl fmt::Display for FundingUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds { vout, len } => {
                write!(f, "vout {} out of bounds for tx list len: {}", vout, len)
            }
            Self::MissingUtxo => write!(f, "no funding utxo found"),
            Self::MismatchingUtxos => {
                write!(f, "witness and non witness data were provided, but they do not match")
            }
            Self::UnverifiableUtxo => {
                write!(f, "all non p2tr inputs should provide non witness utxo")
            }
            Self::MismatchingTxid => {
                write!(f, "the txid from the non witness utxo doesn't match the prevout txid")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FundingUtxoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OutOfBounds { .. }
            | Self::MissingUtxo
            | Self::MismatchingUtxos
            | Self::UnverifiableUtxo
            | Self::MismatchingTxid => None,
        }
    }
}

/// Formats error.
///
/// If `std` feature is OFF appends error source (delimited by `: `). We do this because
/// `e.source()` is only available in std builds, without this macro the error source is lost for
/// no-std builds.
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr)*; $source:expr) => {
        {
            #[cfg(feature = "std")]
            {
                let _ = &$source;   // Prevents clippy warnings.
                write!($writer, $string $(, $args)*)
            }
            #[cfg(not(feature = "std"))]
            {
                write!($writer, concat!($string, ": {}") $(, $args)*, $source)
            }
        }
    }
}
pub(crate) use write_err;
