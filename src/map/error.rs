// SPDX-License-Identifier: CC0-1.0

//! Exposes general errors used by the global, input, and output codecs. Types are shared between
//! the v2 and v0 codecs, so it is possible for certain variants to be v2 or v0 specific.

use core::fmt;

use bitcoin::blockdata::script::ScriptBufDecoderError;
use bitcoin::blockdata::transaction::{TransactionDecoderError, TxOutDecoderError};
use bitcoin::blockdata::witness::WitnessDecoderError;
use bitcoin::{bip32, ecdsa, hashes, key, Amount, Sequence};
use bitcoin_consensus_encoding::{
    ByteVecDecoderError, CompactSizeDecoderError, Decode, UnexpectedEofError,
};

use super::Key;
#[cfg(feature = "silent-payments")]
use crate::encoding::native::CompressedPublicKeyDecodeError;
use crate::encoding::native::{
    EcdsaSignatureDecodeError, HeightDecodeError, KeySourceDecodeError, TapKeyOriginDecodeError,
    TapLeafScriptDecodeError, TapNodeHashDecodeError, TapTreeDecodeError,
    TaprootSignatureDecodeError, TimeDecodeError, TxidDecodeError, XOnlyPublicKeyDecodeError,
};
use crate::encoding::ValueDecoderError;
use crate::error::write_err;
use crate::map::output::ValidationError;
use crate::map::v0::unsigned_tx::UnsignedTxDecodeError;
#[cfg(feature = "silent-payments")]
use crate::silent_payments::SpV0InfoDecodeError;

/// An error while decoding a global map.
///
/// Shared by both v0 (BIP-174) and v2 (BIP-370) global map decoders.
/// Some variants are only produced by one decoder or the other.
#[derive(Debug)]
#[non_exhaustive]
pub enum GlobalDecodeError {
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(Key),
    /// Error decoding a key from the stream.
    KeyDecode(KeyDecodeError),
    /// Finished decoding before the end-of-map separator was reached.
    EarlyEnd,
    /// Serialized PSBT is missing the version number (v2 only).
    MissingVersion,
    /// PSBT_GLOBAL_VERSION: PSBT v2 expects the version to be 2.
    WrongVersion(u32),
    /// Serialized PSBT is missing the transaction version number (v2 only).
    MissingTxVersion,
    /// Serialized PSBT is missing the input count (v2 only).
    MissingInputCount,
    /// Serialized PSBT is missing the output count (v2 only).
    MissingOutputCount,
    /// v0 global map is missing the unsigned transaction (v0 only).
    MissingUnsignedTx,
    /// Failed to decode an extended public key.
    Xpub(XpubDecodeError),
    /// Error decoding the PSBT version value.
    Version(ValueDecoderError<crate::version::VersionDecoderError>),
    /// Error decoding the transaction modifiable flags value.
    ModifiableFlags(ValueDecoderError<UnexpectedEofError>),
    /// Error decoding a count value.
    Count(ValueDecoderError<CompactSizeDecoderError>),
    /// Error decoding a transaction version value.
    TxVersion(ValueDecoderError<bitcoin::transaction::VersionDecoderError>),
    /// Error decoding a lock time value.
    LockTime(ValueDecoderError<bitcoin::locktime::absolute::LockTimeDecoderError>),
    /// Error decoding a v0 unsigned transaction value.
    UnsignedTx(ValueDecoderError<UnsignedTxDecodeError>),
    /// Error decoding a proprietary value.
    ProprietaryValue(ByteVecDecoderError),
    /// Error decoding an unknown value.
    UnknownValue(ByteVecDecoderError),
    /// Error decoding a silent payments ECDH share value.
    #[cfg(feature = "silent-payments")]
    SpEcdh(ValueDecoderError<CompressedPublicKeyDecodeError>),
    /// Error decoding a silent payments DLEQ proof value.
    #[cfg(feature = "silent-payments")]
    SpDleq(ValueDecoderError<UnexpectedEofError>),
    /// ECDH shares and DLEQ proofs must both be present or both absent.
    #[cfg(feature = "silent-payments")]
    SpFieldMismatch,
}

impl fmt::Display for GlobalDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Self::WrongVersion(v) =>
                write!(f, "PSBT_GLOBAL_VERSION: expected v2, got version {}", v),
            Self::Xpub(ref e) => write_err!(f, "xpub"; e),
            Self::KeyDecode(ref e) => write_err!(f, "error decoding key"; e),
            Self::EarlyEnd => write!(f, "called end() before completing global map decode"),
            Self::MissingVersion => write!(f, "serialized PSBT is missing the version number"),
            Self::MissingTxVersion => {
                write!(f, "serialized PSBT is missing the transaction version number")
            }
            Self::MissingInputCount => write!(f, "serialized PSBT is missing the input count"),
            Self::MissingOutputCount => write!(f, "serialized PSBT is missing the output count"),
            #[cfg(feature = "silent-payments")]
            Self::SpFieldMismatch => {
                write!(f, "ECDH shares and DLEQ proofs must both be present or both absent")
            }
            Self::MissingUnsignedTx => write!(f, "missing unsigned tx in v0 global map"),
            Self::Version(ref e) => write_err!(f, "error decoding PSBT version"; e),
            Self::ModifiableFlags(ref e) => write_err!(f, "error decoding modifiable flags"; e),
            Self::Count(ref e) => write_err!(f, "error decoding count"; e),
            Self::TxVersion(ref e) => write_err!(f, "error decoding transaction version"; e),
            Self::LockTime(ref e) => write_err!(f, "error decoding lock time"; e),
            Self::UnsignedTx(ref e) => write_err!(f, "error decoding unsigned tx"; e),
            Self::ProprietaryValue(ref e) => write_err!(f, "error decoding proprietary value"; e),
            Self::UnknownValue(ref e) => write_err!(f, "error decoding unknown value"; e),
            #[cfg(feature = "silent-payments")]
            Self::SpEcdh(ref e) => write_err!(f, "error decoding SP ECDH share"; e),
            #[cfg(feature = "silent-payments")]
            Self::SpDleq(ref e) => write_err!(f, "error decoding SP DLEQ proof"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GlobalDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DuplicateKey(_) | Self::WrongVersion(_) => None,
            Self::Xpub(ref e) => Some(e),
            Self::KeyDecode(ref e) => Some(e),
            Self::MissingVersion
            | Self::MissingTxVersion
            | Self::MissingInputCount
            | Self::MissingOutputCount
            | Self::MissingUnsignedTx
            | Self::EarlyEnd => None,
            #[cfg(feature = "silent-payments")]
            Self::SpFieldMismatch => None,
            Self::Version(ref e) => Some(e),
            Self::ModifiableFlags(ref e) => Some(e),
            Self::Count(ref e) => Some(e),
            Self::TxVersion(ref e) => Some(e),
            Self::LockTime(ref e) => Some(e),
            Self::UnsignedTx(ref e) => Some(e),
            Self::ProprietaryValue(ref e) => Some(e),
            Self::UnknownValue(ref e) => Some(e),
            #[cfg(feature = "silent-payments")]
            Self::SpEcdh(ref e) => Some(e),
            #[cfg(feature = "silent-payments")]
            Self::SpDleq(ref e) => Some(e),
        }
    }
}

/// Error decoding a PSBT_GLOBAL_XPUB key-value pair.
#[derive(Debug)]
#[non_exhaustive]
pub enum XpubDecodeError {
    /// Error parsing the extended public key from the key data.
    Key(bip32::Error),
    /// Error decoding the key source (fingerprint + derivation path) from the value.
    KeySource(KeySourceDecodeError),
}

impl fmt::Display for XpubDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(ref e) => write_err!(f, "invalid xpub"; e),
            Self::KeySource(ref e) => write_err!(f, "error decoding xpub key source"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for XpubDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key(ref e) => Some(e),
            Self::KeySource(ref e) => Some(e),
        }
    }
}

/// An error while decoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum OutputDecodeError {
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(Key),
    /// Error decoding a raw PSBT key.
    KeyDecode(KeyDecodeError),
    /// Decoding finished before fully decoding the output map.
    EarlyEnd,
    /// Invalid public key when parsing key data.
    InvalidPublicKey(key::FromSliceError),
    /// Invalid xonly public key when parsing key data.
    InvalidXOnlyPublicKey,
    /// Encoded output is missing an amount value.
    MissingAmount,
    /// Encoded output is missing a script pubkey.
    MissingScriptPubkey,
    /// Error decoding the amount value.
    Amount(
        ValueDecoderError<
            <<Amount as Decode>::Decoder as bitcoin_consensus_encoding::Decoder>::Error,
        >,
    ),
    /// Error decoding the script pubkey.
    Script(ScriptBufDecoderError),
    /// Error decoding the redeem script.
    RedeemScript(ScriptBufDecoderError),
    /// Error decoding the witness script.
    WitnessScript(ScriptBufDecoderError),
    /// Error decoding the BIP32 derivation value.
    Bip32Derivation(KeySourceDecodeError),
    /// Error decoding the taproot internal key.
    TapInternalKey(ValueDecoderError<XOnlyPublicKeyDecodeError>),
    /// Error decoding the taproot tree.
    TapTree(TapTreeDecodeError),
    /// Error decoding the taproot BIP32 derivation value.
    TapBip32Derivation(TapKeyOriginDecodeError),
    /// Error decoding a proprietary value.
    ProprietaryValue(ByteVecDecoderError),
    /// Error decoding an unknown value.
    UnknownValue(ByteVecDecoderError),
    /// Error validating the decoded output.
    Validation(ValidationError),
    /// Error decoding a silent payments v0 info.
    #[cfg(feature = "silent-payments")]
    SpV0Info(ValueDecoderError<SpV0InfoDecodeError>),
    /// Error decoding a silent payments v0 label.
    #[cfg(feature = "silent-payments")]
    SpV0Label(ValueDecoderError<UnexpectedEofError>),
}

impl fmt::Display for OutputDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Self::InvalidPublicKey(ref e) => write_err!(f, "invalid public key"; e),
            Self::InvalidXOnlyPublicKey => write!(f, "invalid xonly public key"),
            Self::KeyDecode(ref e) => write_err!(f, "error decoding key"; e),
            Self::EarlyEnd => write!(f, "called build() before completing output map decode"),
            Self::MissingAmount => write!(f, "encoded output is missing an amount"),
            Self::MissingScriptPubkey => write!(f, "encoded output is missing a script pubkey"),
            Self::Validation(ref e) => write_err!(f, "output validation error"; e),
            Self::Amount(ref e) => write_err!(f, "error decoding amount"; e),
            Self::Script(ref e) => write_err!(f, "error decoding script pubkey"; e),
            Self::RedeemScript(ref e) => write_err!(f, "error decoding redeem script"; e),
            Self::WitnessScript(ref e) => write_err!(f, "error decoding witness script"; e),
            Self::Bip32Derivation(ref e) => write_err!(f, "error decoding BIP32 derivation"; e),
            Self::TapInternalKey(ref e) => write_err!(f, "error decoding tap internal key"; e),
            Self::TapTree(ref e) => write_err!(f, "error decoding tap tree"; e),
            Self::TapBip32Derivation(ref e) =>
                write_err!(f, "error decoding tap BIP32 derivation"; e),
            Self::ProprietaryValue(ref e) => write_err!(f, "error decoding proprietary value"; e),
            Self::UnknownValue(ref e) => write_err!(f, "error decoding unknown value"; e),
            #[cfg(feature = "silent-payments")]
            Self::SpV0Info(ref e) => write_err!(f, "error decoding SP v0 info"; e),
            #[cfg(feature = "silent-payments")]
            Self::SpV0Label(ref e) => write_err!(f, "error decoding SP v0 label"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OutputDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPublicKey(ref e) => Some(e),
            Self::KeyDecode(ref e) => Some(e),
            Self::Amount(ref e) => Some(e),
            Self::Script(ref e) => Some(e),
            Self::RedeemScript(ref e) => Some(e),
            Self::WitnessScript(ref e) => Some(e),
            Self::Bip32Derivation(ref e) => Some(e),
            Self::TapInternalKey(ref e) => Some(e),
            Self::TapTree(ref e) => Some(e),
            Self::TapBip32Derivation(ref e) => Some(e),
            Self::ProprietaryValue(ref e) => Some(e),
            Self::UnknownValue(ref e) => Some(e),
            #[cfg(feature = "silent-payments")]
            Self::SpV0Info(ref e) => Some(e),
            #[cfg(feature = "silent-payments")]
            Self::SpV0Label(ref e) => Some(e),
            Self::DuplicateKey(_)
            | Self::InvalidXOnlyPublicKey
            | Self::EarlyEnd
            | Self::MissingAmount
            | Self::MissingScriptPubkey => None,
            Self::Validation(ref e) => Some(e),
        }
    }
}

/// An error while decoding an input map.
///
/// Shared by both v0 (BIP-174) and v2 (BIP-370) input map decoders.
#[derive(Debug)]
#[non_exhaustive]
pub enum InputDecodeError {
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(Key),
    /// Invalid hash when parsing key or value data.
    InvalidHash(hashes::FromSliceError),
    /// Invalid public key when parsing key data.
    InvalidPublicKey(key::FromSliceError),
    /// Invalid ECDSA signature when parsing value data.
    InvalidEcdsaSignature(ecdsa::Error),
    /// Error decoding key.
    KeyDecode(KeyDecodeError),
    /// Error decoding a value.
    ValueDecode(InputValueDecodeError),
    /// Input must contain a previous txid.
    MissingPreviousTxid,
    /// Input must contain a spent output index.
    MissingSpentOutputIndex,
    /// End before fully decoding the input map.
    EarlyEnd,
    /// BIP-375: ECDH shares and DLEQ proofs must both be present or both absent.
    #[cfg(feature = "silent-payments")]
    SpFieldMismatch,
    /// Non-witness UTXO txid does not match the input's previous txid.
    IncorrectNonWitnessUtxo {
        /// The txid of the input being spent.
        previous_txid: bitcoin::Txid,
        /// The txid of the non-witness UTXO.
        non_witness_utxo_txid: bitcoin::Txid,
    },
    /// Encoded xpub key derivation is missing a fingerprint.
    MissingXpubFingerprint,
    /// Encoded taproot BIP32 derivation is missing a fingerprint.
    MissingTapBip32Fingerprint,
}

impl fmt::Display for InputDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Self::InvalidHash(ref e) => write_err!(f, "invalid hash"; e),
            Self::InvalidPublicKey(ref e) => write_err!(f, "invalid public key"; e),
            Self::InvalidEcdsaSignature(ref e) => write_err!(f, "invalid ECDSA signature"; e),
            Self::KeyDecode(ref e) => write_err!(f, "error decoding key"; e),
            Self::ValueDecode(ref e) => write_err!(f, "error decoding value"; e),
            Self::MissingPreviousTxid => write!(f, "input must contain a previous txid"),
            Self::MissingSpentOutputIndex => write!(f, "input must contain a spent output index"),
            Self::EarlyEnd => write!(f, "called build() before completing input map decode"),
            #[cfg(feature = "silent-payments")]
            Self::SpFieldMismatch => {
                write!(f, "ECDH shares and DLEQ proofs must both be present or both absent")
            }
            Self::IncorrectNonWitnessUtxo { previous_txid, non_witness_utxo_txid } => write!(
                f,
                "non-witness utxo txid {} does not match previous txid {}",
                non_witness_utxo_txid, previous_txid
            ),
            Self::MissingXpubFingerprint => write!(f, "xpub derivation missing fingerprint"),
            Self::MissingTapBip32Fingerprint =>
                write!(f, "tap BIP32 derivation missing fingerprint"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidHash(ref e) => Some(e),
            Self::InvalidPublicKey(ref e) => Some(e),
            Self::InvalidEcdsaSignature(ref e) => Some(e),
            Self::DuplicateKey(_) => None,
            Self::KeyDecode(ref e) => Some(e),
            Self::ValueDecode(ref e) => Some(e),
            Self::MissingPreviousTxid
            | Self::MissingSpentOutputIndex
            | Self::EarlyEnd
            | Self::IncorrectNonWitnessUtxo { .. }
            | Self::MissingXpubFingerprint
            | Self::MissingTapBip32Fingerprint => None,
            #[cfg(feature = "silent-payments")]
            Self::SpFieldMismatch => None,
        }
    }
}

/// Error decoding the body of a value from an input map.
#[derive(Debug)]
#[non_exhaustive]
pub enum InputValueDecodeError {
    /// Value length does not match the expected fixed size for this key type (got, expected).
    WrongLength {
        /// The decoded value length.
        got: usize,
        /// The expected value length.
        expected: usize,
    },
    /// Error decoding the previous transaction ID.
    PreviousTxid(ValueDecoderError<TxidDecodeError>),
    /// Error decoding the output index.
    OutputIndex(ValueDecoderError<UnexpectedEofError>),
    /// Error decoding the sequence number).
    Sequence(
        ValueDecoderError<
            <<Sequence as bitcoin_consensus_encoding::Decode>::Decoder as bitcoin_consensus_encoding::Decoder>::Error,
        >,
    ),
    /// Error decoding the minimum lock time.
    MinTime(ValueDecoderError<TimeDecodeError>),
    /// Error decoding the minimum lock height.
    MinHeight(ValueDecoderError<HeightDecodeError>),
    /// Error decoding the sighash type.
    SighashType(ValueDecoderError<UnexpectedEofError>),
    /// Error decoding the taproot internal key.
    TapInternalKey(ValueDecoderError<XOnlyPublicKeyDecodeError>),
    /// Error decoding the taproot merkle root.
    TapMerkleRoot(ValueDecoderError<TapNodeHashDecodeError>),
    /// Error decoding the non-witness UTXO (full transaction).
    NonWitnessUtxo(ValueDecoderError<TransactionDecoderError>),
    /// Error decoding the witness UTXO (transaction output).
    WitnessUtxo(ValueDecoderError<TxOutDecoderError>),
    /// Error decoding the final script witness (witness stack).
    FinalScriptWitness(ValueDecoderError<WitnessDecoderError>),
    /// Error decoding the redeem script.
    RedeemScript(ScriptBufDecoderError),
    /// Error decoding the witness script.
    WitnessScript(ScriptBufDecoderError),
    /// Error decoding the final scriptSig.
    FinalScriptSig(ScriptBufDecoderError),
    /// Error decoding the taproot key signature.
    TapKeySig(TaprootSignatureDecodeError),
    /// Error decoding an ECDSA partial signature.
    PartialSig(EcdsaSignatureDecodeError),
    /// Error decoding the BIP32 derivation key source.
    Bip32Derivation(KeySourceDecodeError),
    /// Error decoding the taproot BIP32 derivation key source.
    TapBip32Derivation(TapKeyOriginDecodeError),
    /// Error decoding a RIPEMD160 preimage.
    Ripemd160Preimage(ByteVecDecoderError),
    /// Error decoding a SHA256 preimage.
    Sha256Preimage(ByteVecDecoderError),
    /// Error decoding a HASH160 preimage.
    Hash160Preimage(ByteVecDecoderError),
    /// Error decoding a HASH256 preimage.
    Hash256Preimage(ByteVecDecoderError),
    /// Error decoding a taproot script signature.
    TapScriptSig(TaprootSignatureDecodeError),
    /// Error decoding a tap leaf script.
    TapLeafScript(TapLeafScriptDecodeError),
    /// Error decoding a proprietary value.
    ProprietaryValue(ByteVecDecoderError),
    /// Error decoding an unknown value.
    UnknownValue(ByteVecDecoderError),
    /// The decoded value is not a valid taproot control block.
    InvalidControlBlock,
    /// Error decoding a silent payments ECDH share.
    #[cfg(feature = "silent-payments")]
    SpEcdh(ValueDecoderError<CompressedPublicKeyDecodeError>),
    /// Error decoding a silent payments DLEQ proof).
    #[cfg(feature = "silent-payments")]
    SpDleq(ValueDecoderError<UnexpectedEofError>),
}

impl fmt::Display for InputValueDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { got, expected } =>
                write!(f, "value length {} (expected {})", got, expected),
            Self::PreviousTxid(ref e) => write_err!(f, "error decoding previous txid"; e),
            Self::OutputIndex(ref e) => write_err!(f, "error decoding output index"; e),
            Self::Sequence(ref e) => write_err!(f, "error decoding sequence"; e),
            Self::MinTime(ref e) => write_err!(f, "error decoding min time"; e),
            Self::MinHeight(ref e) => write_err!(f, "error decoding min height"; e),
            Self::SighashType(ref e) => write_err!(f, "error decoding sighash type"; e),
            Self::TapInternalKey(ref e) => write_err!(f, "error decoding tap internal key"; e),
            Self::TapMerkleRoot(ref e) => write_err!(f, "error decoding tap merkle root"; e),
            Self::NonWitnessUtxo(ref e) => write_err!(f, "error decoding non-witness UTXO"; e),
            Self::WitnessUtxo(ref e) => write_err!(f, "error decoding witness UTXO"; e),
            Self::FinalScriptWitness(ref e) =>
                write_err!(f, "error decoding final script witness"; e),
            Self::RedeemScript(ref e) => write_err!(f, "error decoding redeem script"; e),
            Self::WitnessScript(ref e) => write_err!(f, "error decoding witness script"; e),
            Self::FinalScriptSig(ref e) => write_err!(f, "error decoding final scriptSig"; e),
            Self::TapKeySig(ref e) => write_err!(f, "error decoding tap key signature"; e),
            Self::PartialSig(ref e) => write_err!(f, "error decoding partial signature"; e),
            Self::Bip32Derivation(ref e) => write_err!(f, "error decoding BIP32 derivation"; e),
            Self::TapBip32Derivation(ref e) =>
                write_err!(f, "error decoding tap BIP32 derivation"; e),
            Self::Ripemd160Preimage(ref e) => write_err!(f, "error decoding RIPEMD160 preimage"; e),
            Self::Sha256Preimage(ref e) => write_err!(f, "error decoding SHA256 preimage"; e),
            Self::Hash160Preimage(ref e) => write_err!(f, "error decoding HASH160 preimage"; e),
            Self::Hash256Preimage(ref e) => write_err!(f, "error decoding HASH256 preimage"; e),
            Self::TapScriptSig(ref e) => write_err!(f, "error decoding tap script signature"; e),
            Self::TapLeafScript(ref e) => write_err!(f, "error decoding tap leaf script"; e),
            Self::ProprietaryValue(ref e) => write_err!(f, "error decoding proprietary value"; e),
            Self::UnknownValue(ref e) => write_err!(f, "error decoding unknown value"; e),
            Self::InvalidControlBlock => write!(f, "invalid control block"),
            #[cfg(feature = "silent-payments")]
            Self::SpEcdh(ref e) => write_err!(f, "error decoding SP ECDH share"; e),
            #[cfg(feature = "silent-payments")]
            Self::SpDleq(ref e) => write_err!(f, "error decoding SP DLEQ proof"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InputValueDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WrongLength { .. } => None,
            Self::PreviousTxid(ref e) => Some(e),
            Self::OutputIndex(ref e) => Some(e),
            Self::Sequence(ref e) => Some(e),
            Self::MinTime(ref e) => Some(e),
            Self::MinHeight(ref e) => Some(e),
            Self::SighashType(ref e) => Some(e),
            Self::TapInternalKey(ref e) => Some(e),
            Self::TapMerkleRoot(ref e) => Some(e),
            Self::NonWitnessUtxo(ref e) => Some(e),
            Self::WitnessUtxo(ref e) => Some(e),
            Self::FinalScriptWitness(ref e) => Some(e),
            Self::RedeemScript(ref e) => Some(e),
            Self::WitnessScript(ref e) => Some(e),
            Self::FinalScriptSig(ref e) => Some(e),
            Self::TapKeySig(ref e) => Some(e),
            Self::PartialSig(ref e) => Some(e),
            Self::Bip32Derivation(ref e) => Some(e),
            Self::TapBip32Derivation(ref e) => Some(e),
            Self::Ripemd160Preimage(ref e) => Some(e),
            Self::Sha256Preimage(ref e) => Some(e),
            Self::Hash160Preimage(ref e) => Some(e),
            Self::Hash256Preimage(ref e) => Some(e),
            Self::TapScriptSig(ref e) => Some(e),
            Self::TapLeafScript(ref e) => Some(e),
            Self::ProprietaryValue(ref e) => Some(e),
            Self::UnknownValue(ref e) => Some(e),
            Self::InvalidControlBlock => None,
            #[cfg(feature = "silent-payments")]
            Self::SpEcdh(ref e) => Some(e),
            #[cfg(feature = "silent-payments")]
            Self::SpDleq(ref e) => Some(e),
        }
    }
}

/// Error returned when decoding a raw PSBT [`Key`] fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDecodeError {
    /// Failed to decode the key's length-prefixed byte body.
    Bytes(ByteVecDecoderError),
    /// The key body was empty.
    ///
    /// A `keylen` of zero encodes the end-of-map separator (0x00), not a [`super::Key`]; callers decoding
    /// a PSBT map should check for the separator before decoding a [`super::Key`].
    Empty,
    /// Failed to decode the `keytype` compact size integer from the key body.
    TypeValue(CompactSizeDecoderError),
    /// Key data is invalid for this key type (e.g., non-empty when empty expected,
    /// wrong length, malformed content).
    InvalidKeyData(Key),
    /// Key type is excluded from this version of PSBT.
    ExcludedKey {
        /// Key type value we found.
        key_type_value: u64,
    },
    /// Invalid proprietary key (e.g., missing prefix, malformed sub-key).
    InvalidProprietaryKey,
}

impl fmt::Display for KeyDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Bytes(e) => write!(f, "failed to decode key body: {}", e),
            Self::Empty => write!(f, "empty key (this is the map separator)"),
            Self::TypeValue(e) => write!(f, "failed to decode keytype: {}", e),
            Self::InvalidKeyData(ref key) => write!(f, "key data invalid for key: {}", key),
            Self::ExcludedKey { key_type_value } =>
                write!(f, "excluded key type 0x{:02x}", key_type_value),
            Self::InvalidProprietaryKey => write!(f, "invalid proprietary key"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeyDecodeError {}
