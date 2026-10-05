// SPDX-License-Identifier: CC0-1.0

//! Error types shared by the global, input, and output map codecs (v0 and v2).

use core::fmt;

use bitcoin::bip32;
use bitcoin_consensus_encoding::{
    ByteVecDecoderError, CompactSizeDecoderError, UnexpectedEofError,
};

use super::Key;
use crate::consts;
use crate::error::write_err;
use crate::map::v0::unsigned_tx::UnsignedTxDecodeError;

/// An error while decoding a global map.
///
/// Shared by both v0 (BIP-174) and v2 (BIP-370) global map decoders.
/// Some variants are only produced by one decoder or the other.
#[derive(Debug)]
pub enum GlobalDecodeError {
    /// Error inserting a key-value pair.
    InsertPair(InsertPairError),
    /// Error decoding a key from the stream.
    KeyDecode(super::KeyDecodeError),
    /// Error decoding a value.
    ValueDecode(ValueDecodeError),
    /// Called `end()` before the end-of-map separator was reached (v2 only).
    EarlyEnd,
    /// Serialized PSBT is missing the version number (v2 only).
    MissingVersion,
    /// Serialized PSBT is missing the transaction version number (v2 only).
    MissingTxVersion,
    /// Serialized PSBT is missing the input count (v2 only).
    MissingInputCount,
    /// Input count overflows word size for current architecture (v2 only).
    InputCountOverflow(u64),
    /// Serialized PSBT is missing the output count (v2 only).
    MissingOutputCount,
    /// Output count overflows word size for current architecture (v2 only).
    OutputCountOverflow(u64),
    /// ECDH shares and DLEQ proofs must both be present or both absent.
    FieldMismatch,
    /// v0 global map is missing the unsigned transaction (v0 only).
    MissingUnsignedTx,
    /// Error decoding the unsigned transaction from a v0 global map (v0 only).
    UnsignedTx(UnsignedTxDecodeError),
}

impl fmt::Display for GlobalDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsertPair(ref e) => write_err!(f, "error inserting a pair"; e),
            Self::KeyDecode(ref e) => write_err!(f, "error decoding key"; e),
            Self::ValueDecode(ref e) => write_err!(f, "error decoding value"; e),
            Self::EarlyEnd => write!(f, "called end() before completing global map decode"),
            Self::MissingVersion => write!(f, "serialized PSBT is missing the version number"),
            Self::MissingTxVersion => {
                write!(f, "serialized PSBT is missing the transaction version number")
            }
            Self::MissingInputCount => write!(f, "serialized PSBT is missing the input count"),
            Self::InputCountOverflow(count) => {
                write!(f, "input count overflows word size for current architecture: {}", count)
            }
            Self::MissingOutputCount => write!(f, "serialized PSBT is missing the output count"),
            Self::OutputCountOverflow(count) => {
                write!(f, "output count overflows word size for current architecture: {}", count)
            }
            Self::FieldMismatch => {
                write!(f, "ECDH shares and DLEQ proofs must both be present or both absent")
            }
            Self::MissingUnsignedTx => write!(f, "missing unsigned tx in v0 global map"),
            Self::UnsignedTx(ref e) => write_err!(f, "unsigned tx"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GlobalDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InsertPair(ref e) => Some(e),
            Self::KeyDecode(ref e) => Some(e),
            Self::ValueDecode(ref e) => Some(e),
            Self::UnsignedTx(ref e) => Some(e),
            Self::MissingVersion
            | Self::MissingTxVersion
            | Self::MissingInputCount
            | Self::InputCountOverflow(_)
            | Self::MissingOutputCount
            | Self::OutputCountOverflow(_)
            | Self::FieldMismatch
            | Self::MissingUnsignedTx
            | Self::EarlyEnd => None,
        }
    }
}

impl From<InsertPairError> for GlobalDecodeError {
    fn from(e: InsertPairError) -> Self { Self::InsertPair(e) }
}

/// Error inserting a key-value pair.
#[derive(Debug)]
pub enum InsertPairError {
    /// Keys within key-value map should never be duplicated.
    DuplicateKey(Key),
    /// Key should contain data.
    InvalidKeyDataEmpty(Key),
    /// Key should not contain data.
    InvalidKeyDataNotEmpty(Key),
    /// Value was not the correct length (got, want).
    ValueWrongLength(usize, usize),
    /// PSBT_GLOBAL_VERSION: PSBT v2 expects the version to be 2.
    WrongVersion(u32),
    /// PSBT_GLOBAL_XPUB: Must contain 4 bytes for the xpub fingerprint.
    XpubInvalidFingerprint,
    /// PSBT_GLOBAL_XPUB: value must contain at least 4 bytes for the xpub fingerprint.
    XpubValueTooShort(usize),
    /// PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints.
    XpubInvalidPath(usize),
    /// PSBT_GLOBAL_XPUB: value must not be empty.
    XpubValueEmpty,
    /// PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type.
    Bip32(bip32::Error),
    /// PSBT_GLOBAL_XPUB: xpubs must be unique.
    DuplicateXpub(bitcoin::bip32::KeySource),
    /// PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key.
    InvalidProprietaryKey,
    /// Key must be excluded from this version of PSBT (see consts.rs for u8 values).
    ExcludedKey {
        /// Key type value we found.
        key_type_value: u64,
    },
    /// Key was not the correct length (got, expected).
    KeyWrongLength(usize, usize),
}

impl fmt::Display for InsertPairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey(ref key) => write!(f, "duplicate key: {}", key),
            Self::InvalidKeyDataEmpty(ref key) => write!(f, "key should contain data: {}", key),
            Self::InvalidKeyDataNotEmpty(ref key) =>
                write!(f, "key should not contain data: {}", key),
            Self::ValueWrongLength(got, want) => {
                write!(f, "value (keyvalue pair) wrong length (got, want) {} {}", got, want)
            }
            Self::WrongVersion(v) => {
                write!(f, "PSBT_GLOBAL_VERSION: PSBT v2 expects the version to be 2, found: {}", v)
            }
            Self::XpubInvalidFingerprint => {
                write!(f, "PSBT_GLOBAL_XPUB: xpub fingerprint must be 4 bytes")
            }
            Self::XpubInvalidPath(len) => write!(
                f,
                "PSBT_GLOBAL_XPUB: derivation path must be a list of 32 byte varints: {}",
                len
            ),
            Self::XpubValueTooShort(got) => write!(
                f,
                "PSBT_GLOBAL_XPUB: value must contain at least 4 bytes for the xpub fingerprint, got: {}",
                got
            ),
            Self::Bip32(ref e) =>
                write_err!(f, "PSBT_GLOBAL_XPUB: Failed to decode a BIP-32 type"; e),
            Self::DuplicateXpub((fingerprint, ref derivation_path)) => write!(
                f,
                "PSBT_GLOBAL_XPUB: xpubs must be unique ({}, {})",
                fingerprint, derivation_path
            ),
            Self::XpubValueEmpty => write!(f, "PSBT_GLOBAL_XPUB: keypair value must not be empty"),
            Self::InvalidProprietaryKey =>
                write!(f, "PSBT_GLOBAL_PROPRIETARY: Invalid proprietary key"),
            Self::ExcludedKey { key_type_value } => write!(
                f,
                "found a keypair type that is explicitly excluded: {}",
                consts::psbt_global_key_type_value_to_str(*key_type_value)
            ),
            Self::KeyWrongLength(got, expected) => {
                write!(f, "key wrong length (got: {}, expected: {})", got, expected)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bip32(ref e) => Some(e),
            Self::DuplicateKey(_)
            | Self::InvalidKeyDataEmpty(_)
            | Self::InvalidKeyDataNotEmpty(_)
            | Self::ValueWrongLength(..)
            | Self::WrongVersion(_)
            | Self::XpubInvalidFingerprint
            | Self::XpubInvalidPath(_)
            | Self::XpubValueTooShort(_)
            | Self::DuplicateXpub(_)
            | Self::XpubValueEmpty
            | Self::InvalidProprietaryKey
            | Self::ExcludedKey { .. }
            | Self::KeyWrongLength(..) => None,
        }
    }
}

impl From<bip32::Error> for InsertPairError {
    fn from(e: bip32::Error) -> Self { Self::Bip32(e) }
}

/// Error decoding a value from the stream.
#[derive(Debug)]
pub enum ValueDecodeError {
    /// Error decoding the value's length prefix.
    LengthPrefix(CompactSizeDecoderError),
    /// Error decoding the PSBT version value.
    Version(UnexpectedEofError),
    /// Error decoding the transaction modifiable flags value.
    ModifiableFlags(UnexpectedEofError),
    /// Error decoding a count (VarInt) value.
    Count(CompactSizeDecoderError),
    /// Error decoding a transaction version value.
    TxVersion(bitcoin::transaction::VersionDecoderError),
    /// Error decoding a lock time value.
    LockTime(bitcoin::locktime::absolute::LockTimeDecoderError),
    /// Error decoding an xpub value.
    XpubValue(ByteVecDecoderError),
    /// Error decoding a proprietary value.
    ProprietaryValue(ByteVecDecoderError),
    /// Error decoding an unknown value.
    UnknownValue(ByteVecDecoderError),
    /// Error decoding a silent payments ECDH share value.
    #[cfg(feature = "silent-payments")]
    SpEcdh(UnexpectedEofError),
    /// Error decoding a silent payments DLEQ proof value.
    #[cfg(feature = "silent-payments")]
    SpDleq(UnexpectedEofError),
}

impl fmt::Display for ValueDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthPrefix(ref e) => write_err!(f, "error decoding value length prefix"; e),
            Self::Version(ref e) => write_err!(f, "error decoding PSBT version"; e),
            Self::ModifiableFlags(ref e) => write_err!(f, "error decoding modifiable flags"; e),
            Self::Count(ref e) => write_err!(f, "error decoding count"; e),
            Self::TxVersion(ref e) => write_err!(f, "error decoding transaction version"; e),
            Self::LockTime(ref e) => write_err!(f, "error decoding lock time"; e),
            Self::XpubValue(ref e) => write_err!(f, "error decoding xpub value"; e),
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
impl std::error::Error for ValueDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LengthPrefix(ref e) => Some(e),
            Self::Version(ref e) => Some(e),
            Self::ModifiableFlags(ref e) => Some(e),
            Self::Count(ref e) => Some(e),
            Self::TxVersion(ref e) => Some(e),
            Self::LockTime(ref e) => Some(e),
            Self::XpubValue(ref e) => Some(e),
            Self::ProprietaryValue(ref e) => Some(e),
            Self::UnknownValue(ref e) => Some(e),
            #[cfg(feature = "silent-payments")]
            Self::SpEcdh(ref e) => Some(e),
            #[cfg(feature = "silent-payments")]
            Self::SpDleq(ref e) => Some(e),
        }
    }
}
