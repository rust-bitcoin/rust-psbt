// SPDX-License-Identifier: CC0-1.0

//! PSBT required height lock time (`PSBT_IN_REQUIRED_HEIGHT_LOCKTIME`).
//!
//! Defined in [BIP-370], each input may require a minimum block height for inclusion in the
//! transaction. The value is encoded as a 4-byte little-endian unsigned integer greater than 0 and
//! less than 500,000,000.
//!
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

use core::convert::TryFrom;
use core::fmt;

use bitcoin::locktime::absolute;
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decoder, DecoderStatus, UnexpectedEofError,
};

use crate::encoding::{PsbtDecode, PsbtEncode};

/// The minimum block height at which an input may be included in the transaction
/// (`PSBT_IN_REQUIRED_HEIGHT_LOCKTIME`).
///
/// BIP-370 requires this value to be greater than 0 and less than 500,000,000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RequiredHeightLockTime(absolute::Height);

impl RequiredHeightLockTime {
    /// Constructs a [`RequiredHeightLockTime`] from its consensus `u32` value.
    ///
    /// # Errors
    ///
    /// Returns [`RequiredHeightLockTimeError::Zero`] for `0` and
    /// [`RequiredHeightLockTimeError::OutOfRange`] for values greater than or
    /// equal to 500,000,000.
    pub fn from_consensus(n: u32) -> Result<Self, RequiredHeightLockTimeError> {
        let height = absolute::Height::from_consensus(n)
            .map_err(|_| RequiredHeightLockTimeError::OutOfRange)?;
        Self::try_from(height)
    }

    /// Returns the underlying [`absolute::Height`].
    pub fn to_height(self) -> absolute::Height { self.0 }
}

impl TryFrom<absolute::Height> for RequiredHeightLockTime {
    type Error = RequiredHeightLockTimeError;

    fn try_from(height: absolute::Height) -> Result<Self, Self::Error> {
        if height == absolute::Height::ZERO {
            return Err(RequiredHeightLockTimeError::Zero);
        }
        Ok(Self(height))
    }
}

impl From<RequiredHeightLockTime> for absolute::Height {
    fn from(v: RequiredHeightLockTime) -> Self { v.0 }
}

impl From<RequiredHeightLockTime> for absolute::LockTime {
    fn from(v: RequiredHeightLockTime) -> Self { Self::from(v.0) }
}

impl fmt::Display for RequiredHeightLockTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.to_consensus_u32(), f)
    }
}

impl PsbtEncode for RequiredHeightLockTime {
    type Encoder<'e>
        = RequiredHeightLockTimeEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        RequiredHeightLockTimeEncoder::new(ArrayEncoder::without_length_prefix(
            self.0.to_consensus_u32().to_le_bytes(),
        ))
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a [`RequiredHeightLockTime`] value (4-byte little-endian).
    pub struct RequiredHeightLockTimeEncoder<'e>(ArrayEncoder<4>);
}

/// Decoder for a [`RequiredHeightLockTime`] value (4-byte little-endian).
#[derive(Debug, Default)]
pub struct RequiredHeightLockTimeDecoder(ArrayDecoder<4>);

impl Decoder for RequiredHeightLockTimeDecoder {
    type Output = RequiredHeightLockTime;
    type Error = RequiredHeightLockTimeDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes).map_err(RequiredHeightLockTimeDecodeError::UnexpectedEof)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.0.end().map_err(RequiredHeightLockTimeDecodeError::UnexpectedEof)?;
        let n = u32::from_le_bytes(bytes);
        RequiredHeightLockTime::from_consensus(n)
            .map_err(RequiredHeightLockTimeDecodeError::Invalid)
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl PsbtDecode for RequiredHeightLockTime {
    type Decoder = RequiredHeightLockTimeDecoder;
}

/// Error when constructing a [`RequiredHeightLockTime`] from an invalid value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequiredHeightLockTimeError {
    /// The value is zero, which BIP-370 forbids for `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME`.
    Zero,
    /// The value is greater than or equal to 500,000,000.
    OutOfRange,
}

impl fmt::Display for RequiredHeightLockTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => f.write_str("required height lock time must be greater than zero"),
            Self::OutOfRange =>
                f.write_str("required height lock time must be less than 500000000"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RequiredHeightLockTimeError {}

/// Error decoding a [`RequiredHeightLockTime`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequiredHeightLockTimeDecodeError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The value is not a valid required height lock time.
    Invalid(RequiredHeightLockTimeError),
}

impl fmt::Display for RequiredHeightLockTimeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding required height: {e}"),
            Self::Invalid(e) => write!(f, "invalid required height lock time: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RequiredHeightLockTimeDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::Invalid(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::encoding::{decode_from_slice, encode_to_vec};

    #[test]
    fn from_consensus_rejects_zero() {
        assert_eq!(
            RequiredHeightLockTime::from_consensus(0).unwrap_err(),
            RequiredHeightLockTimeError::Zero
        );
    }

    #[test]
    fn from_consensus_rejects_out_of_range() {
        assert_eq!(
            RequiredHeightLockTime::from_consensus(500_000_000).unwrap_err(),
            RequiredHeightLockTimeError::OutOfRange
        );
    }

    #[test]
    fn from_consensus_accepts_valid() {
        let v = RequiredHeightLockTime::from_consensus(800_000).unwrap();
        assert_eq!(v.to_height().to_consensus_u32(), 800_000);
    }

    #[test]
    fn try_from_height_rejects_zero() {
        assert_eq!(
            RequiredHeightLockTime::try_from(absolute::Height::ZERO).unwrap_err(),
            RequiredHeightLockTimeError::Zero
        );
    }

    #[test]
    fn display() {
        let v = RequiredHeightLockTime::from_consensus(800_000).unwrap();
        assert_eq!(alloc::format!("{v}"), "800000");
    }

    #[test]
    fn read_limit_lifecycle() {
        let mut decoder = RequiredHeightLockTimeDecoder::default();
        assert_eq!(decoder.read_limit(), 4, "fresh decoder should request 4 bytes");

        let mut bytes: &[u8] = &[0x04, 0x03, 0x02, 0x01];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0, "completed decoder should request no bytes");
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = RequiredHeightLockTime::from_consensus(0x12345678).unwrap();
        let encoded = encode_to_vec(&original);
        let decoded: RequiredHeightLockTime = decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_rejects_zero() {
        let bytes = 0u32.to_le_bytes();
        let err = decode_from_slice::<RequiredHeightLockTime>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            bitcoin_consensus_encoding::DecodeError::Parse(
                RequiredHeightLockTimeDecodeError::Invalid(RequiredHeightLockTimeError::Zero)
            )
        ));
    }

    #[test]
    fn encode_le_bytes() {
        let encoded = encode_to_vec(&RequiredHeightLockTime::from_consensus(0x01020304).unwrap());
        assert_eq!(encoded, vec![0x04, 0x03, 0x02, 0x01]);
    }
}
