// SPDX-License-Identifier: CC0-1.0

use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;

use bitcoin::consensus::encode as consensus;
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, CompactSizeEncoder, Decoder, DecoderStatus, UnexpectedEofError,
};

use crate::encoding::{KeyValueEncoder, PsbtDecode, PsbtEncode};
use crate::serialize::{self, Deserialize, Serialize};

/// The PSBT version.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version(u32);

impl Version {
    /// The original PSBT format [BIP-174].
    ///
    /// [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
    pub const ZERO: Self = Self(0);

    /// The second PSBT version [BIP-370].
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>
    pub const TWO: Self = Self(2);
}

pub(crate) type VersionKeyValueEncoder<'e> =
    KeyValueEncoder<CompactSizeEncoder, VersionEncoder<'e>>;

impl Version {
    /// Returns the version number as a `u32`.
    pub fn to_u32(self) -> u32 { self.0 }
}

impl From<Version> for u32 {
    fn from(v: Version) -> Self { v.to_u32() }
}

impl TryFrom<u32> for Version {
    type Error = UnsupportedVersionError;

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Self::ZERO),
            2 => Ok(Self::TWO),
            n => Err(UnsupportedVersionError(n)),
        }
    }
}

impl Serialize for Version {
    fn serialize(&self) -> Vec<u8> { consensus::serialize(&self.to_u32()) }
}

impl Deserialize for Version {
    fn deserialize(bytes: &[u8]) -> Result<Self, serialize::Error> {
        let n: u32 = consensus::deserialize(bytes)?;
        let version = Self::try_from(n)?;
        Ok(version)
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// An encoder for PSBT Version values.
    pub struct VersionEncoder<'e>(ArrayEncoder<4>);
}

impl PsbtEncode for Version {
    type Encoder<'e>
        = VersionEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> VersionEncoder<'_> {
        VersionEncoder::new(ArrayEncoder::without_length_prefix(self.to_u32().to_le_bytes()))
    }
}

/// A decoder for [`Version`].
#[derive(Debug, Clone)]
pub struct VersionDecoder(ArrayDecoder<4>);

impl VersionDecoder {
    /// Constructs a new [`Version`] decoder.
    pub const fn new() -> Self { Self(ArrayDecoder::new()) }
}

impl Default for VersionDecoder {
    fn default() -> Self { Self::new() }
}

impl Decoder for VersionDecoder {
    type Output = Version;
    type Error = VersionDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes).map_err(VersionDecoderError::UnexpectedEof)
    }

    #[inline]
    fn end(self) -> Result<Version, Self::Error> {
        let bytes = self.0.end().map_err(VersionDecoderError::UnexpectedEof)?;
        let n = u32::from_le_bytes(bytes);
        Version::try_from(n).map_err(VersionDecoderError::UnsupportedVersion)
    }

    #[inline]
    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl PsbtDecode for Version {
    type Decoder = VersionDecoder;
}

/// Error decoding a [`Version`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionDecoderError {
    /// Not enough bytes were provided.
    UnexpectedEof(UnexpectedEofError),
    /// The version number is not supported.
    UnsupportedVersion(UnsupportedVersionError),
}

impl fmt::Display for VersionDecoderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding version: {}", e),
            Self::UnsupportedVersion(e) => write!(f, "{}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VersionDecoderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnexpectedEof(e) => Some(e),
            Self::UnsupportedVersion(e) => Some(e),
        }
    }
}

/// Unsupported PSBT version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnsupportedVersionError(u32);

impl fmt::Display for UnsupportedVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported version, we only support v0 and v2: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsupportedVersionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn version_as_u32() {
        assert_eq!(Version::ZERO.to_u32(), 0);
        assert_eq!(Version::TWO.to_u32(), 2);
        assert_eq!(u32::from(Version::ZERO), 0);
        assert_eq!(u32::from(Version::TWO), 2);
    }

    #[test]
    fn version_serialize() {
        assert_eq!(Version::ZERO.serialize(), vec![0x00, 0x00, 0x00, 0x00]);
        assert_eq!(Version::TWO.serialize(), vec![0x02, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn version_roundtrip() {
        let bytes = Version::TWO.serialize();
        let version = Version::deserialize(&bytes).unwrap();
        assert_eq!(version, Version::TWO);
    }

    #[test]
    fn version_decoder_read_limit() {
        let mut decoder = VersionDecoder::new();
        assert_eq!(decoder.read_limit(), 4);

        let mut bytes: &[u8] = &[0x02, 0x00, 0x00, 0x00];
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }
}
