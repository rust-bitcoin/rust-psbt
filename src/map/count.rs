// SPDX-License-Identifier: CC0-1.0

//! PSBT count value (`PSBT_GLOBAL_INPUT_COUNT` / `PSBT_GLOBAL_OUTPUT_COUNT`).
//!
//! Defined in [BIP-370] (PSBT version 2), the input count and output count
//! fields are compact-size encoded integers that declare how many input and
//! output maps follow the global map.
//!
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

use core::fmt;

use bitcoin_consensus_encoding::{
    CompactSizeDecoder, CompactSizeDecoderError, CompactSizeEncoder, Decoder, DecoderStatus,
};

use crate::encoding::{PsbtDecode, PsbtEncode};

/// A PSBT count value, encoded as a compact-size integer.
///
/// Used for `PSBT_GLOBAL_INPUT_COUNT` (`0x04`) and `PSBT_GLOBAL_OUTPUT_COUNT`
/// (`0x05`). The value is the number of input maps and output maps,
/// respectively, that follow the global map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Count(usize);

impl From<usize> for Count {
    fn from(value: usize) -> Self { Self(value) }
}

impl From<Count> for usize {
    fn from(count: Count) -> Self { count.0 }
}

impl core::ops::AddAssign<usize> for Count {
    fn add_assign(&mut self, rhs: usize) { self.0 += rhs; }
}

impl fmt::Display for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl PsbtEncode for Count {
    type Encoder<'e>
        = CountEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        CountEncoder::new(CompactSizeEncoder::new(self.0))
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a [`Count`] value (compact-size integer).
    pub struct CountEncoder<'e>(CompactSizeEncoder);
}

/// Decoder for a PSBT count value.
#[derive(Debug, Default)]
pub struct CountDecoder(CompactSizeDecoder);

impl Decoder for CountDecoder {
    type Output = Count;
    type Error = CompactSizeDecoderError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> { self.0.end().map(Count) }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl PsbtDecode for Count {
    type Decoder = CountDecoder;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{decode_from_slice, encode_to_vec};

    #[test]
    fn new_is_zero() {
        assert_eq!(usize::from(Count::from(0)), 0);
    }

    #[test]
    fn from_usize_roundtrip() {
        let c = Count::from(42);
        assert_eq!(usize::from(c), 42);
    }

    #[test]
    fn display() {
        assert_eq!(alloc::format!("{}", Count::from(5)), "5");
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = Count::from(42);
        let encoded = encode_to_vec(&original);
        let decoded: Count = decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_zero() {
        let encoded = encode_to_vec(&Count::from(0));
        assert_eq!(encoded, alloc::vec![0x00]);
    }

    #[test]
    fn encode_single_byte_max() {
        // 0xfc is the largest compact-size value encoded in a single byte.
        let encoded = encode_to_vec(&Count::from(0xfc));
        assert_eq!(encoded, alloc::vec![0xfc]);
    }

    #[test]
    fn encode_two_byte_boundary() {
        // 0xfd triggers the 2-byte encoding: 0xfd marker + 2-byte LE.
        let encoded = encode_to_vec(&Count::from(0xfd));
        assert_eq!(encoded, alloc::vec![0xfd, 0xfd, 0x00]);
    }

    #[test]
    fn encode_four_byte_boundary() {
        // 0x10000 triggers the 4-byte encoding: 0xfe marker + 4-byte LE.
        let encoded = encode_to_vec(&Count::from(0x10000));
        assert_eq!(encoded, alloc::vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
    }
}
