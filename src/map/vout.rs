// SPDX-License-Identifier: CC0-1.0

//! PSBT output index (`PSBT_IN_OUTPUT_INDEX`).
//!
//! Defined in [BIP-174], each input map includes the index of the output being
//! spent within the previous transaction (the `vout` of the previous
//! transaction's outpoint). The value is encoded as a 4-byte little-endian
//! unsigned integer.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use core::fmt;

use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decoder, DecoderStatus, UnexpectedEofError,
};

use crate::encoding::{PsbtDecode, PsbtEncode};

/// The index of the output being spent, i.e. the `vout` of the previous
/// transaction's outpoint.
///
/// Encoded as a 4-byte little-endian unsigned integer in the PSBT input map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Vout(u32);

impl From<u32> for Vout {
    fn from(value: u32) -> Self { Self(value) }
}

impl From<Vout> for u32 {
    fn from(vout: Vout) -> Self { vout.0 }
}

impl From<Vout> for usize {
    fn from(vout: Vout) -> Self { vout.0 as Self }
}

impl fmt::Display for Vout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.0, f) }
}

impl PsbtEncode for Vout {
    type Encoder<'e>
        = VoutEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        VoutEncoder::new(ArrayEncoder::without_length_prefix(self.0.to_le_bytes()))
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a [`Vout`] value (4-byte little-endian).
    pub struct VoutEncoder<'e>(ArrayEncoder<4>);
}

/// Decoder for a PSBT `vout` value (4-byte little-endian).
#[derive(Debug, Default)]
pub struct VoutDecoder(ArrayDecoder<4>);

impl Decoder for VoutDecoder {
    type Output = Vout;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        self.0.end().map(|bytes| Vout(u32::from_le_bytes(bytes)))
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl PsbtDecode for Vout {
    type Decoder = VoutDecoder;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{decode_from_slice, encode_to_vec};

    #[test]
    fn new_is_zero() {
        assert_eq!(u32::from(Vout::from(0)), 0);
    }

    #[test]
    fn from_u32_roundtrip() {
        let v = Vout::from(42);
        assert_eq!(u32::from(v), 42);
    }

    #[test]
    fn display() {
        assert_eq!(alloc::format!("{}", Vout::from(5)), "5");
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = Vout::from(0x12345678);
        let encoded = encode_to_vec(&original);
        let decoded: Vout = decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn read_limit_lifecycle() {
        let mut decoder = VoutDecoder::default();
        assert_eq!(decoder.read_limit(), 4, "fresh decoder should request 4 bytes");

        let mut bytes: &[u8] = &[0x04, 0x03, 0x02, 0x01];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0, "completed decoder should request no bytes");
    }

    #[test]
    fn encode_le_bytes() {
        let encoded = encode_to_vec(&Vout::from(0x01020304));
        assert_eq!(encoded, alloc::vec![0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn encode_zero() {
        let encoded = encode_to_vec(&Vout::from(0));
        assert_eq!(encoded, alloc::vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn encode_max() {
        let encoded = encode_to_vec(&Vout::from(u32::MAX));
        assert_eq!(encoded, alloc::vec![0xff, 0xff, 0xff, 0xff]);
    }
}
