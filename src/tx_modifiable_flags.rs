// SPDX-License-Identifier: CC0-1.0

//! Transaction modifiable flags (`PSBT_GLOBAL_TX_MODIFIABLE`).

use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decoder, DecoderStatus, UnexpectedEofError,
};

use crate::encoding::{PsbtDecode, PsbtEncode};

/// A bitfield for various transaction modification flags.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxModifiableFlags(pub u8);

impl PsbtEncode for TxModifiableFlags {
    type Encoder<'e>
        = ArrayEncoder<1>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { ArrayEncoder::without_length_prefix([self.0]) }
}

/// Decoder for the single-byte modifiable-flags value.
#[derive(Debug, Default)]
pub struct TxModifiableFlagsDecoder(ArrayDecoder<1>);

impl Decoder for TxModifiableFlagsDecoder {
    type Output = TxModifiableFlags;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let [byte] = self.0.end()?;
        Ok(TxModifiableFlags(byte))
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl PsbtDecode for TxModifiableFlags {
    type Decoder = TxModifiableFlagsDecoder;
}
