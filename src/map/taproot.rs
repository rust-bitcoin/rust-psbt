// SPDX-License-Identifier: CC0-1.0

//! PSBT-specific taproot field types.
//!
//! These are tuples of upstream [`bitcoin`] taproot types that exist only as PSBT field key,
//! value, or key-data types and have no single named upstream representation. They are shared by
//! multiple map types (e.g. input and output).

use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::TapLeafHash;
use bitcoin_consensus_encoding::{ArrayEncoder, Encoder2};

use crate::encoding::PsbtEncode;

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a `(XOnlyPublicKey, TapLeafHash)` composite (32 byte + 32 byte).
    pub struct XOnlyLeafHashPairEncoder<'e>(Encoder2<ArrayEncoder<32>, ArrayEncoder<32>>);
}

impl PsbtEncode for (XOnlyPublicKey, TapLeafHash) {
    type Encoder<'e>
        = XOnlyLeafHashPairEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        XOnlyLeafHashPairEncoder::new(Encoder2::new(self.0.psbt_encoder(), self.1.psbt_encoder()))
    }
}
