// SPDX-License-Identifier: CC0-1.0

//! Encoder for the unsigned transaction in a PSBT v0 global map.
//!
//! Per [BIP-174], the unsigned transaction is always serialized in the legacy
//! (pre-segwit) format with empty `scriptSig`s and no witnesses.
//!
//! The encoder reads directly from a [`Psbt`](crate::Psbt)'s fields without
//! materializing an intermediate [`Transaction`](bitcoin::Transaction).
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute;
use bitcoin::Sequence;
use bitcoin_consensus_encoding::{
    ArrayEncoder, BytesEncoder, CompactSizeEncoder, Encoder2, Encoder4, IterEncoder,
    PrefixedBytesEncoder,
};

use crate::encoding::PsbtEncode;

/// Default sequence for unsigned tx inputs. Matches the convention in
/// [`Input::unsigned_tx_in()`](crate::input::Input::unsigned_tx_in): a
/// missing `PSBT_IN_SEQUENCE` is treated as `0xFFFFFFFF`.
static DEFAULT_SEQUENCE: Sequence = Sequence::MAX;

/// Encoder for a single unsigned transaction input.
///
/// Borrows fields directly from the PSBT [`Input`](crate::input::Input) rather
/// than from an intermediate [`TxIn`](bitcoin::TxIn).
type TxIn<'e> = Encoder4<
    BytesEncoder<'e>, // previous_txid
    ArrayEncoder<4>,  // spent_output_index
    ArrayEncoder<1>,  // script_sig always 0x00
    <Sequence as PsbtEncode>::Encoder<'e>,
>;

#[derive(Clone)]
struct TxInIter<'e> {
    iter: core::slice::Iter<'e, crate::input::Input>,
}

impl<'e> Iterator for TxInIter<'e> {
    type Item = TxIn<'e>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|input| {
            Encoder4::new(
                BytesEncoder::without_length_prefix(input.previous_txid.as_byte_array()),
                ArrayEncoder::without_length_prefix(input.spent_output_index.to_le_bytes()),
                ArrayEncoder::without_length_prefix([0x00]),
                match input.sequence {
                    Some(ref seq) => seq.psbt_encoder(),
                    None => DEFAULT_SEQUENCE.psbt_encoder(),
                },
            )
        })
    }
}

/// Encoder for a single unsigned transaction output.
///
/// Borrows fields directly from the PSBT [`Output`](crate::Output) rather than
/// from an intermediate [`TxOut`](bitcoin::TxOut).
type TxOut<'e> = Encoder2<
    <bitcoin::Amount as PsbtEncode>::Encoder<'e>, // amount
    PrefixedBytesEncoder<'e>,                     // script_pubkey (output script)
>;

#[derive(Clone)]
struct TxOutIter<'e> {
    iter: core::slice::Iter<'e, crate::Output>,
}

impl<'e> Iterator for TxOutIter<'e> {
    type Item = TxOut<'e>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|output| {
            let amount: &'e bitcoin::Amount = &output.amount;
            let script: &'e [u8] = output.script_pubkey.as_bytes();
            Encoder2::new(amount.psbt_encoder(), PrefixedBytesEncoder::new(script))
        })
    }
}

type Inputs<'e> = Encoder2<CompactSizeEncoder, IterEncoder<TxInIter<'e>>>;
type Outputs<'e> = Encoder2<CompactSizeEncoder, IterEncoder<TxOutIter<'e>>>;

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encodes the unsigned transaction body for PSBT v0.
    pub(crate) struct UnsignedTxEncoder<'e>(
        Encoder4<
            <bitcoin::transaction::Version as PsbtEncode>::Encoder<'e>,
            Inputs<'e>,
            Outputs<'e>,
            <absolute::LockTime as PsbtEncode>::Encoder<'e>,
        >
    );
}

impl<'e> UnsignedTxEncoder<'e> {
    pub(crate) fn from_psbt(v0: &'e crate::psbt::PsbtV0) -> Self {
        UnsignedTxEncoder::new(Encoder4::new(
            v0.psbt.global.tx_version.psbt_encoder(),
            Inputs::new(
                CompactSizeEncoder::new(v0.psbt.inputs.len()),
                IterEncoder::new(TxInIter { iter: v0.psbt.inputs.iter() }),
            ),
            Outputs::new(
                CompactSizeEncoder::new(v0.psbt.outputs.len()),
                IterEncoder::new(TxOutIter { iter: v0.psbt.outputs.iter() }),
            ),
            v0.lock_time.psbt_encoder(),
        ))
    }
}
