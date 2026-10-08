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

use alloc::vec::Vec;

use bitcoin::absolute::{LockTimeDecoder, LockTimeDecoderError};
use bitcoin::blockdata::transaction::{
    TxInDecoder, TxInDecoderError, TxOutDecoder, TxOutDecoderError,
};
use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute;
use bitcoin::transaction::{self, Sequence};
use bitcoin::{Amount, ScriptBuf, Txid};
use bitcoin_consensus_encoding::{
    ArrayEncoder, BytesEncoder, CompactSizeEncoder, Decoder, DecoderStatus, Encoder2, Encoder4,
    IterEncoder, PrefixedBytesEncoder, VecDecoderError, VecDecoderWith,
};

use crate::encoding::PsbtEncode;
use crate::version::{VersionDecoder, VersionDecoderError};

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
    pub(crate) fn from_psbt(v0: &'e crate::v0::PsbtV0) -> Self {
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

#[derive(Debug)]
pub enum UnsignedTxDecodeError {
    EarlyEnd,
    InvalidScriptSig(u8),
    DecodeVersion(VersionDecoderError),
    DecodeLockTime(LockTimeDecoderError),
    Inputs(VecDecoderError<TxInDecoderError>),
    Outputs(VecDecoderError<TxOutDecoderError>),
}

impl core::fmt::Display for UnsignedTxDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EarlyEnd => write!(f, "end called before decoding finished"),
            Self::InvalidScriptSig(b) =>
                write!(f, "non-empty scriptSig (0x{b:02x}) in unsigned tx"),
            Self::DecodeVersion(e) => write!(f, "version: {e}"),
            Self::DecodeLockTime(e) => write!(f, "lock time: {e}"),
            Self::Inputs(e) => write!(f, "inputs: {e}"),
            Self::Outputs(e) => write!(f, "outputs: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsignedTxDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DecodeVersion(e) => Some(e),
            Self::DecodeLockTime(e) => Some(e),
            Self::Inputs(e) => Some(e),
            Self::Outputs(e) => Some(e),
            Self::EarlyEnd | Self::InvalidScriptSig(_) => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct UnsignedTxDecoder {
    state: State,
}

impl Default for UnsignedTxDecoder {
    fn default() -> Self { Self { state: State::Version(VersionDecoder::new()) } }
}

#[derive(Debug)]
enum State {
    Version(VersionDecoder),
    Inputs(transaction::Version, VecDecoderWith<TxInDecoder>),
    Outputs(transaction::Version, Vec<(Txid, u32, Sequence)>, VecDecoderWith<TxOutDecoder>),
    LockTime(
        transaction::Version,
        Vec<(Txid, u32, Sequence)>,
        Vec<(Amount, ScriptBuf)>,
        LockTimeDecoder,
    ),
    Done(
        transaction::Version,
        Vec<(Txid, u32, Sequence)>,
        Vec<(Amount, ScriptBuf)>,
        absolute::LockTime,
    ),
}

impl Decoder for UnsignedTxDecoder {
    type Output = (
        transaction::Version,
        Vec<(Txid, u32, Sequence)>,
        Vec<(Amount, ScriptBuf)>,
        absolute::LockTime,
    );
    type Error = UnsignedTxDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        loop {
            let needs_more = match &mut self.state {
                State::Version(d) => d.push_bytes(bytes).is_ok_and(|s| s.needs_more()),
                State::Inputs(_, d) =>
                    d.push_bytes(bytes).map_err(UnsignedTxDecodeError::Inputs)?.needs_more(),
                State::Outputs(_, _, d) =>
                    d.push_bytes(bytes).map_err(UnsignedTxDecodeError::Outputs)?.needs_more(),
                State::LockTime(_, _, _, d) => d.push_bytes(bytes).is_ok_and(|s| s.needs_more()),
                State::Done(..) => return Ok(DecoderStatus::Ready),
            };
            if needs_more {
                return Ok(DecoderStatus::NeedsMore);
            }
            self.state =
                match core::mem::replace(&mut self.state, State::Version(VersionDecoder::new())) {
                    State::Version(d) => {
                        let version = transaction::Version(
                            d.end().map_err(UnsignedTxDecodeError::DecodeVersion)?.to_u32() as i32,
                        );
                        State::Inputs(version, VecDecoderWith::new())
                    }
                    State::Inputs(version, d) => {
                        let raw = d.end().map_err(UnsignedTxDecodeError::Inputs)?;
                        for tx_in in &raw {
                            if !tx_in.script_sig.is_empty() {
                                return Err(UnsignedTxDecodeError::InvalidScriptSig(
                                    tx_in.script_sig.as_bytes()[0],
                                ));
                            }
                        }
                        let inputs: Vec<_> = raw
                            .into_iter()
                            .map(|tx_in| {
                                let out = tx_in.previous_output;
                                (out.txid, out.vout, tx_in.sequence)
                            })
                            .collect();
                        State::Outputs(version, inputs, VecDecoderWith::new())
                    }
                    State::Outputs(version, inputs, d) => {
                        let outputs: Vec<_> = d
                            .end()
                            .map_err(UnsignedTxDecodeError::Outputs)?
                            .into_iter()
                            .map(|tx_out: bitcoin::blockdata::transaction::TxOut| {
                                (tx_out.value, tx_out.script_pubkey)
                            })
                            .collect();
                        State::LockTime(version, inputs, outputs, LockTimeDecoder::new())
                    }
                    State::LockTime(version, inputs, outputs, d) => {
                        let lock_time = d.end().map_err(UnsignedTxDecodeError::DecodeLockTime)?;
                        State::Done(version, inputs, outputs, lock_time)
                    }
                    _ => unreachable!(),
                };
        }
    }

    fn read_limit(&self) -> usize {
        match &self.state {
            State::Version(d) => d.read_limit(),
            State::Inputs(_, d) => d.read_limit(),
            State::Outputs(_, _, d) => d.read_limit(),
            State::LockTime(_, _, _, d) => d.read_limit(),
            State::Done(..) => 0,
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            State::Done(version, inputs, outputs, lock_time) =>
                Ok((version, inputs, outputs, lock_time)),
            _ => Err(UnsignedTxDecodeError::EarlyEnd),
        }
    }
}
