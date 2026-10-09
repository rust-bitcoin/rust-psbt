// SPDX-License-Identifier: CC0-1.0

//! PSBT Version 0.
//!
//! PSBTs with version v0 (BIP-174) are supported through a minimal [`PsbtV0`] wrapper which
//! exposes little beyond encoding and decoding.

#[cfg(feature = "base64")]
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bitcoin::{Amount, ScriptBuf, Sequence, Txid};
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decoder, DecoderStatus, Encoder4, IterEncoder,
};

use crate::encoding::{encode_to_vec, PsbtEncode};
use crate::error::DeserializeError;
use crate::map::global::Global;
use crate::map::input::Input;
#[cfg(feature = "base64")]
use crate::psbt::ParsePsbtError;
use crate::psbt::{MagicEncoder, Psbt, PSBT_MAGIC, PSBT_MAGIC_BYTES, PSBT_SEPARATOR};

/// A PSBT locked to version 0 (BIP-174).
///
/// Takes ownership of a [`Psbt`] and exposes a limited encode/decode interface.
#[derive(Debug)]
pub struct PsbtV0 {
    pub(crate) psbt: Psbt,
    // Lock time is resolved at construction.
    pub(crate) lock_time: bitcoin::locktime::absolute::LockTime,
}

impl PsbtV0 {
    /// Wrap an existing [`Psbt`] by taking ownership and resolving lock time.
    pub fn from_psbt(psbt: Psbt) -> Result<Self, crate::error::DetermineLockTimeError> {
        let lock_time = psbt.determine_lock_time()?;
        Ok(Self { psbt, lock_time })
    }

    /// Encode this PSBT as v0 (BIP-174) binary.
    pub fn serialize(&self) -> Vec<u8> { encode_to_vec(self) }

    /// Encode this PSBT as a v0 (BIP-174) base64 string.
    #[cfg(feature = "base64")]
    pub fn serialize_base64(&self) -> String {
        use bitcoin::base64::display::Base64Display;
        use bitcoin::base64::prelude::BASE64_STANDARD;

        Base64Display::new(&self.serialize(), &BASE64_STANDARD).to_string()
    }

    /// Extract the inner [`Psbt`].
    pub fn into_psbt(self) -> Psbt { self.psbt }

    /// Reports which v2 fields will be demoted to unknown key-value pairs
    /// when this PSBT is encoded as v0 (BIP-174).
    pub fn degraded(&self) -> Degraded {
        #[cfg(feature = "silent-payments")]
        {
            Degraded {
                sp_ecdh_shares: self.psbt.global.sp_ecdh_shares.len(),
                sp_dleq_proofs: self.psbt.global.sp_dleq_proofs.len(),
                sp_dropped_inputs: self
                    .psbt
                    .inputs
                    .iter()
                    .filter(|i| !i.sp_ecdh_shares.is_empty() || !i.sp_dleq_proofs.is_empty())
                    .count(),
                sp_dropped_outputs: self
                    .psbt
                    .outputs
                    .iter()
                    .filter(|o| o.sp_v0_info.is_some() || o.sp_v0_label.is_some())
                    .count(),
            }
        }
        #[cfg(not(feature = "silent-payments"))]
        {
            Degraded::default()
        }
    }

    /// Deserializes a PSBT v0 (BIP-174) from raw bytes.
    ///
    /// Returns an error if the input contains trailing bytes after the PSBT.
    ///
    /// If you need to parse a v0 PSBT from a buffer that may contain additional
    /// data, use the lower-level
    /// [`decode_from_slice_unbounded_with_decoder`](bitcoin_consensus_encoding::decode_from_slice_unbounded_with_decoder)
    /// directly with [`PsbtV0Decoder`]:
    ///
    /// ```
    /// # use psbt_v2::Psbt;
    /// # use psbt_v2::PsbtV0;
    /// # use psbt_v2::PsbtV0Decoder;
    /// # use psbt_v2::{Global, Input, DeserializeError};
    /// # use psbt_v2::bitcoin::hashes::Hash as _;
    /// # use psbt_v2::bitcoin::{OutPoint, Txid};
    /// # use bitcoin_consensus_encoding::decode_from_slice_unbounded_with_decoder;
    /// # let psbt = Psbt {
    /// #     global: Global { input_count: 1, output_count: 0, ..Global::default() },
    /// #     inputs: vec![Input::new(&OutPoint { txid: Txid::hash(b"x"), vout: 0 })],
    /// #     outputs: vec![],
    /// # };
    /// # let bytes = PsbtV0::from_psbt(psbt).unwrap().serialize();
    /// let mut remaining = &bytes[..];
    /// let _psbt_v0 = decode_from_slice_unbounded_with_decoder::<PsbtV0Decoder>(
    ///     &mut remaining,
    /// )?;
    /// // `remaining` now points to whatever followed the PSBT
    /// # Ok::<(), DeserializeError>(())
    /// ```
    pub fn deserialize(bytes: &[u8]) -> Result<Self, crate::error::DeserializeError> {
        bitcoin_consensus_encoding::decode_from_slice_with_decoder::<PsbtV0Decoder>(bytes).map_err(
            |e| match e {
                bitcoin_consensus_encoding::DecodeError::Parse(e) => e,
                bitcoin_consensus_encoding::DecodeError::Unconsumed(_) =>
                    DeserializeError::Unconsumed,
            },
        )
    }

    /// Deserializes a PSBT v0 (BIP-174) from a base64-encoded string.
    #[cfg(feature = "base64")]
    pub fn deserialize_base64(s: &str) -> Result<Self, ParsePsbtError> {
        use bitcoin::base64::prelude::{Engine, BASE64_STANDARD};

        let data = BASE64_STANDARD.decode(s).map_err(ParsePsbtError::Base64Encoding)?;
        Self::deserialize(&data).map_err(ParsePsbtError::PsbtEncoding)
    }
}

/// Reports which v2-only fields will be demoted to unknown key-value pairs by a v0
/// (BIP-174) encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Degraded {
    /// Number of silent payment ECDH shares encoded as unknown global keys (`0x07`).
    pub sp_ecdh_shares: usize,
    /// Number of silent payment DLEQ proofs encoded as unknown global keys from the global map
    /// (`0x08`).
    pub sp_dleq_proofs: usize,
    /// Number of inputs whose silent payment fields were encoded as unknown
    /// per-input keys (`0x1d` / `0x1e`).
    pub sp_dropped_inputs: usize,
    /// Number of outputs whose silent payment fields were encoded as unknown per-output keys
    /// (`0x09` and/or `0x0a` was `Some`).
    pub sp_dropped_outputs: usize,
}

impl Degraded {
    /// Returns `true` if no fields were demoted to unknowns.
    pub fn is_empty(&self) -> bool {
        self.sp_ecdh_shares == 0
            && self.sp_dleq_proofs == 0
            && self.sp_dropped_inputs == 0
            && self.sp_dropped_outputs == 0
    }
}

impl PsbtEncode for PsbtV0 {
    type Encoder<'e>
        = PsbtV0Encoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        PsbtV0Encoder::new(Encoder4::new(
            MagicEncoder::new(ArrayEncoder::without_length_prefix(PSBT_MAGIC_BYTES)),
            crate::map::v0::global::GlobalMapEncoder::new(self),
            IterEncoder::new(crate::map::v0::input::Inputs::from(self.psbt.inputs.iter())),
            IterEncoder::new(crate::map::v0::output::Outputs::from(self.psbt.outputs.iter())),
        ))
    }
}

bitcoin_consensus_encoding::encoder_newtype! {
    /// Encoder for a complete PSBT v0 (BIP-174).
    pub struct PsbtV0Encoder<'e>(
        Encoder4<
            MagicEncoder<'e>,
            crate::map::v0::global::GlobalMapEncoder<'e>,
            IterEncoder<crate::map::v0::input::Inputs<'e>>,
            IterEncoder<crate::map::v0::output::Outputs<'e>>,
        >
    );
}

/// Decoder for PSBT v0 (BIP-174).
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum V0DecoderStage {
    /// Decoding the magic bytes (`"psbt"`).
    Magic(ArrayDecoder<4>),
    /// Decoding the separator (`0xff`).
    Separator,
    /// Decoding the v0 global map.
    Global(crate::map::v0::GlobalMapDecoder),
    /// Decoding the v0 input maps.
    Inputs(
        Global,
        Vec<(Txid, u32, Sequence)>,
        Vec<(Amount, ScriptBuf)>,
        crate::map::v0::InputsDecoder,
    ),
    /// Decoding the v0 output maps.
    Outputs(Global, Vec<Input>, Vec<(Amount, ScriptBuf)>, crate::map::v0::OutputsDecoder),
    /// Done decoding.
    Done(Psbt),
    /// Sentinel used during state transitions.
    Errored,
}

/// Decoder for a complete PSBT v0 (BIP-174).
#[derive(Debug)]
pub struct PsbtV0Decoder {
    stage: V0DecoderStage,
}

impl Decoder for PsbtV0Decoder {
    type Output = PsbtV0;
    type Error = DeserializeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        loop {
            match &mut self.stage {
                V0DecoderStage::Magic(decoder) => match decoder.push_bytes(bytes) {
                    Ok(status) if status.needs_more() => return Ok(DecoderStatus::NeedsMore),
                    Ok(_) => {}
                    Err(_) => unreachable!("ArrayDecoder never errors in push_bytes"),
                },
                V0DecoderStage::Separator =>
                    if bytes.is_empty() {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                V0DecoderStage::Global(decoder) =>
                    if decoder
                        .push_bytes(bytes)
                        .map_err(DeserializeError::DecodeGlobal)?
                        .needs_more()
                    {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                V0DecoderStage::Inputs(_, _, _, d) =>
                    if d.push_bytes(bytes).map_err(DeserializeError::DecodeInputs)?.needs_more() {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                V0DecoderStage::Outputs(_, _, _, d) =>
                    if d.push_bytes(bytes).map_err(DeserializeError::DecodeOutputs)?.needs_more() {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                V0DecoderStage::Done(_) => return Ok(DecoderStatus::Ready),
                V0DecoderStage::Errored => panic!("push_bytes after error"),
            }

            // Transition states.
            match core::mem::replace(&mut self.stage, V0DecoderStage::Errored) {
                V0DecoderStage::Magic(decoder) => {
                    let magic = decoder.end().expect("magic ready");
                    if magic != *PSBT_MAGIC {
                        return Err(DeserializeError::InvalidMagic(magic));
                    }
                    self.stage = V0DecoderStage::Separator;
                }
                V0DecoderStage::Separator => {
                    let sep = bytes[0];
                    *bytes = &bytes[1..];
                    if sep != PSBT_SEPARATOR {
                        return Err(DeserializeError::InvalidSeparator(sep));
                    }
                    self.stage =
                        V0DecoderStage::Global(crate::map::v0::GlobalMapDecoder::default());
                }
                V0DecoderStage::Global(decoder) => {
                    let (global, tx_inputs, tx_outputs) =
                        decoder.end().map_err(DeserializeError::DecodeGlobal)?;
                    let in_count = tx_inputs.len();
                    let out_count = tx_outputs.len();
                    if in_count == 0 {
                        if out_count == 0 {
                            self.stage = V0DecoderStage::Done(Psbt {
                                global,
                                inputs: Vec::new(),
                                outputs: Vec::new(),
                            });
                        } else {
                            self.stage = V0DecoderStage::Outputs(
                                global,
                                Vec::new(),
                                tx_outputs,
                                crate::map::v0::OutputsDecoder::new(out_count),
                            );
                        }
                    } else {
                        self.stage = V0DecoderStage::Inputs(
                            global,
                            tx_inputs,
                            tx_outputs,
                            crate::map::v0::InputsDecoder::new(in_count),
                        );
                    }
                    continue;
                }
                V0DecoderStage::Inputs(global, tx_inputs, tx_outputs, decoder) => {
                    let mut inputs = decoder.end().map_err(DeserializeError::DecodeInputs)?;
                    for (input, (txid, vout, seq)) in inputs.iter_mut().zip(&tx_inputs) {
                        input.previous_txid = *txid;
                        input.spent_output_index = *vout;
                        input.sequence = Some(*seq);
                    }
                    let out_count = tx_outputs.len();
                    if out_count == 0 {
                        self.stage =
                            V0DecoderStage::Done(Psbt { global, inputs, outputs: Vec::new() });
                    } else {
                        self.stage = V0DecoderStage::Outputs(
                            global,
                            inputs,
                            tx_outputs,
                            crate::map::v0::OutputsDecoder::new(out_count),
                        );
                    }
                    continue;
                }
                V0DecoderStage::Outputs(global, inputs, tx_outputs, decoder) => {
                    let mut outputs = decoder.end().map_err(DeserializeError::DecodeOutputs)?;
                    for (output, (amount, script)) in outputs.iter_mut().zip(&tx_outputs) {
                        output.amount = *amount;
                        output.script_pubkey = script.clone();
                    }
                    self.stage = V0DecoderStage::Done(Psbt { global, inputs, outputs });
                }
                V0DecoderStage::Done(_) => return Ok(DecoderStatus::Ready),
                V0DecoderStage::Errored => unreachable!(),
            }
        }
    }

    fn end(self) -> Result<PsbtV0, Self::Error> {
        match self.stage {
            V0DecoderStage::Done(psbt) =>
                Ok(PsbtV0::from_psbt(psbt).expect("lock time determinable after successful decode")),
            V0DecoderStage::Magic(_) => Err(DeserializeError::EarlyEnd("magic")),
            V0DecoderStage::Separator => Err(DeserializeError::EarlyEnd("separator")),
            V0DecoderStage::Global(_) => Err(DeserializeError::EarlyEnd("global")),
            V0DecoderStage::Inputs(..) => Err(DeserializeError::EarlyEnd("inputs")),
            V0DecoderStage::Outputs(..) => Err(DeserializeError::EarlyEnd("outputs")),
            V0DecoderStage::Errored => panic!("PsbtV0Decoder ended in Errored state"),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            V0DecoderStage::Magic(magic) => magic.read_limit(),
            V0DecoderStage::Separator => 1,
            V0DecoderStage::Global(dec) => dec.read_limit(),
            V0DecoderStage::Inputs(_, _, _, dec) => dec.read_limit(),
            V0DecoderStage::Outputs(_, _, _, dec) => dec.read_limit(),
            V0DecoderStage::Done(_) | V0DecoderStage::Errored => 0,
        }
    }
}

impl Default for PsbtV0Decoder {
    fn default() -> Self { Self { stage: V0DecoderStage::Magic(ArrayDecoder::default()) } }
}
