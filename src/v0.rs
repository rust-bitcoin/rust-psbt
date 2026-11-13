// SPDX-License-Identifier: CC0-1.0

//! PSBT Version 0.
//!
//! PSBTs with version v0 (BIP-174) are supported through a minimal [`PsbtV0`] wrapper which
//! exposes little beyond encoding and decoding.

#[cfg(feature = "base64")]
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bitcoin::locktime::absolute;
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
use crate::tx_modifiable_flags::TxModifiableFlags;

/// A PSBT locked to version 0 (BIP-174).
///
/// Takes ownership of a [`Psbt`] and exposes a limited encode/decode interface.
#[derive(Debug)]
pub struct PsbtV0 {
    pub(crate) psbt: Psbt,
    // Lock time resolved at construction since construction is implicitely assumed to be over
    // due to the generation of the unsigned transaction.
    pub(crate) lock_time: bitcoin::locktime::absolute::LockTime,
}

impl PsbtV0 {
    /// Wrap an existing [`Psbt`] by taking ownership and resolving lock time.
    ///
    /// V0 serialization is the implicite end of construction, the transaction structure
    /// is set. At this point the effective lock time must be determinable.
    /// Per-input lock time requirements are resolved into the single unsigned
    /// transaction lock time. Conflicting requirements produce an error.
    pub fn from_psbt(psbt: Psbt) -> Result<Self, crate::error::DetermineLockTimeError> {
        let lock_time = psbt.determine_lock_time()?;
        Ok(Self { psbt, lock_time })
    }

    /// Encode this PSBT as v0 (BIP-174) binary.
    ///
    /// The v0 format has no per-input lock time fields. But the per-input requirements can be
    /// resolved into a single lock time and preserved in the unsigned tx (conflicting
    /// requirements are rejected), but the input granularity is lost in a v2-v0-v2 roundtrip.
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

    /// Returns a [`Degraded`] report of which v2 (BIP-370) metadata will be
    /// lost when this PSBT is encoded as v0 (BIP-174).
    ///
    /// See [`Degraded`] for a breakdown of each degradation category and
    /// the [`is_empty`](Degraded::is_empty) method to check whether any loss
    /// occurred.
    pub fn degraded(&self) -> Degraded {
        let lock_time_inputs = self
            .psbt
            .inputs
            .iter()
            .filter(|i| i.min_time.is_some() || i.min_height.is_some())
            .count();

        Degraded {
            lock_time_inputs,
            tx_modifiable_flags: (self.psbt.global.tx_modifiable_flags != TxModifiableFlags::new())
                .then_some(self.psbt.global.tx_modifiable_flags),
            #[cfg(feature = "silent-payments")]
            sp_ecdh_shares: self.psbt.global.sp_ecdh_shares.len(),
            #[cfg(feature = "silent-payments")]
            sp_dleq_proofs: self.psbt.global.sp_dleq_proofs.len(),
            #[cfg(feature = "silent-payments")]
            sp_dropped_inputs: self
                .psbt
                .inputs
                .iter()
                .filter(|i| !i.sp_ecdh_shares.is_empty() || !i.sp_dleq_proofs.is_empty())
                .count(),
            #[cfg(feature = "silent-payments")]
            sp_dropped_outputs: self
                .psbt
                .outputs
                .iter()
                .filter(|o| o.sp_v0_info.is_some() || o.sp_v0_label.is_some())
                .count(),
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
    /// # use psbt_v2::{Count, Global, Input, DeserializeError};
    /// # use psbt_v2::bitcoin::hashes::Hash as _;
    /// # use psbt_v2::bitcoin::{OutPoint, Txid};
    /// # use bitcoin_consensus_encoding::decode_from_slice_unbounded_with_decoder;
    /// # let psbt = Psbt {
    /// #     global: Global { input_count: Count::from(1), output_count: Count::from(0), ..Global::default() },
    /// #     inputs: vec![Input::new(&OutPoint { txid: Txid::hash(b"x"), vout: 0 })],
    /// #     outputs: vec![],
    /// # };
    /// # let bytes = PsbtV0::from_psbt(psbt).expect("lock time").serialize();
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

/// Reports what metadata is degraded by a v0 (BIP-174) encoding.
///
/// # What "Degraded" Means
///
/// Encoding a v2 PSBT as v0 is a lossy conversion. Some v2-only fields have no
/// corresponding v0 key type and are either dropped, resolved into the unsigned
/// transaction, or demoted to unknown keys. This struct categorizes every kind
/// of loss so callers can decide whether the degradation is acceptable before
/// serializing.
///
/// # Degradation Categories
///
/// | Category | What happens | Field |
/// |----------|-------------|-------|
/// | Per-input lock time | [`Input::min_time`] / [`Input::min_height`] are resolved into a single `nLockTime` via [`Psbt::determine_lock_time`]; per-input identity is lost | [`lock_time_inputs`](Self::lock_time_inputs) |
/// | Tx modifiable flags | `PSBT_GLOBAL_TX_MODIFIABLE` (`0x06`) is dropped entirely; the v0 decoder always sets flags to zero | [`tx_modifiable_flags`](Self::tx_modifiable_flags) |
/// | SP global ECDH shares | Encoded as unknown global keys (`0x07`) | `sp_ecdh_shares` |
/// | SP global DLEQ proofs | Encoded as unknown global keys (`0x08`) | `sp_dleq_proofs` |
/// | Per-input SP fields | Encoded as unknown per-input keys (`0x1d` / `0x1e`) | `sp_dropped_inputs` |
/// | Per-output SP fields | Encoded as unknown per-output keys (`0x09` / `0x0a`) | `sp_dropped_outputs` |
///
/// Other v2-only fields (transaction version, input/output counts, sequence
/// numbers) are embedded in the unsigned transaction body and survive the
/// round-trip intact.
///
/// [`Input::min_time`]: crate::Input::min_time
/// [`Input::min_height`]: crate::Input::min_height
/// [`Psbt::determine_lock_time`]: crate::Psbt::determine_lock_time
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct Degraded {
    /// Number of inputs whose per-input lock time requirements
    /// ([`min_time`](crate::Input::min_time) /
    /// [`min_height`](crate::Input::min_height)) are resolved into the
    /// single unsigned transaction `nLockTime`, losing per-input identity.
    pub lock_time_inputs: usize,
    /// The [`TxModifiableFlags`] that will be cleared. `None` means the flags
    /// were already all-zero (no construction state was lost). `Some(flags)`
    /// means the PSBT was still under construction and that signal is
    /// irrevocably lost in the v0 encoding.
    pub tx_modifiable_flags: Option<TxModifiableFlags>,
    /// Number of silent payment ECDH shares encoded as unknown global keys (`0x07`).
    #[cfg(feature = "silent-payments")]
    pub sp_ecdh_shares: usize,
    /// Number of silent payment DLEQ proofs encoded as unknown global keys (`0x08`).
    #[cfg(feature = "silent-payments")]
    pub sp_dleq_proofs: usize,
    /// Number of inputs whose silent payment fields were encoded as unknown
    /// per-input keys (`0x1d` / `0x1e`).
    #[cfg(feature = "silent-payments")]
    pub sp_dropped_inputs: usize,
    /// Number of outputs whose silent payment fields were encoded as unknown
    /// per-output keys (`0x09` and/or `0x0a` was `Some`).
    #[cfg(feature = "silent-payments")]
    pub sp_dropped_outputs: usize,
}

impl Degraded {
    /// Returns `true` if no metadata was degraded by the v0 encoding.
    pub fn is_empty(&self) -> bool {
        let base = self.lock_time_inputs == 0 && self.tx_modifiable_flags.is_none();
        #[cfg(feature = "silent-payments")]
        {
            base && self.sp_ecdh_shares == 0
                && self.sp_dleq_proofs == 0
                && self.sp_dropped_inputs == 0
                && self.sp_dropped_outputs == 0
        }
        #[cfg(not(feature = "silent-payments"))]
        {
            base
        }
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
                    let v0_inputs = decoder.end().map_err(DeserializeError::DecodeInputs)?;
                    let inputs: Vec<Input> = v0_inputs
                        .into_iter()
                        .zip(&tx_inputs)
                        .map(|(vi, (txid, vout, seq))| vi.into_input(*txid, *vout, *seq))
                        .collect();
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
                    let v0_outputs = decoder.end().map_err(DeserializeError::DecodeOutputs)?;
                    let outputs: Vec<_> = v0_outputs
                        .into_iter()
                        .zip(&tx_outputs)
                        .map(|(vo, (amount, script))| vo.into_output(*amount, script.clone()))
                        .collect();
                    self.stage = V0DecoderStage::Done(Psbt { global, inputs, outputs });
                }
                V0DecoderStage::Done(_) => return Ok(DecoderStatus::Ready),
                V0DecoderStage::Errored => unreachable!(),
            }
        }
    }

    fn end(self) -> Result<PsbtV0, Self::Error> {
        match self.stage {
            // The v0 format has no per-input lock time fields (min_time/min_height
            // are v2-only), so no need to derive (and possibly fail on) a lock time.
            V0DecoderStage::Done(psbt) => {
                let lock_time = psbt.global.fallback_lock_time.unwrap_or(absolute::LockTime::ZERO);
                Ok(PsbtV0 { psbt, lock_time })
            }
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use bitcoin::absolute;

    use super::*;
    use crate::{Creator, Input, Output};

    #[test]
    fn degraded_default_is_empty() {
        assert!(Degraded::default().is_empty());
    }

    #[test]
    fn degraded_not_empty_with_lock_time_inputs() {
        let d = Degraded { lock_time_inputs: 1, ..Default::default() };
        assert!(!d.is_empty());
    }

    #[test]
    fn degraded_not_empty_with_tx_modifiable_flags() {
        let d = Degraded {
            tx_modifiable_flags: Some(TxModifiableFlags::with_inputs_modifiable()),
            ..Default::default()
        };
        assert!(!d.is_empty());
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn degraded_not_empty_with_sp_fields() {
        // Each SP field independently makes is_empty() return false.
        let d = Degraded { sp_ecdh_shares: 1, ..Default::default() };
        assert!(!d.is_empty());
        let d = Degraded { sp_dleq_proofs: 1, ..Default::default() };
        assert!(!d.is_empty());
        let d = Degraded { sp_dropped_inputs: 1, ..Default::default() };
        assert!(!d.is_empty());
        let d = Degraded { sp_dropped_outputs: 1, ..Default::default() };
        assert!(!d.is_empty());
    }

    #[test]
    fn degraded_input_locktimes() {
        let mut input = Input::new(&bitcoin::OutPoint::null());
        input.min_time = Some(absolute::Time::from_consensus(500_000_001).unwrap());

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input)
            .expect("well-formed input")
            .output(Output::new(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::from(vec![0xab; 4]),
            }))
            .expect("valid output")
            .psbt();

        let degraded = PsbtV0::from_psbt(psbt).unwrap().degraded();
        assert_eq!(degraded.lock_time_inputs, 1);

        // Reverse case: min_height only, no min_time.
        let height = absolute::Height::from_consensus(100_000).unwrap();
        let mut input = Input::new(&bitcoin::OutPoint::null());
        input.min_height = Some(crate::RequiredHeightLockTime::try_from(height).unwrap());

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input)
            .expect("well-formed input")
            .output(Output::new(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::from(vec![0xab; 4]),
            }))
            .expect("valid output")
            .psbt();

        let degraded = PsbtV0::from_psbt(psbt).unwrap().degraded();
        assert_eq!(degraded.lock_time_inputs, 1);
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn degraded_counts_input_with_only_sp_ecdh() {
        use bitcoin::CompressedPublicKey;

        let pk_bytes = [0x02u8; 33];
        let pk = CompressedPublicKey::from_slice(&pk_bytes).unwrap();

        let mut input = Input::new(&bitcoin::OutPoint::null());
        input.sp_ecdh_shares.insert(pk, pk);

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input)
            .expect("well-formed input")
            .output(Output::new(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::from(vec![0xab; 4]),
            }))
            .expect("valid output")
            .psbt();

        let degraded = PsbtV0::from_psbt(psbt).unwrap().degraded();
        assert_eq!(degraded.sp_dropped_inputs, 1);
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn degraded_counts_input_with_only_sp_dleq() {
        use bitcoin::CompressedPublicKey;

        use crate::DleqProof;

        let pk_bytes = [0x02u8; 33];
        let pk = CompressedPublicKey::from_slice(&pk_bytes).unwrap();

        let mut input = Input::new(&bitcoin::OutPoint::null());
        input.sp_dleq_proofs.insert(pk, DleqProof([0xAB; 64]));

        let psbt = Creator::new()
            .constructor_modifiable()
            .input(input)
            .expect("well-formed input")
            .output(Output::new(bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1),
                script_pubkey: bitcoin::ScriptBuf::from(vec![0xab; 4]),
            }))
            .expect("valid output")
            .psbt();

        let degraded = PsbtV0::from_psbt(psbt).unwrap().degraded();
        assert_eq!(degraded.sp_dropped_inputs, 1);
    }
}
