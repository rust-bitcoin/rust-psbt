// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 output map encoder.
//!
//! v0 outputs omit `amount` and `script_pubkey`, those come from the unsigned transaction.

use bitcoin_consensus_encoding::{CompactSizeEncoder, Encoder, EncoderStatus, IterEncoder};

use crate::consts::{PSBT_OUT_TAP_INTERNAL_KEY, PSBT_OUT_TAP_TREE, PSBT_OUT_WITNESS_SCRIPT};
#[cfg(feature = "silent-payments")]
use crate::encoding::native::SpV0InfoPair;
#[cfg(feature = "silent-payments")]
use crate::encoding::native::SpV0LabelPair;
use crate::encoding::native::{
    OutBip32DerivationIter, OutTapKeyOriginIter, ScriptPair, SeparatorEncoder, TapInternalKeyPair,
    TapTreePair,
};
use crate::encoding::{KeyValueEncoder, PsbtEncode};
use crate::map::{ProprietaryKeyValueIter, UnknownKeyValueIter};
use crate::Output;

pub struct OutputMapEncoder<'e> {
    output: &'e Output,
    state: State<'e>,
}

enum State<'e> {
    WitnessScript(ScriptPair<'e>),
    Bip32Derivations(IterEncoder<OutBip32DerivationIter<'e>>),
    TapInternalKey(TapInternalKeyPair<'e>),
    TapTree(TapTreePair<'e>),
    TapKeyOrigins(IterEncoder<OutTapKeyOriginIter<'e>>),
    Proprietaries(IterEncoder<ProprietaryKeyValueIter<'e>>),
    Unknowns(IterEncoder<UnknownKeyValueIter<'e>>),
    #[cfg(feature = "silent-payments")]
    SpV0Info(SpV0InfoPair<'e>),
    #[cfg(feature = "silent-payments")]
    SpV0Label(SpV0LabelPair<'e>),
    Separator(SeparatorEncoder),
    Done,
}

impl<'e> OutputMapEncoder<'e> {
    pub(crate) fn new(output: &'e Output) -> Self {
        Self { output, state: Self::witness_script_or_next(output) }
    }

    fn next_state(&self) -> State<'e> {
        match &self.state {
            State::WitnessScript(_) => Self::bip32_or_next(self.output),
            State::Bip32Derivations(_) => Self::tap_internal_key_or_next(self.output),
            State::TapInternalKey(_) => Self::tap_tree_or_next(self.output),
            State::TapTree(_) => Self::tap_key_origins_or_next(self.output),
            State::TapKeyOrigins(_) => Self::proprietaries_or_next(self.output),
            State::Proprietaries(_) => Self::unknowns_or_next(self.output),
            State::Unknowns(_) => Self::sp_v0_info_or_next(self.output),
            #[cfg(feature = "silent-payments")]
            State::SpV0Info(_) => Self::sp_v0_label_or_next(self.output),
            #[cfg(feature = "silent-payments")]
            State::SpV0Label(_) => State::Separator(SeparatorEncoder::new()),
            State::Separator(_) => State::Done,
            State::Done => State::Done,
        }
    }

    fn witness_script_or_next(output: &'e Output) -> State<'e> {
        if let Some(ws) = &output.witness_script {
            State::WitnessScript(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_WITNESS_SCRIPT),
                ws.psbt_encoder(),
            ))
        } else {
            Self::bip32_or_next(output)
        }
    }

    fn bip32_or_next(o: &'e Output) -> State<'e> {
        if !o.bip32_derivations.is_empty() {
            State::Bip32Derivations(IterEncoder::new(OutBip32DerivationIter::new(
                o.bip32_derivations.iter(),
            )))
        } else {
            Self::tap_internal_key_or_next(o)
        }
    }

    fn tap_internal_key_or_next(o: &'e Output) -> State<'e> {
        if let Some(key) = o.tap_internal_key {
            State::TapInternalKey(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_TAP_INTERNAL_KEY),
                key.psbt_encoder(),
            ))
        } else {
            Self::tap_tree_or_next(o)
        }
    }

    fn tap_tree_or_next(o: &'e Output) -> State<'e> {
        if let Some(tree) = &o.tap_tree {
            State::TapTree(KeyValueEncoder::from_sized_kv(
                CompactSizeEncoder::new_u64(PSBT_OUT_TAP_TREE),
                tree.psbt_encoder(),
            ))
        } else {
            Self::tap_key_origins_or_next(o)
        }
    }

    fn tap_key_origins_or_next(o: &'e Output) -> State<'e> {
        if !o.tap_key_origins.is_empty() {
            State::TapKeyOrigins(IterEncoder::new(OutTapKeyOriginIter::new(
                o.tap_key_origins.iter(),
            )))
        } else {
            Self::proprietaries_or_next(o)
        }
    }

    fn proprietaries_or_next(o: &'e Output) -> State<'e> {
        if !o.proprietaries.is_empty() {
            State::Proprietaries(IterEncoder::new(ProprietaryKeyValueIter(o.proprietaries.iter())))
        } else {
            Self::unknowns_or_next(o)
        }
    }

    fn unknowns_or_next(o: &'e Output) -> State<'e> {
        if !o.unknowns.is_empty() {
            return State::Unknowns(IterEncoder::new(UnknownKeyValueIter(o.unknowns.iter())));
        }
        Self::sp_v0_info_or_next(o)
    }

    fn sp_v0_info_or_next(_o: &'e Output) -> State<'e> {
        #[cfg(feature = "silent-payments")]
        {
            use crate::consts::PSBT_OUT_SP_V0_INFO;
            if let Some(ref info) = _o.sp_v0_info {
                return State::SpV0Info(KeyValueEncoder::from_sized_kv(
                    CompactSizeEncoder::new_u64(PSBT_OUT_SP_V0_INFO),
                    info.psbt_encoder(),
                ));
            }
            Self::sp_v0_label_or_next(_o)
        }
        #[cfg(not(feature = "silent-payments"))]
        State::Separator(SeparatorEncoder::new())
    }

    #[cfg(feature = "silent-payments")]
    fn sp_v0_label_or_next(o: &'e Output) -> State<'e> {
        #[cfg(feature = "silent-payments")]
        {
            use bitcoin_consensus_encoding::ArrayEncoder;

            use crate::consts::PSBT_OUT_SP_V0_LABEL;
            if let Some(label) = o.sp_v0_label {
                return State::SpV0Label(KeyValueEncoder::from_sized_kv(
                    CompactSizeEncoder::new_u64(PSBT_OUT_SP_V0_LABEL),
                    ArrayEncoder::without_length_prefix(label.to_le_bytes()),
                ));
            }
        }
        State::Separator(SeparatorEncoder::new())
    }
}

impl Encoder for OutputMapEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match &self.state {
            State::WitnessScript(e) => e.current_chunk(),
            State::Bip32Derivations(e) => e.current_chunk(),
            State::TapInternalKey(e) => e.current_chunk(),
            State::TapTree(e) => e.current_chunk(),
            State::TapKeyOrigins(e) => e.current_chunk(),
            State::Proprietaries(e) => e.current_chunk(),
            State::Unknowns(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::SpV0Info(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::SpV0Label(e) => e.current_chunk(),
            State::Separator(e) => e.current_chunk(),
            State::Done => &[],
        }
    }

    fn advance(&mut self) -> EncoderStatus {
        let state_finished = match &mut self.state {
            State::WitnessScript(e) => e.advance().has_finished(),
            State::Bip32Derivations(e) => e.advance().has_finished(),
            State::TapInternalKey(e) => e.advance().has_finished(),
            State::TapTree(e) => e.advance().has_finished(),
            State::TapKeyOrigins(e) => e.advance().has_finished(),
            State::Proprietaries(e) => e.advance().has_finished(),
            State::Unknowns(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::SpV0Info(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::SpV0Label(e) => e.advance().has_finished(),
            State::Separator(e) => e.advance().has_finished(),
            State::Done => return EncoderStatus::Finished,
        };

        if state_finished {
            self.state = self.next_state();
            if matches!(&self.state, State::Done) {
                return EncoderStatus::Finished;
            }
        }

        EncoderStatus::HasMore
    }
}

/// Iterator that wraps each [`Output`](crate::Output) in an
/// [`OutputMapEncoder`].
///
/// Used by [`PsbtV0Encoder`](crate::PsbtV0Encoder) to stream output maps without
/// allocation.
pub(crate) struct Outputs<'e> {
    iter: core::slice::Iter<'e, crate::Output>,
}

impl<'e> Iterator for Outputs<'e> {
    type Item = OutputMapEncoder<'e>;

    fn next(&mut self) -> Option<Self::Item> { self.iter.next().map(OutputMapEncoder::new) }
}

impl<'e> From<core::slice::Iter<'e, crate::Output>> for Outputs<'e> {
    fn from(iter: core::slice::Iter<'e, crate::Output>) -> Self { Self { iter } }
}
