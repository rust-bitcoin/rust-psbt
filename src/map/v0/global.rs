// SPDX-License-Identifier: CC0-1.0

//! PSBT v0 global map encoder.
//!
//! `<global-map> := <unsigned_tx> <xpub>* <proprietary>* <unknown>* 0x00`

use bitcoin_consensus_encoding::{CompactSizeEncoder, Encoder, EncoderStatus, IterEncoder};

use super::unsigned_tx::UnsignedTxEncoder;
use crate::consts::PSBT_GLOBAL_UNSIGNED_TX;
#[cfg(feature = "silent-payments")]
use crate::encoding::native::{DleqKeyValueIter, EcdhKeyValueIter};
use crate::encoding::native::{SeparatorEncoder, XpubKeyValueIter};
use crate::encoding::KeyValueEncoder;
use crate::map::ProprietaryKeyValueIter;

/// Encoder for the PSBT v0 global map.
pub(crate) struct GlobalMapEncoder<'e> {
    psbt: &'e crate::Psbt,
    state: State<'e>,
}

enum State<'e> {
    UnsignedTx(KeyValueEncoder<CompactSizeEncoder, UnsignedTxEncoder<'e>>),
    Xpubs(IterEncoder<XpubKeyValueIter<'e>>),
    Proprietaries(IterEncoder<ProprietaryKeyValueIter<'e>>),
    Unknowns(IterEncoder<crate::map::UnknownKeyValueIter<'e>>),
    #[cfg(feature = "silent-payments")]
    Ecdh(IterEncoder<EcdhKeyValueIter<'e>>),
    #[cfg(feature = "silent-payments")]
    Dleq(IterEncoder<DleqKeyValueIter<'e>>),
    Separator(SeparatorEncoder),
    Done,
}

impl<'e> GlobalMapEncoder<'e> {
    pub(crate) fn new(v0: &'e crate::psbt::PsbtV0<'_>) -> Self {
        Self { psbt: v0.psbt, state: Self::unsigned_tx(v0) }
    }

    fn unsigned_tx(v0: &'e crate::psbt::PsbtV0<'_>) -> State<'e> {
        State::UnsignedTx(KeyValueEncoder::from_sized_kv(
            CompactSizeEncoder::new_u64(PSBT_GLOBAL_UNSIGNED_TX),
            UnsignedTxEncoder::from_psbt(v0),
        ))
    }

    fn next_state(&self) -> State<'e> {
        match &self.state {
            State::UnsignedTx(_) => self.xpubs_or_next(),
            State::Xpubs(_) => self.proprietaries_or_next(),
            State::Proprietaries(_) => self.unknowns_or_next(),
            State::Unknowns(_) => self.ecdh_or_next(),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(_) => self.dleq_or_next(),
            #[cfg(feature = "silent-payments")]
            State::Dleq(_) => State::Separator(SeparatorEncoder::new()),
            State::Separator(_) => State::Done,
            State::Done => State::Done,
        }
    }

    fn xpubs_or_next(&self) -> State<'e> {
        if self.psbt.global.xpubs.is_empty() {
            self.proprietaries_or_next()
        } else {
            State::Xpubs(IterEncoder::new(XpubKeyValueIter::new(self.psbt.global.xpubs.iter())))
        }
    }

    fn proprietaries_or_next(&self) -> State<'e> {
        if self.psbt.global.proprietaries.is_empty() {
            self.unknowns_or_next()
        } else {
            State::Proprietaries(IterEncoder::new(ProprietaryKeyValueIter(
                self.psbt.global.proprietaries.iter(),
            )))
        }
    }

    fn unknowns_or_next(&self) -> State<'e> {
        if self.psbt.global.unknowns.is_empty() {
            self.ecdh_or_next()
        } else {
            State::Unknowns(IterEncoder::new(crate::map::UnknownKeyValueIter(
                self.psbt.global.unknowns.iter(),
            )))
        }
    }

    fn ecdh_or_next(&self) -> State<'e> {
        #[cfg(feature = "silent-payments")]
        {
            if !self.psbt.global.sp_ecdh_shares.is_empty() {
                return State::Ecdh(IterEncoder::new(EcdhKeyValueIter::new(
                    self.psbt.global.sp_ecdh_shares.iter(),
                )));
            }
            self.dleq_or_next()
        }
        #[cfg(not(feature = "silent-payments"))]
        State::Separator(SeparatorEncoder::new())
    }

    #[allow(dead_code)]
    fn dleq_or_next(&self) -> State<'e> {
        #[cfg(feature = "silent-payments")]
        {
            if !self.psbt.global.sp_dleq_proofs.is_empty() {
                return State::Dleq(IterEncoder::new(DleqKeyValueIter::new(
                    self.psbt.global.sp_dleq_proofs.iter(),
                )));
            }
        }
        State::Separator(SeparatorEncoder::new())
    }
}

impl Encoder for GlobalMapEncoder<'_> {
    fn current_chunk(&self) -> &[u8] {
        match &self.state {
            State::UnsignedTx(e) => e.current_chunk(),
            State::Xpubs(e) => e.current_chunk(),
            State::Proprietaries(e) => e.current_chunk(),
            State::Unknowns(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(e) => e.current_chunk(),
            #[cfg(feature = "silent-payments")]
            State::Dleq(e) => e.current_chunk(),
            State::Separator(e) => e.current_chunk(),
            State::Done => &[],
        }
    }

    fn advance(&mut self) -> EncoderStatus {
        let state_finished = match &mut self.state {
            State::UnsignedTx(e) => e.advance().has_finished(),
            State::Xpubs(e) => e.advance().has_finished(),
            State::Proprietaries(e) => e.advance().has_finished(),
            State::Unknowns(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::Ecdh(e) => e.advance().has_finished(),
            #[cfg(feature = "silent-payments")]
            State::Dleq(e) => e.advance().has_finished(),
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
