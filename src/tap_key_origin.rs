// SPDX-License-Identifier: CC0-1.0

//! Tap key origin PSBT field value type.
//!
//! Corresponds to the value format of PSBT key types `PSBT_IN_TAP_BIP32_DERIVATION` (0x16)
//! and `PSBT_OUT_TAP_BIP32_DERIVATION` (0x07) as defined in [BIP-371].
//!
//! [BIP-371]: <https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki>

use alloc::vec::Vec;
use core::fmt;

use bitcoin::bip32::{self, ChildNumber, KeySource};
use bitcoin::hashes::Hash as _;
use bitcoin::taproot::TapLeafHash;
use bitcoin_consensus_encoding::{
    ArrayDecoder, CompactSizeDecoder, CompactSizeDecoderError, Decoder, DecoderStatus, Encoder2,
    UnexpectedEofError,
};

use crate::encoding::codecs::key_source::KeySourceEncoder;
use crate::encoding::{PrefixedSliceEncoder, PsbtDecode, PsbtEncode};

/// Expected byte length of a single leaf hash.
const LEAF_HASH_LEN: usize = 32;
/// Expected byte length of the master fingerprint field.
const FINGERPRINT_LEN: usize = 4;
/// Expected byte length of a single derivation path step.
const PATH_STEP_LEN: usize = 4;

/// A tap key origin: leaf hashes with a key source.
pub(crate) type TapKeyOrigin = (Vec<TapLeafHash>, KeySource);

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a [`TapKeyOrigin`] value: `count <hash*a> <key source>` where `count` is a
    /// compact-size prefix.
    pub struct LeafHashVecKeySourceEncoder<'e>(
        Encoder2<PrefixedSliceEncoder<'e, TapLeafHash>, KeySourceEncoder<'e>>
    );
}

impl PsbtEncode for TapKeyOrigin {
    type Encoder<'e>
        = LeafHashVecKeySourceEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        LeafHashVecKeySourceEncoder::new(Encoder2::new(
            <PrefixedSliceEncoder<'_, TapLeafHash>>::new(self.0.as_slice()),
            self.1.psbt_encoder(),
        ))
    }
}

/// Push-based decoder for a [`TapKeyOrigin`] value.
///
/// Reads the PSBT framing compact-size length prefix, then incrementally parses the value
/// body: `<length> <count> <hash*count> <fingerprint> <path>`.
#[derive(Debug, Default)]
pub struct TapKeyOriginDecoder {
    /// Current decoding stage.
    stage: Stage,
    /// Leaf hashes accumulated so far.
    leaf_hashes: Vec<TapLeafHash>,
    /// Master fingerprint, set when the [`Stage::Fingerprint`] stage completes.
    fingerprint: Option<bip32::Fingerprint>,
    /// Derivation path steps accumulated so far.
    path_steps: Vec<ChildNumber>,
}

#[derive(Debug)]
enum Stage {
    /// Reading the PSBT framing compact-size value length.
    ReadingPrefix(CompactSizeDecoder),
    /// Reading the value body bytes. `remaining` bytes counts down to zero.
    ReadingValue { remaining: usize, inner: ValueStage },
    /// All bytes consumed, ready for [`Decoder::end`].
    Done,
    /// Previous call errored; this decoder is unusable.
    Errored,
}

impl Default for Stage {
    fn default() -> Self { Self::ReadingPrefix(CompactSizeDecoder::new()) }
}

#[derive(Debug)]
enum ValueStage {
    /// Processing the compact-size leaf-hash count.
    Count(CompactSizeDecoder),
    /// Processing a 32-byte [`TapLeafHash`]. The `usize` is the total number of hashes expected.
    LeafHash(ArrayDecoder<LEAF_HASH_LEN>, usize),
    /// Processing the 4-byte [`bip32::Fingerprint`].
    Fingerprint(ArrayDecoder<FINGERPRINT_LEN>),
    /// Processing a 4-byte derivation path step ([`ChildNumber`]).
    PathStep(ArrayDecoder<PATH_STEP_LEN>),
}

impl Decoder for TapKeyOriginDecoder {
    type Output = TapKeyOrigin;
    type Error = TapKeyOriginDecodeError;

    #[allow(clippy::too_many_lines)]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        loop {
            match core::mem::replace(&mut self.stage, Stage::Errored) {
                Stage::ReadingPrefix(mut decoder) => {
                    let status =
                        decoder.push_bytes(bytes).map_err(TapKeyOriginDecodeError::LengthPrefix)?;
                    if status.needs_more() {
                        self.stage = Stage::ReadingPrefix(decoder);
                        return Ok(DecoderStatus::NeedsMore);
                    }
                    let length = decoder.end().map_err(TapKeyOriginDecodeError::LengthPrefix)?;
                    self.stage = Stage::ReadingValue {
                        remaining: length,
                        inner: ValueStage::Count(CompactSizeDecoder::new()),
                    };
                }
                Stage::ReadingValue { remaining, inner } => {
                    self.stage = match inner {
                        ValueStage::Count(mut decoder) => {
                            // Manually track read bytes since compact size is dynamic.
                            let count_before = bytes.len();
                            let status = decoder
                                .push_bytes(bytes)
                                .map_err(TapKeyOriginDecodeError::Count)?;
                            let remaining = remaining - (count_before - bytes.len());

                            if status.needs_more() {
                                Stage::ReadingValue { remaining, inner: ValueStage::Count(decoder) }
                            } else {
                                let count =
                                    decoder.end().map_err(TapKeyOriginDecodeError::Count)?;
                                if count == 0 {
                                    Stage::ReadingValue {
                                        remaining,
                                        inner: ValueStage::Fingerprint(ArrayDecoder::default()),
                                    }
                                } else {
                                    Stage::ReadingValue {
                                        remaining,
                                        inner: ValueStage::LeafHash(ArrayDecoder::default(), count),
                                    }
                                }
                            }
                        }
                        ValueStage::LeafHash(mut decoder, count) => {
                            if decoder
                                .push_bytes(bytes)
                                .map_err(TapKeyOriginDecodeError::LeafHash)?
                                .needs_more()
                            {
                                Stage::ReadingValue {
                                    remaining,
                                    inner: ValueStage::LeafHash(decoder, count),
                                }
                            } else {
                                let hash_bytes =
                                    decoder.end().map_err(TapKeyOriginDecodeError::LeafHash)?;
                                self.leaf_hashes.push(TapLeafHash::from_byte_array(hash_bytes));
                                let remaining = remaining - LEAF_HASH_LEN;
                                if self.leaf_hashes.len() == count {
                                    Stage::ReadingValue {
                                        remaining,
                                        inner: ValueStage::Fingerprint(ArrayDecoder::default()),
                                    }
                                } else {
                                    Stage::ReadingValue {
                                        remaining,
                                        inner: ValueStage::LeafHash(ArrayDecoder::default(), count),
                                    }
                                }
                            }
                        }
                        ValueStage::Fingerprint(mut decoder) => {
                            if decoder
                                .push_bytes(bytes)
                                .map_err(TapKeyOriginDecodeError::Fingerprint)?
                                .needs_more()
                            {
                                Stage::ReadingValue {
                                    remaining,
                                    inner: ValueStage::Fingerprint(decoder),
                                }
                            } else {
                                let fingerprint =
                                    decoder.end().map_err(TapKeyOriginDecodeError::Fingerprint)?;
                                self.fingerprint = Some(bip32::Fingerprint::from(fingerprint));
                                let remaining = remaining - FINGERPRINT_LEN;
                                if remaining == 0 {
                                    Stage::Done
                                } else {
                                    Stage::ReadingValue {
                                        remaining,
                                        inner: ValueStage::PathStep(ArrayDecoder::default()),
                                    }
                                }
                            }
                        }
                        ValueStage::PathStep(mut decoder) => {
                            if decoder
                                .push_bytes(bytes)
                                .map_err(TapKeyOriginDecodeError::PathStep)?
                                .needs_more()
                            {
                                Stage::ReadingValue {
                                    remaining,
                                    inner: ValueStage::PathStep(decoder),
                                }
                            } else {
                                let step_bytes =
                                    decoder.end().map_err(TapKeyOriginDecodeError::PathStep)?;
                                self.path_steps
                                    .push(ChildNumber::from(u32::from_le_bytes(step_bytes)));
                                let remaining = remaining - PATH_STEP_LEN;
                                if remaining == 0 {
                                    Stage::Done
                                } else {
                                    Stage::ReadingValue {
                                        remaining,
                                        inner: ValueStage::PathStep(ArrayDecoder::default()),
                                    }
                                }
                            }
                        }
                    };
                    if matches!(&self.stage, Stage::Done) {
                        return Ok(DecoderStatus::Ready);
                    }
                    if bytes.is_empty() {
                        return Ok(DecoderStatus::NeedsMore);
                    }
                }
                Stage::Done => return Ok(DecoderStatus::Ready),
                Stage::Errored => panic!("push_bytes on errored decoder"),
            }
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let Self { stage, leaf_hashes, fingerprint, path_steps, .. } = self;
        match stage {
            Stage::Done => {
                let key_source = (
                    fingerprint.ok_or(TapKeyOriginDecodeError::MissingFingerprint)?,
                    bip32::DerivationPath::from(path_steps),
                );
                Ok((leaf_hashes, key_source))
            }
            _ => Err(TapKeyOriginDecodeError::EarlyEnd),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            Stage::ReadingPrefix(prefix) => prefix.read_limit(),
            Stage::ReadingValue { remaining, .. } => *remaining,
            Stage::Done | Stage::Errored => 0,
        }
    }
}

impl PsbtDecode for TapKeyOrigin {
    type Decoder = TapKeyOriginDecoder;
}

/// Error decoding a [`TapKeyOrigin`] value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapKeyOriginDecodeError {
    /// An error decoding the value length prefix.
    LengthPrefix(CompactSizeDecoderError),
    /// An error reading the leaf-hash count byte.
    Count(CompactSizeDecoderError),
    /// An error reading a leaf hash.
    LeafHash(UnexpectedEofError),
    /// An error reading the master fingerprint.
    Fingerprint(UnexpectedEofError),
    /// An error reading a derivation path step.
    PathStep(UnexpectedEofError),
    /// The value did not contain a fingerprint.
    MissingFingerprint,
    /// Called [`Decoder::end`] before [`Decoder::push_bytes`] returned [`DecoderStatus::Ready`].
    EarlyEnd,
}

impl fmt::Display for TapKeyOriginDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthPrefix(e) => write!(f, "error decoding tap key origin framing: {e}"),
            Self::Count(e) => write!(f, "error decoding tap key origin count: {e}"),
            Self::LeafHash(e) => write!(f, "error decoding leaf hash: {e}"),
            Self::Fingerprint(e) => write!(f, "error decoding master fingerprint: {e}"),
            Self::PathStep(e) => write!(f, "error decoding derivation path step: {e}"),
            Self::MissingFingerprint => write!(f, "tap key origin missing fingerprint"),
            Self::EarlyEnd => write!(f, "end called before push_bytes returned Ready"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TapKeyOriginDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LengthPrefix(e) => Some(e),
            Self::Count(e) => Some(e),
            Self::LeafHash(e) => Some(e),
            Self::Fingerprint(e) => Some(e),
            Self::PathStep(e) => Some(e),
            Self::MissingFingerprint | Self::EarlyEnd => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_limit_lifecycle() {
        let mut decoder = TapKeyOriginDecoder::default();
        assert!(decoder.read_limit() > 0);

        // Minimal valid value: count=0, fingerprint=0x00000000, no path.
        // Framing compact_size = 5, then count byte, then 4-byte fingerprint.
        let mut bytes: &[u8] = &[0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    fn count_exhausts_input() {
        let mut decoder = TapKeyOriginDecoder::default();
        // Framing prefix (1 byte) + count byte (1 byte) with no trailing data.
        let mut bytes: &[u8] = &[0x05, 0x00];
        assert!(decoder.push_bytes(&mut bytes).unwrap().needs_more());
        assert_eq!(decoder.read_limit(), 4);
    }
}
