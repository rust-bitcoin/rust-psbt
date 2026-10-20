// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource};
use bitcoin_consensus_encoding::{
    ArrayDecoder, BytesEncoder, CompactSizeDecoder, CompactSizeDecoderError, Decoder, Decoder2,
    Decoder2Error, DecoderStatus, Encoder2, ExactVecDecoderWith, UnexpectedEofError,
    VecDecoderError,
};

use super::ChildNumberDecoder;
use crate::encoding::{PsbtDecode, PsbtEncode, SliceEncoder};

/// Size of a key source fingerprint in bytes.
const FINGERPRINT_SIZE: usize = 4;
/// Size of a single derivation path child number in bytes.
const CHILD_NUMBER_SIZE: usize = 4;

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a serialized [`KeySource`].
    pub struct KeySourceEncoder<'e>(Encoder2<BytesEncoder<'e>, SliceEncoder<'e, ChildNumber>>);
}

impl PsbtEncode for KeySource {
    type Encoder<'e>
        = KeySourceEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        KeySourceEncoder::new(Encoder2::new(
            BytesEncoder::without_length_prefix(self.0.as_bytes()),
            <SliceEncoder<'_, ChildNumber>>::without_length_prefix(self.1.as_ref()),
        ))
    }
}

/// Internal state for [`KeySourceDecoder`].
#[derive(Debug)]
enum DecoderState {
    /// Reading the compact-size length prefix.
    ReadingPrefix(CompactSizeDecoder),
    /// Reading the fingerprint followed by the derivation path child numbers.
    ReadingValue(Decoder2<ArrayDecoder<FINGERPRINT_SIZE>, ExactVecDecoderWith<ChildNumberDecoder>>),
    /// A previous [`Decoder::push_bytes`] call errored; the decoder is unusable.
    Errored,
}

/// Decoder for a [`KeySource`] value (fingerprint + derivation path).
#[derive(Debug)]
pub struct KeySourceDecoder {
    state: DecoderState,
}

impl Default for KeySourceDecoder {
    fn default() -> Self { Self { state: DecoderState::ReadingPrefix(CompactSizeDecoder::new()) } }
}

impl Decoder for KeySourceDecoder {
    type Output = KeySource;
    type Error = KeySourceDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        use DecoderState::*;

        // Decode the compact-size length prefix.
        if matches!(self.state, ReadingPrefix(_)) {
            let mut prefix = match core::mem::replace(&mut self.state, Errored) {
                ReadingPrefix(p) => p,
                _ => unreachable!(),
            };
            if prefix.push_bytes(bytes).map_err(KeySourceDecodeError::LengthPrefix)?.needs_more() {
                self.state = ReadingPrefix(prefix);
                return Ok(DecoderStatus::NeedsMore);
            }
            let len = prefix.end().map_err(KeySourceDecodeError::LengthPrefix)?;
            if len < FINGERPRINT_SIZE {
                return Err(KeySourceDecodeError::TooShort(len));
            }
            if len % CHILD_NUMBER_SIZE != 0 {
                return Err(KeySourceDecodeError::InvalidPathLength(len));
            }
            let path_count = (len - FINGERPRINT_SIZE) / CHILD_NUMBER_SIZE;
            self.state = ReadingValue(Decoder2::new(
                ArrayDecoder::new(),
                ExactVecDecoderWith::new(path_count),
            ));
        }

        // Read the fingerprint and path.
        match &mut self.state {
            ReadingValue(dec) => dec.push_bytes(bytes).map_err(|e| match e {
                Decoder2Error::First(e) => KeySourceDecodeError::Fingerprint(e),
                Decoder2Error::Second(e) => KeySourceDecodeError::Path(e),
            }),
            ReadingPrefix(_) => unreachable!(),
            Errored => panic!("use of failed decoder"),
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            DecoderState::ReadingPrefix(p) => {
                let err = p.end().unwrap_err();
                Err(KeySourceDecodeError::LengthPrefix(err))
            }
            DecoderState::ReadingValue(dec) => {
                let (fingerprint, path) = dec.end().map_err(|e| match e {
                    Decoder2Error::First(e) => KeySourceDecodeError::Fingerprint(e),
                    Decoder2Error::Second(e) => KeySourceDecodeError::Path(e),
                })?;
                Ok((Fingerprint::from(fingerprint), DerivationPath::from(path)))
            }
            DecoderState::Errored => panic!("use of failed decoder"),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.state {
            DecoderState::ReadingPrefix(dec) => dec.read_limit(),
            DecoderState::ReadingValue(dec) => dec.read_limit(),
            DecoderState::Errored => 0,
        }
    }
}

impl PsbtDecode for KeySource {
    type Decoder = KeySourceDecoder;
}

/// Error decoding a [`KeySource`] (fingerprint + derivation path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySourceDecodeError {
    /// Error decoding the compact-size length prefix.
    LengthPrefix(CompactSizeDecoderError),
    /// Error decoding the 4-byte fingerprint.
    Fingerprint(UnexpectedEofError),
    /// Error decoding the derivation path.
    Path(VecDecoderError<UnexpectedEofError>),
    /// The value is shorter than the 4-byte fingerprint.
    TooShort(usize),
    /// The derivation path is not a multiple of 4 bytes.
    InvalidPathLength(usize),
}

impl fmt::Display for KeySourceDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthPrefix(e) => write!(f, "error decoding key source length prefix: {e}"),
            Self::Fingerprint(e) => write!(f, "error decoding key source fingerprint: {e}"),
            Self::Path(e) => write!(f, "error decoding key source derivation path: {e}"),
            Self::TooShort(len) => {
                write!(f, "key source too short ({} bytes, need at least 4)", len)
            }
            Self::InvalidPathLength(len) => {
                write!(f, "key source path not aligned ({} bytes, not a multiple of 4)", len)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeySourceDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LengthPrefix(e) => Some(e),
            Self::Fingerprint(e) => Some(e),
            Self::Path(e) => Some(e),
            Self::TooShort(_) | Self::InvalidPathLength(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use bitcoin::bip32::{DerivationPath, Fingerprint};
    use bitcoin_consensus_encoding::ExactSizeEncoder;

    use super::*;
    use crate::encoding::encode_to_vec;

    /// Build test data from a key source, prepending the compact-size prefix.
    fn encode(key_source: &KeySource) -> Vec<u8> {
        let psbt_enc = key_source.psbt_encoder();
        let mut enc = Encoder2::new(
            bitcoin_consensus_encoding::CompactSizeEncoder::new(psbt_enc.len()),
            psbt_enc,
        );
        bitcoin_consensus_encoding::drain_to_vec(&mut enc)
    }

    #[test]
    fn encode_empty_path() {
        let key_source: KeySource =
            (Fingerprint::from([0x42, 0x99, 0x69, 0xf0]), DerivationPath::default());
        let bytes = encode_to_vec(&key_source);
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes, [0x42, 0x99, 0x69, 0xf0]);
    }

    #[test]
    fn encode_multi_element_path() {
        let path: DerivationPath = [
            ChildNumber::from_hardened_idx(84).unwrap(),
            ChildNumber::from_normal_idx(1).unwrap(),
            ChildNumber::from_hardened_idx(2).unwrap(),
        ]
        .into_iter()
        .collect();
        let key_source: KeySource = (Fingerprint::from([0x12, 0x34, 0x56, 0x78]), path);

        let bytes = encode_to_vec(&key_source);
        assert_eq!(bytes.len(), 4 + 3 * 4);
        let mut expected = vec![0x12, 0x34, 0x56, 0x78];
        for n in &key_source.1 {
            expected.extend(u32::from(*n).to_le_bytes());
        }
        assert_eq!(bytes, expected);
    }

    #[test]
    fn decoder_read_limit_lifecycle() {
        let mut decoder = KeySourceDecoder::default();
        assert!(decoder.read_limit() > 0);

        // Fingerprint-only value, compact_size(4) + 4 bytes.
        let mut bytes: &[u8] = &[0x04, 0xde, 0xad, 0xbe, 0xef];
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    fn decode_fingerprint_only() {
        let mut decoder = KeySourceDecoder::default();
        // Fingerprint without derivation, compact_size(4) + 4-byte fingerprint.
        let mut bytes: &[u8] = &[0x04, 0xde, 0xad, 0xbe, 0xef];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        let (fingerprint, derivation) = decoder.end().unwrap();
        assert_eq!(fingerprint, Fingerprint::from([0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(derivation, DerivationPath::master());
    }

    #[test]
    fn decode_with_path() {
        let mut decoder = KeySourceDecoder::default();
        // Fingerprint + one child, compact_size(8) + 4-byte fingerprint + 4-byte child.
        let mut bytes: &[u8] = &[0x08, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x00, 0x00, 0x00];
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        let (fingerprint, derivation) = decoder.end().unwrap();
        assert_eq!(fingerprint, Fingerprint::from([0xaa, 0xbb, 0xcc, 0xdd]));
        let children: Vec<ChildNumber> = derivation.into_iter().copied().collect();
        assert_eq!(children.len(), 1);
        assert_eq!(u32::from(children[0]), 1);
    }

    #[test]
    fn decode_too_short_rejects_early() {
        let mut decoder = KeySourceDecoder::default();
        // 3 bytes, shorter than the 4-byte fingerprint.
        let mut bytes: &[u8] = &[0x03, 0xde, 0xad, 0xbe];
        let err = decoder.push_bytes(&mut bytes).unwrap_err();
        assert_eq!(err, KeySourceDecodeError::TooShort(3));
    }

    #[test]
    fn decode_invalid_path_length_rejects_early() {
        let mut decoder = KeySourceDecoder::default();
        // Fingerprint + 2 extra bytes, compact_size(6) but path is not 4-byte aligned.
        let mut bytes: &[u8] = &[0x06, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00];
        let err = decoder.push_bytes(&mut bytes).unwrap_err();
        assert_eq!(err, KeySourceDecodeError::InvalidPathLength(6));
    }

    #[test]
    fn decode_roundtrip() {
        let key_source: KeySource = (
            Fingerprint::from([0xde, 0xad, 0xbe, 0xef]),
            [ChildNumber::from_hardened_idx(84).unwrap(), ChildNumber::from_normal_idx(0).unwrap()]
                .into_iter()
                .collect(),
        );
        let encoded = encode(&key_source);

        let mut decoder = KeySourceDecoder::default();
        let mut bytes: &[u8] = &encoded;
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        assert!(bytes.is_empty());

        let decoded = decoder.end().unwrap();
        assert_eq!(decoded.0, key_source.0);
        assert_eq!(decoded.1.as_ref(), key_source.1.as_ref());
    }

    #[test]
    fn decode_truncated_path_reports_eof() {
        let mut decoder = KeySourceDecoder::default();
        // compact_size(8) + fingerprint + only 2 of the 4 path bytes.
        let mut bytes: &[u8] = &[0x08, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x00];
        assert!(decoder.push_bytes(&mut bytes).unwrap().needs_more());
        let err = decoder.end().unwrap_err();
        assert!(matches!(err, KeySourceDecodeError::Path(_)));
    }
}
