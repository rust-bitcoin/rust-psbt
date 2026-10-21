// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::ecdsa;
use bitcoin_consensus_encoding::{
    CompactSizeDecoder, CompactSizeDecoderError, Decoder, DecoderStatus, Encoder, EncoderStatus,
    ExactSizeEncoder,
};

use crate::encoding::PsbtEncode;

/// Maximum size of a DER-encoded ECDSA signature (two 32-byte scalars, each possibly padded).
const MAX_DER_SIZE: usize = 72;
/// Size of a single sighash type byte.
const SIGHASH_SIZE: usize = 1;
/// Maximum size of an ECDSA signature including the sighash type byte.
const MAX_SIG_SIZE: usize = MAX_DER_SIZE + SIGHASH_SIZE;

/// Encoder for an [`ecdsa::Signature`].
///
/// Unlike the [`taproot::Signature`](bitcoin::taproot::Signature) encoder, which can reference the
/// 64 signature bytes already stored inline in the struct, ECDSA signatures store `(r, s)` as
/// scalars, not as a serialized byte array. The DER encoding is computed on the fly by
/// calling [`ecdsa::Signature::serialize`], which produces a small stack-allocated buffer (max 73
/// bytes). The encoder owns this buffer and yields it as a single chunk.
#[derive(Debug)]
pub struct EcdsaSignatureEncoder {
    serialized: ecdsa::SerializedSignature,
}

impl EcdsaSignatureEncoder {
    fn new(sig: &ecdsa::Signature) -> Self { Self { serialized: sig.serialize() } }
}

impl Encoder for EcdsaSignatureEncoder {
    fn current_chunk(&self) -> &[u8] { &self.serialized }

    fn advance(&mut self) -> EncoderStatus { EncoderStatus::Finished }
}

impl ExactSizeEncoder for EcdsaSignatureEncoder {
    fn len(&self) -> usize { self.serialized.len() }
}

impl PsbtEncode for ecdsa::Signature {
    type Encoder<'e> = EcdsaSignatureEncoder;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { EcdsaSignatureEncoder::new(self) }
}

/// Internal state for [`EcdsaSignatureDecoder`].
#[derive(Debug)]
enum DecoderState {
    /// Reading the compact-size length prefix.
    ReadingPrefix(CompactSizeDecoder),
    /// Reading the value bytes into a stack buffer.
    ReadingValue {
        buf: [u8; MAX_SIG_SIZE],
        /// Number of bytes written into `buf`.
        written: usize,
        /// Total number of bytes expected (from the length prefix).
        expected: usize,
    },
    /// A previous [`Decoder::push_bytes`] call errored; the decoder is unusable.
    Errored,
}

/// Decoder for an [`ecdsa::Signature`] value.
///
/// Uses a push-based state machine, first decodes the compact-size length prefix,
/// then reads that many bytes into a stack-allocated buffer. No heap allocation.
///
/// The value buffering is hand-rolled to keep the buffer on the stack. ECDSA signatures are
/// variable-length, their DER encoding ranges from 9 to 73 bytes depending on whether either
/// scalar needs a leading zero padding byte.
#[derive(Debug)]
pub struct EcdsaSignatureDecoder {
    state: DecoderState,
}

impl Default for EcdsaSignatureDecoder {
    fn default() -> Self { Self { state: DecoderState::ReadingPrefix(CompactSizeDecoder::new()) } }
}

impl Decoder for EcdsaSignatureDecoder {
    type Output = ecdsa::Signature;
    type Error = EcdsaSignatureDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        use DecoderState::*;

        if matches!(self.state, ReadingPrefix(_)) {
            let mut prefix = match core::mem::replace(&mut self.state, Errored) {
                ReadingPrefix(p) => p,
                _ => unreachable!(),
            };
            if prefix
                .push_bytes(bytes)
                .map_err(EcdsaSignatureDecodeError::LengthPrefix)?
                .needs_more()
            {
                self.state = ReadingPrefix(prefix);
                return Ok(DecoderStatus::NeedsMore);
            }
            let len = prefix.end().map_err(EcdsaSignatureDecodeError::LengthPrefix)?;
            if len > MAX_SIG_SIZE {
                return Err(EcdsaSignatureDecodeError::InvalidLength(len));
            }
            self.state = ReadingValue { buf: [0; MAX_SIG_SIZE], written: 0, expected: len };
        }

        match &mut self.state {
            ReadingValue { buf, written, expected } => {
                let remaining = *expected - *written;
                let copy_len = bytes.len().min(remaining);
                buf[*written..*written + copy_len].copy_from_slice(&bytes[..copy_len]);
                *written += copy_len;
                *bytes = &bytes[copy_len..];

                if *written == *expected {
                    Ok(DecoderStatus::Ready)
                } else {
                    Ok(DecoderStatus::NeedsMore)
                }
            }
            ReadingPrefix(_) => unreachable!(),
            Errored => panic!("use of failed decoder"),
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            DecoderState::ReadingPrefix(p) => {
                // Prefix never completed; end() surfaces the compact-size error.
                let err = p.end().unwrap_err();
                Err(EcdsaSignatureDecodeError::LengthPrefix(err))
            }
            DecoderState::ReadingValue { buf, written, expected } => {
                if written != expected {
                    let missing = expected - written;
                    return Err(EcdsaSignatureDecodeError::UnexpectedEof(missing));
                }
                ecdsa::Signature::from_slice(&buf[..expected])
                    .map_err(EcdsaSignatureDecodeError::InvalidSignature)
            }
            DecoderState::Errored => panic!("use of failed decoder"),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.state {
            DecoderState::ReadingPrefix(dec) => dec.read_limit(),
            DecoderState::ReadingValue { written, expected, .. } => expected - written,
            DecoderState::Errored => 0,
        }
    }
}

/// Error decoding an [`ecdsa::Signature`] value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaSignatureDecodeError {
    /// Error decoding the compact-size length prefix.
    LengthPrefix(CompactSizeDecoderError),
    /// Not enough bytes were provided for the declared length.
    UnexpectedEof(usize),
    /// The declared length exceeds the maximum ECDSA signature size (73 bytes).
    InvalidLength(usize),
    /// The bytes are not a valid ECDSA signature.
    InvalidSignature(ecdsa::Error),
}

impl fmt::Display for EcdsaSignatureDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthPrefix(e) => {
                write!(f, "error decoding ECDSA signature length prefix: {e}")
            }
            Self::UnexpectedEof(missing) =>
                write!(f, "unexpected EOF decoding ECDSA signature: need {} more bytes", missing),
            Self::InvalidLength(len) => {
                write!(f, "invalid ECDSA signature length ({len} bytes, max is {MAX_SIG_SIZE})")
            }
            Self::InvalidSignature(e) => write!(f, "invalid ECDSA signature: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EcdsaSignatureDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LengthPrefix(e) => Some(e),
            Self::UnexpectedEof(_) => None,
            Self::InvalidLength(_) => None,
            Self::InvalidSignature(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use bitcoin::ecdsa;
    use bitcoin_consensus_encoding::{drain_to_vec, CompactSizeEncoder, Encoder2};

    use super::*;
    use crate::encoding::PsbtEncode;

    /// Build test data from a signature, prepending the compact-size prefix.
    fn encode(sig: &ecdsa::Signature) -> Vec<u8> {
        let psbt_enc = sig.psbt_encoder();
        let mut enc = Encoder2::new(CompactSizeEncoder::new(psbt_enc.len()), psbt_enc);
        drain_to_vec(&mut enc)
    }

    /// Exercise the decoder on a pathological minimal signature (r=1, s=1, DER 8 bytes + 1 sighash).
    #[test]
    fn decode_minimal_signature() {
        let der = bitcoin::secp256k1::ecdsa::Signature::from_der(&[
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        ])
        .unwrap();
        let sig = ecdsa::Signature { signature: der, sighash_type: bitcoin::EcdsaSighashType::All };
        let encoded = encode(&sig);

        let mut decoder = EcdsaSignatureDecoder::default();
        assert!(decoder.read_limit() > 0, "initial read_limit should be > 0 (prefix)");

        let mut bytes: &[u8] = &encoded;
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0);

        let decoded = decoder.end().unwrap();
        assert_eq!(decoded.sighash_type, bitcoin::EcdsaSighashType::All);
    }

    /// Exercise the decoder on a 73-byte signature (max size: two padded scalars + sighash).
    #[test]
    fn decode_maximal_signature() {
        let mut compact = [0u8; 64];
        compact[0] = 0x80;
        compact[32] = 0x80;
        let raw = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact).unwrap();
        let sig = ecdsa::Signature {
            signature: raw,
            sighash_type: bitcoin::EcdsaSighashType::NonePlusAnyoneCanPay,
        };
        let encoded = encode(&sig);
        assert_eq!(encoded.len(), 1 + MAX_SIG_SIZE, "compact_size(73) + 73");

        let mut decoder = EcdsaSignatureDecoder::default();
        let mut bytes: &[u8] = &encoded;
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());

        let decoded = decoder.end().unwrap();
        assert_eq!(decoded.sighash_type, bitcoin::EcdsaSighashType::NonePlusAnyoneCanPay);
    }

    #[test]
    fn read_limit_lifecycle() {
        let der = bitcoin::secp256k1::ecdsa::Signature::from_der(&[
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        ])
        .unwrap();
        let sig = ecdsa::Signature { signature: der, sighash_type: bitcoin::EcdsaSighashType::All };
        let encoded = encode(&sig);

        let mut decoder = EcdsaSignatureDecoder::default();
        assert_eq!(decoder.read_limit(), 1);

        let mut remaining = encoded.as_slice();
        let mut byte = &remaining[..1];
        decoder.push_bytes(&mut byte).unwrap();
        remaining = &remaining[1..];
        assert_eq!(decoder.read_limit(), 9, "after prefix, read_limit jumps to value size");

        while decoder.read_limit() > 0 {
            let mut byte = &remaining[..1];
            let status = decoder.push_bytes(&mut byte).unwrap();
            remaining = &remaining[1..];
            if status.is_ready() {
                assert_eq!(decoder.read_limit(), 0);
            }
        }
    }

    /// An invalid declared length is rejected early.
    #[test]
    fn reject_invalid_length() {
        let mut bytes: &[u8] = &[0x4a, 0x00];
        let mut decoder = EcdsaSignatureDecoder::default();
        let err = decoder.push_bytes(&mut bytes).unwrap_err();
        assert!(matches!(err, EcdsaSignatureDecodeError::InvalidLength(74)));
    }

    /// Ending before the full value is received reports the exact number of missing bytes.
    #[test]
    fn end_before_value_complete_reports_missing() {
        let der = bitcoin::secp256k1::ecdsa::Signature::from_der(&[
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        ])
        .unwrap();
        let sig = ecdsa::Signature { signature: der, sighash_type: bitcoin::EcdsaSighashType::All };
        let encoded = encode(&sig);

        let mut decoder = EcdsaSignatureDecoder::default();
        // Feed the prefix plus only 2 of the 9 value bytes.
        let mut bytes: &[u8] = &encoded[..3];
        assert!(decoder.push_bytes(&mut bytes).unwrap().needs_more());
        assert!(bytes.is_empty());

        let err = decoder.end().unwrap_err();
        assert_eq!(err, EcdsaSignatureDecodeError::UnexpectedEof(7));
    }

    /// Feeding more bytes into the hand-rolled buffering logic than the value length consumes
    /// exactly the value and leaves the rest.
    #[test]
    fn push_bytes_consumes_exactly_value_bytes() {
        let der = bitcoin::secp256k1::ecdsa::Signature::from_der(&[
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
        ])
        .unwrap();
        let sig = ecdsa::Signature { signature: der, sighash_type: bitcoin::EcdsaSighashType::All };
        let mut extra = encode(&sig);
        extra.extend_from_slice(&[0xff, 0xee]);

        let mut decoder = EcdsaSignatureDecoder::default();

        let mut first: &[u8] = &extra[..5];
        assert!(decoder.push_bytes(&mut first).unwrap().needs_more());
        assert!(first.is_empty());

        let mut second: &[u8] = &extra[5..];
        assert!(decoder.push_bytes(&mut second).unwrap().is_ready());
        assert_eq!(second.len(), 2, "only the trailing bytes remain unconsumed");
    }

    /// Encoder reports the correct size for signatures whose DER encoding varies with scalar
    /// padding. Strict DER prepends a leading zero byte to a scalar whose high bit is set, so
    /// differently-sized scalars produce differently-sized encodings.
    #[test]
    fn encoded_size_varies_with_der_size() {
        // Builds a signature from two 32-byte big-endian scalars.
        fn sig(r: &[u8; 32], s: &[u8; 32]) -> ecdsa::Signature {
            let mut compact = [0u8; 64];
            compact[..32].copy_from_slice(r);
            compact[32..].copy_from_slice(s);
            let raw = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact).unwrap();
            ecdsa::Signature { signature: raw, sighash_type: bitcoin::EcdsaSighashType::All }
        }

        // r = 1, s = 1 -> minimal DER (8 bytes), +1 sighash byte = 9.
        let mut one = [0u8; 32];
        one[31] = 0x01;
        let minimal = sig(&one, &one);

        // r, s each 32 bytes, high bits clear -> no padding (70-byte DER), +1 = 71.
        let low = [0x01; 32];
        let mid = sig(&low, &low);

        // r padded (high bit set), s not -> 71-byte DER, +1 = 72.
        let high = [0x80; 32];
        let one_pad = sig(&high, &low);

        // r, s both padded -> 72-byte DER, +1 = 73.
        let both_pad = sig(&high, &high);

        // Use the encoder directly to check `ExactSizeEncoder` len and remove mutants.
        let minimal_len = minimal.psbt_encoder().len();
        let mid_len = mid.psbt_encoder().len();
        let one_pad_len = one_pad.psbt_encoder().len();
        let both_pad_len = both_pad.psbt_encoder().len();

        assert_eq!(minimal_len, 9, "minimal r=s=1 signature");
        assert_eq!(mid_len, 71, "two unpadded 32-byte scalars");
        assert_eq!(one_pad_len, 72, "one padded scalar");
        assert_eq!(both_pad_len, 73, "two padded scalars");

        // The core claim, differently-sized signatures encode to differently-sized values.
        let mut sizes = vec![minimal_len, mid_len, one_pad_len, both_pad_len];
        sizes.sort_unstable();
        sizes.dedup();
        assert_eq!(sizes.len(), 4, "encoded sizes must all be distinct");
    }
}
