// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::taproot;
use bitcoin_consensus_encoding::{
    ArrayDecoder, CompactSizeDecoder, CompactSizeDecoderError, Decoder, DecoderStatus,
    UnexpectedEofError,
};

/// Size of a Schnorr signature without the sighash type byte (BIP-340).
const SIG_SIZE: usize = 64;
/// Size of a Schnorr signature including the optional sighash type byte (BIP-341).
const MAX_SIG_SIZE: usize = 65;

/// Internal state for [`TaprootSignatureDecoder`].
#[derive(Debug)]
enum TaprootSigDecoderState {
    /// Reading the compact-size length prefix.
    ReadingPrefix(CompactSizeDecoder),
    /// Reading a 64-byte signature (no sighash).
    Reading64(ArrayDecoder<64>),
    /// Reading a 65-byte signature (with sighash).
    Reading65(ArrayDecoder<65>),
    /// A previous [`Decoder::push_bytes`] call errored; the decoder is unusable.
    Errored,
}

/// Decoder for a [`taproot::Signature`] value.
///
/// Uses a push-based state machine: first decodes the compact-size length prefix,
/// then dispatches to either [`ArrayDecoder<64>`] or [`ArrayDecoder<65>`] depending
/// on whether the sighash type byte is present. No heap allocation.
#[derive(Debug)]
pub struct TaprootSignatureDecoder {
    state: TaprootSigDecoderState,
}

impl Default for TaprootSignatureDecoder {
    fn default() -> Self {
        Self { state: TaprootSigDecoderState::ReadingPrefix(CompactSizeDecoder::new()) }
    }
}

impl Decoder for TaprootSignatureDecoder {
    type Output = taproot::Signature;
    type Error = TaprootSignatureDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        use TaprootSigDecoderState::*;

        if matches!(self.state, ReadingPrefix(_)) {
            let mut prefix = match core::mem::replace(&mut self.state, Errored) {
                ReadingPrefix(p) => p,
                _ => unreachable!(),
            };
            if prefix
                .push_bytes(bytes)
                .map_err(TaprootSignatureDecodeError::LengthPrefix)?
                .needs_more()
            {
                self.state = ReadingPrefix(prefix);
                return Ok(DecoderStatus::NeedsMore);
            }
            let len = prefix.end().map_err(TaprootSignatureDecodeError::LengthPrefix)?;
            match len {
                SIG_SIZE => self.state = Reading64(ArrayDecoder::new()),
                MAX_SIG_SIZE => self.state = Reading65(ArrayDecoder::new()),
                n => return Err(TaprootSignatureDecodeError::InvalidLength(n)),
            }
        }

        match &mut self.state {
            Reading64(ref mut dec) =>
                dec.push_bytes(bytes).map_err(TaprootSignatureDecodeError::UnexpectedEof),
            Reading65(ref mut dec) =>
                dec.push_bytes(bytes).map_err(TaprootSignatureDecodeError::UnexpectedEof),
            ReadingPrefix(_) => unreachable!(),
            Errored => panic!("use of failed decoder"),
        }
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        match self.state {
            TaprootSigDecoderState::ReadingPrefix(p) => {
                // Prefix never completed; end() surfaces the compact-size error.
                let err = p.end().unwrap_err();
                Err(TaprootSignatureDecodeError::LengthPrefix(err))
            }
            TaprootSigDecoderState::Reading64(dec) => {
                let buf = dec.end().map_err(TaprootSignatureDecodeError::UnexpectedEof)?;
                taproot::Signature::from_slice(&buf)
                    .map_err(TaprootSignatureDecodeError::InvalidSignature)
            }
            TaprootSigDecoderState::Reading65(dec) => {
                let buf = dec.end().map_err(TaprootSignatureDecodeError::UnexpectedEof)?;
                taproot::Signature::from_slice(&buf)
                    .map_err(TaprootSignatureDecodeError::InvalidSignature)
            }
            TaprootSigDecoderState::Errored => panic!("use of failed decoder"),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.state {
            TaprootSigDecoderState::ReadingPrefix(dec) => dec.read_limit(),
            TaprootSigDecoderState::Reading64(dec) => dec.read_limit(),
            TaprootSigDecoderState::Reading65(dec) => dec.read_limit(),
            TaprootSigDecoderState::Errored => 0,
        }
    }
}

/// Error decoding a [`taproot::Signature`] value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaprootSignatureDecodeError {
    /// Error decoding the compact-size length prefix.
    LengthPrefix(CompactSizeDecoderError),
    /// Not enough bytes were provided for the declared length.
    UnexpectedEof(UnexpectedEofError),
    /// The declared length is not 64 or 65.
    InvalidLength(usize),
    /// The bytes are not a valid taproot signature.
    InvalidSignature(bitcoin::taproot::SigFromSliceError),
}

impl fmt::Display for TaprootSignatureDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthPrefix(e) => {
                write!(f, "error decoding taproot signature length prefix: {e}")
            }
            Self::UnexpectedEof(e) => write!(f, "unexpected EOF decoding taproot signature: {e}"),
            Self::InvalidLength(len) => {
                write!(f, "invalid taproot signature length ({len} bytes, expected {SIG_SIZE} or {MAX_SIG_SIZE})")
            }
            Self::InvalidSignature(e) => write!(f, "invalid taproot signature: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TaprootSignatureDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LengthPrefix(e) => Some(e),
            Self::UnexpectedEof(e) => Some(e),
            Self::InvalidLength(_) => None,
            Self::InvalidSignature(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use bitcoin::taproot;
    use bitcoin_consensus_encoding::{
        drain_to_vec, CompactSizeEncoder, Encoder2, ExactSizeEncoder,
    };

    use super::*;
    use crate::encoding::PsbtEncode;

    /// Build test data from a signature, prepending the compact-size prefix.
    fn encode(sig: &taproot::Signature) -> Vec<u8> {
        let psbt_enc = sig.psbt_encoder();
        let mut enc = Encoder2::new(CompactSizeEncoder::new(psbt_enc.len()), psbt_enc);
        drain_to_vec(&mut enc)
    }

    /// Exercise the decoder on a 64-byte signature (no sighash byte).
    #[test]
    fn decode_64_byte_signature() {
        let raw = bitcoin::secp256k1::schnorr::Signature::from_slice(&[0x51; 64]).unwrap();
        let sig =
            taproot::Signature { signature: raw, sighash_type: bitcoin::TapSighashType::Default };
        let encoded = encode(&sig);

        let mut decoder = TaprootSignatureDecoder::default();
        assert!(decoder.read_limit() > 0, "initial read_limit should be > 0 (prefix)");

        let mut bytes: &[u8] = &encoded;
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0);

        let decoded = decoder.end().unwrap();
        assert_eq!(decoded.sighash_type, bitcoin::TapSighashType::Default);
    }

    /// Exercise the decoder on a 65-byte signature (with sighash byte).
    #[test]
    fn decode_65_byte_signature() {
        let raw = bitcoin::secp256k1::schnorr::Signature::from_slice(&[0x51; 64]).unwrap();
        let sig = taproot::Signature { signature: raw, sighash_type: bitcoin::TapSighashType::All };
        let encoded = encode(&sig);

        let mut decoder = TaprootSignatureDecoder::default();
        assert!(decoder.read_limit() > 0, "initial read_limit should be > 0 (prefix)");

        let mut bytes: &[u8] = &encoded;
        assert!(decoder.push_bytes(&mut bytes).unwrap().is_ready());
        assert_eq!(decoder.read_limit(), 0);

        let decoded = decoder.end().unwrap();
        assert_eq!(decoded.sighash_type, bitcoin::TapSighashType::All);
    }

    #[test]
    fn read_limit_lifecycle() {
        let raw = bitcoin::secp256k1::schnorr::Signature::from_slice(&[0x51; 64]).unwrap();
        let sig =
            taproot::Signature { signature: raw, sighash_type: bitcoin::TapSighashType::Default };
        let encoded = encode(&sig);

        let mut decoder = TaprootSignatureDecoder::default();
        // Prefix phase: compact-size(64) needs 1 byte.
        assert_eq!(decoder.read_limit(), 1);

        let mut remaining = encoded.as_slice();
        // Feed the prefix byte (0x40 = 64).
        let mut byte = &remaining[..1];
        decoder.push_bytes(&mut byte).unwrap();
        remaining = &remaining[1..];
        assert_eq!(decoder.read_limit(), SIG_SIZE, "after prefix, read_limit jumps to value size");

        // Value phase: count down to zero.
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
        // compact_size(66) = 0x42 followed by any bytes.
        let mut bytes: &[u8] = &[0x42, 0x00];
        let mut decoder = TaprootSignatureDecoder::default();
        let err = decoder.push_bytes(&mut bytes).unwrap_err();
        assert!(matches!(err, TaprootSignatureDecodeError::InvalidLength(66)));
    }
}
