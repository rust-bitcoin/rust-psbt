// SPDX-License-Identifier: CC0-1.0

use core::fmt;

use bitcoin::taproot::LeafVersion;
use bitcoin::ScriptBuf;
use bitcoin_consensus_encoding::{
    ArrayEncoder, ByteVecDecoder, ByteVecDecoderError, BytesEncoder, Decoder, DecoderStatus,
    Encoder2,
};

use crate::encoding::{PsbtDecode, PsbtEncode};

/// A taproot leaf script.
///
/// This is currently a tuple. Someday the ecosystem (rust-miniscript) may adopt the upstream
/// [`bitcoin::taproot::LeafScript`] type, in which case we could remove this tuple in favor of
/// it as well.
pub type TapLeafScript = (ScriptBuf, LeafVersion);

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a [`TapLeafScript`] value: `<script bytes> <leaf version>`.
    ///
    /// Corresponds to the value format of PSBT key type `PSBT_IN_TAP_LEAF_SCRIPT` (0x15)
    /// as defined in BIP 371.
    pub struct LeafScriptEncoder<'e>(Encoder2<BytesEncoder<'e>, ArrayEncoder<1>>);
}

impl PsbtEncode for TapLeafScript {
    type Encoder<'e>
        = LeafScriptEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        LeafScriptEncoder::new(Encoder2::new(self.0.psbt_encoder(), self.1.psbt_encoder()))
    }
}

/// Decoder for a [`TapLeafScript`] value: `<script bytes> <leaf version>`.
///
/// Delegates to [`ByteVecDecoder`] for DoS-resistant buffered reading, then splits
/// the version byte off the tail without copying the script bytes.
#[derive(Debug, Default)]
pub struct LeafScriptDecoder {
    inner: ByteVecDecoder,
}

impl Decoder for LeafScriptDecoder {
    type Output = TapLeafScript;
    type Error = LeafScriptDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(LeafScriptDecodeError::Decode)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let mut value = self.inner.end().map_err(LeafScriptDecodeError::Decode)?;
        let version_byte = value.pop().ok_or(LeafScriptDecodeError::Empty)?;
        let version = LeafVersion::from_consensus(version_byte)
            .map_err(|_| LeafScriptDecodeError::InvalidLeafVersion)?;
        let script = ScriptBuf::from_bytes(value);
        Ok((script, version))
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for TapLeafScript {
    type Decoder = LeafScriptDecoder;
}

/// Error decoding a [`TapLeafScript`] value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafScriptDecodeError {
    /// The inner byte-vector decoder encountered an error.
    Decode(ByteVecDecoderError),
    /// The value is empty (needs at least a leaf version byte).
    Empty,
    /// The last byte is not a valid leaf version.
    InvalidLeafVersion,
}

impl fmt::Display for LeafScriptDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "error decoding leaf script: {e}"),
            Self::Empty => write!(f, "leaf script value is empty"),
            Self::InvalidLeafVersion => write!(f, "invalid leaf version in leaf script"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LeafScriptDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            Self::Empty | Self::InvalidLeafVersion => None,
        }
    }
}
