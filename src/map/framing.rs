// SPDX-License-Identifier: CC0-1.0

//! PSBT map-level framing.
//!
//! Provides the key-value framing primitives used by the global, input, and
//! output map encoders/decoders, together with the per-field encoder/decoder
//! type aliases that wire concrete PSBT key types to their value codecs.

#[cfg(test)]
use bitcoin::Sequence;
use bitcoin_consensus_encoding::{
    BytesEncoder, CompactSizeDecoder, CompactSizeDecoderError, CompactSizeEncoder, Decoder,
    DecoderStatus, Encoder, Encoder2, Encoder4, EncoderStatus, ExactSizeEncoder,
};

use crate::encoding::{PsbtDecode, PsbtEncode};

/// Framing for a single PSBT `<keypair>`.
///
/// - `<keypair> := <keylen> <key body> <valuelen> <value body>`
///
/// The length prefixes are pulled before the bodies, so both bodies must expose
/// their statically known length via [`ExactSizeEncoder`].
pub(crate) struct KeyValueEncoder<K, V> {
    inner: Encoder4<CompactSizeEncoder, K, CompactSizeEncoder, V>,
}

impl<K: Encoder, V: Encoder> Encoder for KeyValueEncoder<K, V> {
    fn current_chunk(&self) -> &[u8] { self.inner.current_chunk() }

    fn advance(&mut self) -> EncoderStatus { self.inner.advance() }
}

impl<K: ExactSizeEncoder, V: ExactSizeEncoder> KeyValueEncoder<K, V> {
    pub fn from_sized_kv(key: K, value: V) -> Self {
        let key_len = key.len();
        let value_len = value.len();
        let inner = Encoder4::new(
            CompactSizeEncoder::new(key_len),
            key,
            CompactSizeEncoder::new(value_len),
            value,
        );
        Self { inner }
    }
}

/// Error returned by [`ValueDecoder`].
#[derive(Debug)]
pub enum ValueDecoderError<E> {
    /// Error decoding the value's length prefix.
    LengthPrefix(CompactSizeDecoderError),
    /// The inner decoder consumed a different number of bytes than the length
    /// prefix declared.
    WrongLength {
        /// The length the value prefix declared.
        declared: usize,
        /// The number of bytes the inner decoder actually consumed.
        consumed: usize,
    },
    /// Error from the inner decoder.
    Inner(E),
}

impl<E: core::fmt::Display> core::fmt::Display for ValueDecoderError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LengthPrefix(e) => write!(f, "error decoding value length prefix: {e}"),
            Self::WrongLength { declared, consumed } =>
                write!(f, "value length {declared} does not match consumed {consumed}"),
            Self::Inner(e) => write!(f, "value decode error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for ValueDecoderError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LengthPrefix(e) => Some(e),
            Self::WrongLength { .. } => None,
            Self::Inner(e) => Some(e),
        }
    }
}

/// The decoding state of a [`ValueDecoder`].
#[derive(Debug)]
enum ValueDecoderState {
    /// Reading the value's compact-size length prefix.
    ReadingPrefix(CompactSizeDecoder),
    /// Reading the value body, whose length the prefix declared.
    ReadingValue { declared: usize },
    /// A previous [`Decoder::push_bytes`] call errored; the decoder is unusable.
    Errored,
}

/// Generic decoder (counterpart to [`KeyValueEncoder`]) for a PSBT key/value value.
///
/// Decodes `<valuelen> <value body>` where the value type `T: PsbtDecode`'s decoder produces
/// `T` without needing the length prefix to determine where the value ends (it is fixed-size or
/// structurally self-delimiting). The prefix is therefore only validated: the inner decoder must
/// consume exactly `valuelen` bytes, otherwise [`ValueDecoderError::WrongLength`] is returned.
///
/// If a field's value is a length-prefixed blob (a "raw" decoder, such as the consensus decoder for
/// [`bitcoin::ScriptBuf`]), use that decoder directly instead of wrapping it here.
#[derive(Debug)]
pub(crate) struct ValueDecoder<T: PsbtDecode> {
    inner: T::Decoder,
    state: ValueDecoderState,
    consumed: usize,
}

impl<T: PsbtDecode> Default for ValueDecoder<T> {
    fn default() -> Self {
        Self {
            inner: T::Decoder::default(),
            state: ValueDecoderState::ReadingPrefix(CompactSizeDecoder::new()),
            consumed: 0,
        }
    }
}

impl<T: PsbtDecode> Decoder for ValueDecoder<T> {
    type Output = T;
    type Error = ValueDecoderError<<T::Decoder as Decoder>::Error>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        if matches!(self.state, ValueDecoderState::ReadingPrefix(_)) {
            let ValueDecoderState::ReadingPrefix(mut prefix) =
                core::mem::replace(&mut self.state, ValueDecoderState::Errored)
            else {
                panic!("use of failed decoder");
            };

            if prefix.push_bytes(bytes).map_err(ValueDecoderError::LengthPrefix)?.needs_more() {
                self.state = ValueDecoderState::ReadingPrefix(prefix);
                return Ok(DecoderStatus::NeedsMore);
            }
            let declared = prefix.end().map_err(ValueDecoderError::LengthPrefix)?;
            self.state = ValueDecoderState::ReadingValue { declared };
        }

        let before = bytes.len();
        let status = self.inner.push_bytes(bytes).map_err(|e| {
            self.state = ValueDecoderState::Errored;
            ValueDecoderError::Inner(e)
        })?;
        self.consumed += before - bytes.len();
        Ok(status)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let Self { inner, state, consumed } = self;

        let declared = match state {
            ValueDecoderState::ReadingValue { declared } => declared,
            // Insufficient data, the prefix was never fully read.
            ValueDecoderState::ReadingPrefix(prefix) => {
                return match prefix.end() {
                    Err(e) => Err(ValueDecoderError::LengthPrefix(e)),
                    Ok(declared) =>
                        unreachable!("prefix complete in ReadingPrefix state: {declared}"),
                };
            }
            ValueDecoderState::Errored => panic!("use of failed decoder"),
        };

        let out = inner.end().map_err(ValueDecoderError::Inner)?;

        if consumed != declared {
            return Err(ValueDecoderError::WrongLength { declared, consumed });
        }
        Ok(out)
    }

    fn read_limit(&self) -> usize {
        match &self.state {
            ValueDecoderState::ReadingPrefix(prefix) =>
                prefix.read_limit() + self.inner.read_limit(),
            ValueDecoderState::ReadingValue { .. } => self.inner.read_limit(),
            ValueDecoderState::Errored => 0,
        }
    }
}

/// Iterator yielding [`KeyValueEncoder`]s for a map, prefixing each key's
/// encoder with the constant compact-size type value `TYPE`.
///
/// Works with any iterator of borrowed `(key, value)` pairs (e.g.
/// `btree_map::Iter`); the yielded items implement [`ExactSizeEncoder`] when
/// both key and value encoders do.
///
/// For maps whose values are raw byte slices (`Vec<u8>` preimage maps), use
/// [`BytesKeyValueIter`] instead.
pub(crate) struct KeyValueIter<I, const TYPE: u64> {
    iter: I,
}

impl<I, const TYPE: u64> KeyValueIter<I, TYPE> {
    /// Constructs a pair iterator from the given underlying iterator.
    pub(crate) fn new(iter: I) -> Self { Self { iter } }
}

impl<'e, K, V, I, const TYPE: u64> Iterator for KeyValueIter<I, TYPE>
where
    I: Iterator<Item = (&'e K, &'e V)>,
    K: PsbtEncode + 'e,
    V: PsbtEncode + 'e,
    for<'a> K::Encoder<'a>: ExactSizeEncoder,
    for<'a> V::Encoder<'a>: ExactSizeEncoder,
{
    type Item = KeyValueEncoder<Encoder2<CompactSizeEncoder, K::Encoder<'e>>, V::Encoder<'e>>;

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.iter.next()?;
        Some(KeyValueEncoder::from_sized_kv(
            Encoder2::new(CompactSizeEncoder::new_u64(TYPE), key.psbt_encoder()),
            value.psbt_encoder(),
        ))
    }
}

/// Iterator yielding [`KeyValueEncoder`]s for a map whose values are raw
/// bytes (e.g. preimage maps).
///
/// Like [`KeyValueIter`] but encodes each value as raw unprefixed bytes via
/// [`BytesEncoder::without_length_prefix`], avoiding the need for `V: PsbtEncode`.
pub(crate) struct BytesKeyValueIter<I, const TYPE: u64> {
    iter: I,
}

impl<I, const TYPE: u64> BytesKeyValueIter<I, TYPE> {
    /// Constructs a byte-valued pair iterator from the given underlying iterator.
    pub(crate) fn new(iter: I) -> Self { Self { iter } }
}

impl<'e, K, V, I, const TYPE: u64> Iterator for BytesKeyValueIter<I, TYPE>
where
    I: Iterator<Item = (&'e K, &'e V)>,
    K: PsbtEncode + 'e,
    V: AsRef<[u8]> + 'e,
    for<'a> K::Encoder<'a>: ExactSizeEncoder,
{
    type Item = KeyValueEncoder<Encoder2<CompactSizeEncoder, K::Encoder<'e>>, BytesEncoder<'e>>;

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.iter.next()?;
        Some(KeyValueEncoder::from_sized_kv(
            Encoder2::new(CompactSizeEncoder::new_u64(TYPE), key.psbt_encoder()),
            BytesEncoder::without_length_prefix(value.as_ref()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_key_value_iter_yields_items_then_none() {
        let mut map = alloc::collections::BTreeMap::new();
        map.insert(Sequence::ZERO, alloc::vec![0xaa, 0xbb]);
        map.insert(Sequence::MAX, alloc::vec![0xcc]);

        let mut iter = BytesKeyValueIter::<_, 0x02>::new(map.iter());

        // <keylen=5> <type=0x02> <sequence ZERO> <vallen=2> <value>
        let mut first = iter.next().expect("yields first pair");
        assert_eq!(
            bitcoin_consensus_encoding::drain_to_vec(&mut first),
            alloc::vec![0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb],
        );
        assert!(iter.next().is_some(), "yields second pair");
        assert!(iter.next().is_none(), "exhausted after two items");
    }
}
