// SPDX-License-Identifier: CC0-1.0

//! PSBT encoding using the sans-I/O Encoder trait.
//!
//! This module provides PSBT-specific encoding that leverages the
//! [`bitcoin_consensus_encoding::Encoder`] trait for a sans-I/O approach. Unlike consensus
//! encoding, PSBT encoding is specific to the PSBT key-value map format and related structures.

pub mod delegates;
pub mod native;

use alloc::string::String;
use alloc::vec::Vec;

use bitcoin_consensus_encoding::{
    BytesEncoder, CompactSizeDecoderError, CompactSizeEncoder, CompactSizeU64Decoder, DecodeError,
    Decoder, Decoder2, Decoder2Error, DecoderStatus, Encode, Encoder, Encoder2, Encoder4,
    EncoderStatus, ExactSizeEncoder, IterEncoder, VecDecoderError, VecDecoderWith,
};

/// Types that can be PSBT-decoded.
///
/// This trait mirrors the structure of [`bitcoin_consensus_encoding::Decode`],
/// but for PSBT-specific decoding semantics (not consensus decoding).
pub trait PsbtDecode: Sized {
    /// The decoder associated with this type.
    type Decoder: Decoder<Output = Self> + Default;

    /// Constructs a PSBT decoder for this type.
    fn psbt_decoder() -> Self::Decoder { Self::Decoder::default() }
}

/// Decodes a PSBT-decodable value from a byte slice.
pub fn decode_from_slice<T: PsbtDecode>(
    bytes: &[u8],
) -> Result<T, DecodeError<<T::Decoder as Decoder>::Error>> {
    bitcoin_consensus_encoding::decode_from_slice_with_decoder::<T::Decoder>(bytes)
}

/// Decodes a PSBT-decodable value from a byte slice, allowing trailing bytes.
pub fn decode_from_slice_unbounded<T: PsbtDecode>(
    bytes: &mut &[u8],
) -> Result<T, <T::Decoder as Decoder>::Error> {
    bitcoin_consensus_encoding::decode_from_slice_unbounded_with_decoder::<T::Decoder>(bytes)
}

/// Decodes a PSBT-decodable value from a buffered reader.
#[cfg(feature = "std")]
pub fn decode_from_reader<T: PsbtDecode, R: std::io::BufRead>(
    reader: R,
) -> Result<T, bitcoin_consensus_encoding::ReadError<<T::Decoder as Decoder>::Error>> {
    bitcoin_consensus_encoding::decode_from_read_with_decoder::<T::Decoder, R>(reader)
}

/// Types that can be PSBT-encoded.
///
/// This trait mirrors the structure of [`bitcoin_consensus_encoding::Encode`],
/// but for PSBT-specific encoding semantics (not consensus encoding).
pub trait PsbtEncode {
    /// The encoder associated with this type.
    type Encoder<'e>: Encoder
    where
        Self: 'e;

    /// Constructs a PSBT encoder for this value.
    fn psbt_encoder(&self) -> Self::Encoder<'_>;
}

/// Encodes a PSBT-encodable value to a vector.
pub fn encode_to_vec<T: PsbtEncode + ?Sized>(value: &T) -> Vec<u8> {
    let mut encoder = value.psbt_encoder();
    bitcoin_consensus_encoding::drain_to_vec(&mut encoder)
}

/// Encodes a PSBT-encodable value to a writer.
#[cfg(feature = "std")]
pub fn encode_to_writer<W: std::io::Write, T: PsbtEncode + ?Sized>(
    writer: &mut W,
    value: &T,
) -> std::io::Result<()> {
    let mut encoder = value.psbt_encoder();
    bitcoin_consensus_encoding::drain_to_writer(&mut encoder, writer)
}

/// Encodes a PSBT-encodable value to a hex string.
pub fn encode_to_hex<T: PsbtEncode + ?Sized>(
    value: &T,
    case: bitcoin_consensus_encoding::hex::Case,
) -> String {
    let encoder = value.psbt_encoder();
    bitcoin_consensus_encoding::drain_to_hex(encoder, case)
}

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

/// Generic decoder (counterpart to [`KeyValueEncoder`]) for a PSBT key/value value.
///
/// - `<value> := <valuelen> <value body>`
///
/// The length prefix is decoded, but not used to constrain the value since
/// the given decoder controls how many bytes it takes. A dynamically sized value may
/// want to use a [`bitcoin_consensus_encoding::ByteVecDecoder`] instead.
///
/// The error type is a pass-through [`Decoder2Error`]; callers are responsible
/// for mapping based on the concrete inner decoder type.
#[derive(Debug)]
pub(crate) struct ValueDecoder<D: Decoder>(Decoder2<CompactSizeU64Decoder, D>);

impl<D: Decoder + Default> Default for ValueDecoder<D> {
    fn default() -> Self { Self(Decoder2::default()) }
}

impl<D: Decoder + Default> Decoder for ValueDecoder<D> {
    type Output = (u64, D::Output);
    type Error = Decoder2Error<CompactSizeDecoderError, D::Error>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> { self.0.end() }

    fn read_limit(&self) -> usize { self.0.read_limit() }
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

/// An iterator bridge which maps PSBT encodable items to their encoders.
struct Encoders<'e, T: PsbtEncode> {
    iter: core::slice::Iter<'e, T>,
}

impl<'e, T: PsbtEncode> Iterator for Encoders<'e, T> {
    type Item = T::Encoder<'e>;

    fn next(&mut self) -> Option<T::Encoder<'e>> {
        // A closure is required since the MSRV (1.74.0) cannot infer the `Self: 'e` GAT
        // bound when the method is passed as a bare function item.
        #[allow(clippy::redundant_closure_for_method_calls)]
        self.iter.next().map(|item| item.psbt_encoder())
    }
}

impl<'e, T: PsbtEncode> Clone for Encoders<'e, T> {
    fn clone(&self) -> Self { Self { iter: self.iter.clone() } }
}

/// An encoder for a slice of PSBT-encodable types without a length prefix.
pub struct SliceEncoder<'e, T: PsbtEncode>(IterEncoder<Encoders<'e, T>>);

impl<'e, T: PsbtEncode> SliceEncoder<'e, T> {
    /// Constructs an encoder which encodes the slice without adding a length prefix.
    ///
    /// To encode with a length prefix, use [`PrefixedSliceEncoder`] instead.
    pub fn without_length_prefix(sl: &'e [T]) -> Self {
        Self(IterEncoder::new(Encoders { iter: sl.iter() }))
    }
}

impl<'e, T: PsbtEncode> Encoder for SliceEncoder<'e, T> {
    fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }

    fn advance(&mut self) -> EncoderStatus { self.0.advance() }
}

impl<'e, T: PsbtEncode> ExactSizeEncoder for SliceEncoder<'e, T>
where
    for<'a> T::Encoder<'a>: ExactSizeEncoder,
{
    #[inline]
    fn len(&self) -> usize { self.0.len() }
}

/// An encoder for a slice of PSBT-encodable types with a compact size length prefix.
pub struct PrefixedSliceEncoder<'e, T: PsbtEncode>(
    Encoder2<CompactSizeEncoder, SliceEncoder<'e, T>>,
);

impl<'e, T: PsbtEncode> PrefixedSliceEncoder<'e, T> {
    /// Constructs an encoder which encodes the slice, adding a compact size length prefix.
    pub fn new(sl: &'e [T]) -> Self {
        Self(Encoder2::new(
            CompactSizeEncoder::new(sl.len()),
            SliceEncoder::without_length_prefix(sl),
        ))
    }
}

impl<'e, T: PsbtEncode> Encoder for PrefixedSliceEncoder<'e, T> {
    fn current_chunk(&self) -> &[u8] { self.0.current_chunk() }
    fn advance(&mut self) -> EncoderStatus { self.0.advance() }
}

impl<'e, T: PsbtEncode> ExactSizeEncoder for PrefixedSliceEncoder<'e, T>
where
    for<'a> T::Encoder<'a>: ExactSizeEncoder,
{
    #[inline]
    fn len(&self) -> usize { self.0.len() }
}

/// A decoder for a vector of PSBT-decodable types with a compact-size length prefix.
///
/// Mirrors [`bitcoin_consensus_encoding::VecDecoder`] but bound to [`PsbtDecode`] instead
/// of [`bitcoin_consensus_encoding::Decode`].
pub struct VecDecoder<T: PsbtDecode>(VecDecoderWith<T::Decoder>);

impl<T: PsbtDecode> VecDecoder<T> {
    /// Constructs a new decoder with the default limit of 4,000,000 elements.
    pub const fn new() -> Self { Self(VecDecoderWith::new()) }

    /// Constructs a new decoder with a custom element limit.
    pub const fn new_with_limit(limit: usize) -> Self {
        Self(VecDecoderWith::new_with_limit(limit))
    }
}

impl<T: PsbtDecode> Default for VecDecoder<T> {
    fn default() -> Self { Self::new() }
}

impl<T: PsbtDecode> Decoder for VecDecoder<T> {
    type Output = Vec<T>;
    type Error = VecDecoderError<<T::Decoder as Decoder>::Error>;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Vec<T>, Self::Error> { self.0.end() }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

/// An encoder whose remaining length is known up front, delegating chunk
/// production to the inner consensus encoder.
///
/// Used for types whose consensus encoder does not implement
/// [`ExactSizeEncoder`] because its inner chain contains iterator-based
/// components (e.g. [`Transaction`], [`Witness`]). The caller
/// supplies the total serialized size, e.g. [`Transaction::total_size`],
/// or `Witness::size()`.
pub(crate) struct ExactLenEncoder<'e, T: Encode + 'e> {
    inner: T::Encoder<'e>,
    remaining: usize,
}

impl<'e, T: Encode> ExactLenEncoder<'e, T> {
    /// Wraps `value`'s consensus encoder; `len` is its total serialized size.
    pub(crate) fn new(value: &'e T, len: usize) -> Self {
        Self { inner: value.encoder(), remaining: len }
    }
}

impl<'e, T: Encode> Encoder for ExactLenEncoder<'e, T>
where
    T: 'e,
{
    fn current_chunk(&self) -> &[u8] { self.inner.current_chunk() }

    fn advance(&mut self) -> EncoderStatus {
        let chunk_len = self.inner.current_chunk().len();
        let status = self.inner.advance();
        self.remaining = self.remaining.saturating_sub(chunk_len);
        status
    }
}

impl<T: Encode> ExactSizeEncoder for ExactLenEncoder<'_, T> {
    fn len(&self) -> usize { self.remaining }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::{
        absolute, transaction, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness,
    };

    use super::*;
    use crate::encoding::encode_to_vec;

    #[test]
    fn encoders_next_yields_items_then_none() {
        let items = [Sequence::ZERO, Sequence::MAX];
        let mut encoders = Encoders { iter: items.iter() };

        assert!(encoders.next().is_some(), "should yield first item");
        assert!(encoders.next().is_some(), "should yield second item");
        assert!(encoders.next().is_none(), "should be exhausted after two items");
    }

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

    #[test]
    fn slice_encoder_len_tracks_remaining() {
        let items = [Sequence::ZERO, Sequence::MAX];
        let mut encoder = <SliceEncoder<'_, Sequence>>::without_length_prefix(&items);

        assert_eq!(encoder.current_chunk(), [0x00; 4], "first sequence bytes");
        assert_eq!(encoder.len(), 8, "two sequences encode to 4 bytes each");

        assert!(encoder.advance().has_more(), "second sequence remains");
        assert_eq!(encoder.current_chunk(), [0xff; 4], "second sequence bytes");
        assert_eq!(encoder.len(), 4, "first sequence consumed");

        assert!(encoder.advance().has_finished(), "both items consumed");
        assert_eq!(encoder.len(), 0, "nothing remains after finish");
    }

    #[test]
    fn prefixed_slice_encoder_len_tracks_remaining() {
        let items = [Sequence::ZERO, Sequence::MAX];
        let mut encoder = <PrefixedSliceEncoder<'_, Sequence>>::new(&items);

        assert_eq!(encoder.current_chunk(), [0x02], "compact-size prefix chunk");
        assert_eq!(encoder.len(), 9, "compact-size prefix plus two 4-byte sequences");

        assert!(encoder.advance().has_more(), "body remains");
        assert_eq!(encoder.current_chunk(), [0x00; 4], "first sequence bytes");
        assert_eq!(encoder.len(), 8, "prefix consumed");

        assert!(encoder.advance().has_more(), "second sequence remains");
        assert_eq!(encoder.current_chunk(), [0xff; 4], "second sequence bytes");
        assert_eq!(encoder.len(), 4, "first sequence consumed");

        assert!(encoder.advance().has_finished(), "finished");
        assert_eq!(encoder.len(), 0, "nothing remains after finish");
    }

    fn sample_txin(with_witness: bool) -> TxIn {
        TxIn {
            previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: if with_witness {
                Witness::from_slice(&[alloc::vec![0x51], alloc::vec![0x52]])
            } else {
                Witness::new()
            },
        }
    }

    fn sample_tx(with_witness: bool) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: alloc::vec![sample_txin(with_witness)],
            output: alloc::vec![sample_txout()],
        }
    }

    fn sample_txout() -> TxOut {
        TxOut {
            value: bitcoin::Amount::from_sat(500),
            script_pubkey: ScriptBuf::from_bytes(alloc::vec![0x51]),
        }
    }

    fn finalize(mut encoder: impl ExactSizeEncoder) {
        let mut expected = encoder.len();
        loop {
            let consumed = encoder.current_chunk().len();
            expected -= consumed;
            if encoder.advance().has_finished() {
                break;
            }
            assert_eq!(encoder.len(), expected, "len counts down on advance");
        }
        assert_eq!(encoder.len(), expected);
    }

    #[test]
    fn exact_len_encoder_counts_down() {
        for tx in [sample_tx(false), sample_tx(true)] {
            let encoder = ExactLenEncoder::new(&tx, tx.total_size());
            assert_eq!(encoder.len(), tx.total_size());
            finalize(encoder);
        }
    }

    #[test]
    fn exact_len_encoder_matches_encode_to_vec() {
        for tx in [sample_tx(false), sample_tx(true)] {
            let mut wrapper = ExactLenEncoder::new(&tx, tx.total_size());
            let mut bytes = alloc::vec::Vec::new();
            loop {
                bytes.extend_from_slice(wrapper.current_chunk());
                if wrapper.advance().has_finished() {
                    break;
                }
            }
            assert_eq!(bytes, encode_to_vec(&tx));
        }
    }
}
