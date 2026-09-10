// SPDX-License-Identifier: CC0-1.0

//! Raw PSBT key-value pairs.
//!
//! [BIP-174] defines the following:
//!
//! - `<keypair> := <key> <value>`
//! - `<key> := <keylen> <keytype> <keydata>`
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

use alloc::collections::btree_map;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;

use bitcoin::consensus::encode as consensus;
use bitcoin::consensus::encode::{Decodable, Encodable, VarInt, MAX_VEC_SIZE};
use bitcoin::hex::DisplayHex;
use bitcoin_consensus_encoding::{
    ByteVecDecoder, ByteVecDecoderError, BytesEncoder, CompactSizeDecoderError, CompactSizeEncoder,
    CompactSizeU64Decoder, Decoder, Decoder2, Decoder2Error, DecoderStatus, Encoder2, Encoder3,
    ExactSizeEncoder, PrefixedBytesEncoder,
};

use crate::consts::PSBT_GLOBAL_PROPRIETARY;
use crate::encoding::{KeyValueEncoder, PsbtDecode, PsbtEncode};
use crate::io::{self, Write};
use crate::serialize;
use crate::serialize::{Deserialize, Serialize};

/// A PSBT key-value pair in its raw byte form.
///
/// - `<keypair> := <key> <value>`
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Pair {
    /// The key of this key-value pair.
    pub key: Key,
    /// The value of this key-value pair in raw byte form.
    ///
    /// - `<value> := <valuelen> <valuedata>`
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub value: Vec<u8>,
}

impl Pair {
    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, serialize::Error> {
        Ok(Self { key: Key::decode(r)?, value: Decodable::consensus_decode(r)? })
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "type: {:#x}, key: {:x}", self.type_value, self.key.as_hex())
    }
}

impl Serialize for Pair {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.key.serialize());
        // <value> := <valuelen> <valuedata>
        self.value.consensus_encode(&mut buf).unwrap();
        buf
    }
}

impl Deserialize for Pair {
    fn deserialize(bytes: &[u8]) -> Result<Self, serialize::Error> {
        let mut decoder = bytes;
        Self::decode(&mut decoder)
    }
}

/// The key of a key-value PSBT pair, in its raw byte form.
///
/// - `<key> := <keylen> <keytype> <keydata>`
///
/// We do not carry the `keylen` around, we just create the `VarInt` length when serializing and
/// deserializing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Key {
    /// The `keytype` of this PSBT map key (`keytype`).
    pub type_value: u64,
    /// The `keydata` itself in raw byte form.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

impl Key {
    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, serialize::Error> {
        let VarInt(byte_size): VarInt = Decodable::consensus_decode(r)?;

        if byte_size == 0 {
            return Err(serialize::Error::NoMorePairs);
        }

        let type_value: VarInt = Decodable::consensus_decode(r)?;

        let key_byte_size = match byte_size.checked_sub(
            u64::try_from(type_value.size()).expect("size() returns 1-9, fits inside u64"),
        ) {
            Some(val) => val,
            None => {
                return Err(consensus::Error::ParseFailed(
                    "encoded keytype is larger than specified length",
                ))?;
            }
        };

        if key_byte_size > MAX_VEC_SIZE as u64 {
            return Err(consensus::Error::OversizedVectorAllocation {
                requested: key_byte_size as usize,
                max: MAX_VEC_SIZE,
            }
            .into());
        }

        let mut key = Vec::with_capacity(key_byte_size as usize);
        for _ in 0..key_byte_size {
            key.push(Decodable::consensus_decode(r)?);
        }

        Ok(Self { type_value: type_value.0, key })
    }
}

impl Serialize for Key {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let type_value = VarInt::from(self.type_value);
        VarInt::from(self.key.len() + type_value.size())
            .consensus_encode(&mut buf)
            .expect("in-memory writers don't error");

        type_value.consensus_encode(&mut buf).expect("in-memory writers don't error");

        for key in &self.key {
            key.consensus_encode(&mut buf).expect("in-memory writers don't error");
        }

        buf
    }
}

/// Default implementation for proprietary key subtyping
pub type ProprietaryType = u64;

/// Proprietary keys (i.e. keys starting with 0xFC byte) with their internal
/// structure according to BIP 174.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProprietaryKey<Subtype = ProprietaryType>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    /// Proprietary type prefix used for grouping together keys under some
    /// application and avoid namespace collision
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub prefix: Vec<u8>,
    /// Custom proprietary subtype
    pub subtype: Subtype,
    /// Additional key bytes (like serialized public key data etc)
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

impl<Subtype> ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    /// Constructs full [Key] corresponding to this proprietary key type
    pub fn to_key(&self) -> Key {
        Key { type_value: 0xFC, key: crate::encoding::encode_to_vec(self) }
    }
}

impl<Subtype> TryFrom<Key> for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    type Error = serialize::Error;

    /// Constructs a [`ProprietaryKey`] from a [`Key`].
    ///
    /// # Errors
    ///
    /// Returns [`serialize::Error::InvalidProprietaryKey`] if `key` does not start with `0xFC`.
    fn try_from(key: Key) -> Result<Self, Self::Error> {
        if key.type_value != 0xFC {
            return Err(serialize::Error::InvalidProprietaryKey);
        }

        let mut inner = Decoder2::<ByteVecDecoder, CompactSizeU64Decoder>::default();

        let mut bytes = key.key.as_slice();
        if inner
            .push_bytes(&mut bytes)
            .map_err(|_| serialize::Error::InvalidProprietaryKey)?
            .needs_more()
        {
            return Err(serialize::Error::InvalidProprietaryKey);
        }

        let (prefix, subtype) = inner.end().map_err(|_| serialize::Error::InvalidProprietaryKey)?;

        Ok(Self { prefix, subtype: subtype.into(), key: bytes.to_vec() })
    }
}

impl<Subtype> Encodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(w)?;
        len += VarInt::from(self.subtype.into()).consensus_encode(w)?;
        w.write_all(&self.key)?;
        len += self.key.len();
        Ok(len)
    }
}

impl<Subtype> Decodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, consensus::Error> {
        let prefix = Vec::<u8>::consensus_decode(r)?;
        let VarInt(subtype_u64): VarInt = Decodable::consensus_decode(r)?;
        let subtype = Subtype::from(subtype_u64);

        // The limit is a DOS protection mechanism the exact value is not
        // important, 1024 bytes is bigger than any key should be.
        let mut key = vec![];
        let _ = r.read_to_limit(&mut key, 1024)?;

        Ok(Self { prefix, subtype, key })
    }
}

impl<Subtype> PsbtEncode for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    type Encoder<'e>
        = ProprietaryKeyEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ProprietaryKeyEncoder::new(Encoder3::new(
            PrefixedBytesEncoder::new(&self.prefix),
            CompactSizeEncoder::new_u64(self.subtype.into()),
            BytesEncoder::without_length_prefix(&self.key),
        ))
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for the body of a raw PSBT [`ProprietaryKey`] (`<prefix> <subtype> <keydata>`,
    /// without the leading `0xFC` keytype).
    pub struct ProprietaryKeyEncoder<'e>(Encoder3<PrefixedBytesEncoder<'e>, CompactSizeEncoder, BytesEncoder<'e>>);
}

/// Iterator yielding proprietary key-value pair encoders.
pub(crate) struct ProprietaryKeyValueIter<'e>(
    pub(crate) btree_map::Iter<'e, ProprietaryKey, Vec<u8>>,
);

impl<'e> Iterator for ProprietaryKeyValueIter<'e> {
    type Item =
        KeyValueEncoder<Encoder2<CompactSizeEncoder, ProprietaryKeyEncoder<'e>>, BytesEncoder<'e>>;

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.0.next()?;
        Some(KeyValueEncoder::from_sized_kv(
            Encoder2::new(CompactSizeEncoder::new_u64(PSBT_GLOBAL_PROPRIETARY), key.psbt_encoder()),
            BytesEncoder::without_length_prefix(value),
        ))
    }
}

/// Error returned when decoding a raw PSBT [`Key`] fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyDecodeError {
    /// Failed to decode the key's length-prefixed byte body.
    Bytes(ByteVecDecoderError),
    /// The key body was empty.
    ///
    /// A `keylen` of zero encodes the end-of-map separator (0x00), not a [`Key`]; callers decoding
    /// a PSBT map should check for the separator before decoding a [`Key`].
    Empty,
    /// Failed to decode the `keytype` compact size integer from the key body.
    TypeValue(CompactSizeDecoderError),
}

impl fmt::Display for KeyDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Bytes(e) => write!(f, "failed to decode key body: {}", e),
            Self::Empty => write!(f, "empty key (this is the map separator)"),
            Self::TypeValue(e) => write!(f, "failed to decode keytype: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeyDecodeError {}

/// Decoder for raw PSBT keys.
#[derive(Debug, Default)]
pub struct KeyDecoder {
    inner: ByteVecDecoder,
}

impl Decoder for KeyDecoder {
    type Output = Key;
    type Error = KeyDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes).map_err(KeyDecodeError::Bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let body = self.inner.end().map_err(KeyDecodeError::Bytes)?;

        if body.is_empty() {
            return Err(KeyDecodeError::Empty);
        }

        let mut rest: &[u8] = &body;
        let mut type_decoder = CompactSizeU64Decoder::new();
        type_decoder.push_bytes(&mut rest).map_err(KeyDecodeError::TypeValue)?;
        let type_value = type_decoder.end().map_err(KeyDecodeError::TypeValue)?;

        Ok(Key { type_value, key: rest.to_vec() })
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for Key {
    type Decoder = KeyDecoder;
}

impl PsbtEncode for Key {
    type Encoder<'e> = KeyEncoder<'e>;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { KeyEncoder::from_key(self) }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for raw PSBT keys.
    pub struct KeyEncoder<'e>(Encoder3<CompactSizeEncoder, CompactSizeEncoder, BytesEncoder<'e>>);
}

impl<'e> KeyEncoder<'e> {
    fn from_key(key: &'e Key) -> Self {
        let type_value_encoder = CompactSizeEncoder::new_u64(key.type_value);
        let body_len = type_value_encoder.len() + key.key.len();

        Self::new(Encoder3::new(
            CompactSizeEncoder::new(body_len),
            type_value_encoder,
            BytesEncoder::without_length_prefix(&key.key),
        ))
    }
}

/// Iterator yielding unknown key-value pair encoders.
pub(crate) struct UnknownKeyValueIter<'e>(pub(crate) btree_map::Iter<'e, Key, Vec<u8>>);

impl<'e> Iterator for UnknownKeyValueIter<'e> {
    type Item = KeyValueEncoder<Encoder2<CompactSizeEncoder, BytesEncoder<'e>>, BytesEncoder<'e>>;

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.0.next()?;
        Some(KeyValueEncoder::from_sized_kv(
            Encoder2::new(
                CompactSizeEncoder::new_u64(key.type_value),
                BytesEncoder::without_length_prefix(&key.key),
            ),
            BytesEncoder::without_length_prefix(value),
        ))
    }
}

/// Error returned when decoding a raw PSBT [`Pair`] fails.
pub type PairDecodeError = Decoder2Error<KeyDecodeError, ByteVecDecoderError>;

/// Decoder for raw PSBT pairs.
#[derive(Debug, Default)]
pub struct PairDecoder {
    inner: Decoder2<KeyDecoder, ByteVecDecoder>,
}

impl Decoder for PairDecoder {
    type Output = Pair;
    type Error = PairDecodeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let (key, value) = self.inner.end()?;
        Ok(Pair { key, value })
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for Pair {
    type Decoder = PairDecoder;
}

impl PsbtEncode for Pair {
    type Encoder<'e> = PairEncoder<'e>;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { PairEncoder::from_pair(self) }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for raw PSBT pairs.
    pub struct PairEncoder<'e>(Encoder2<KeyEncoder<'e>, PrefixedBytesEncoder<'e>>);
}

impl<'e> PairEncoder<'e> {
    fn from_pair(pair: &'e Pair) -> Self {
        Self::new(Encoder2::new(
            KeyEncoder::from_key(&pair.key),
            PrefixedBytesEncoder::new(&pair.value),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{decode_from_slice, encode_to_vec};

    // Bytes represent the "test_key" string in utf8
    const TEST_SUBKEYDATA: [u8; 8] = [0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79];

    #[test]
    fn key_roundtrip() {
        let key = Key { type_value: 2, key: vec![1, 2, 3] };
        let bytes = encode_to_vec(&key);
        assert_eq!(decode_from_slice::<Key>(&bytes).unwrap(), key);
    }

    #[test]
    fn key_roundtrip_empty_keydata() {
        let key = Key { type_value: 0xFB, key: vec![] };
        let bytes = encode_to_vec(&key);
        assert_eq!(decode_from_slice::<Key>(&bytes).unwrap(), key);
    }

    #[test]
    fn key_roundtrip_multi_byte_type_value() {
        let key = Key { type_value: 0xFC01, key: vec![0xde, 0xad, 0xbe, 0xef] };
        let bytes = encode_to_vec(&key);
        assert_eq!(decode_from_slice::<Key>(&bytes).unwrap(), key);
    }

    #[test]
    fn key_decode_vector() {
        let bytes = [0x04, 0x02, 0x01, 0x02, 0x03];
        let key = decode_from_slice::<Key>(&bytes).unwrap();
        assert_eq!(key, Key { type_value: 2, key: vec![1, 2, 3] });
    }

    #[test]
    fn key_encode_vector() {
        let key = Key { type_value: 2, key: vec![1, 2, 3] };
        assert_eq!(encode_to_vec(&key), vec![0x04, 0x02, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn key_decode_empty_is_error() {
        let err = decode_from_slice::<Key>(&[0x00]).unwrap_err();
        assert_eq!(err, bitcoin_consensus_encoding::DecodeError::Parse(KeyDecodeError::Empty));
    }

    #[test]
    fn key_decode_truncated_is_error() {
        // keylen=4 but only 2 body bytes are provided.
        let bytes = [0x04, 0x02, 0x01];
        assert!(decode_from_slice::<Key>(&bytes).is_err());
    }

    #[test]
    fn key_decoder_read_limit() {
        let mut decoder = KeyDecoder::default();
        assert_eq!(decoder.read_limit(), 1);

        let mut bytes: &[u8] = &[0x01, 0x0a];
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    fn pair_roundtrip() {
        let pair = Pair { key: Key { type_value: 2, key: vec![1, 2, 3] }, value: vec![9, 9] };
        let bytes = encode_to_vec(&pair);
        assert_eq!(decode_from_slice::<Pair>(&bytes).unwrap(), pair);
    }

    #[test]
    fn pair_roundtrip_empty_value() {
        let pair = Pair { key: Key { type_value: 0xFB, key: vec![] }, value: vec![] };
        let bytes = encode_to_vec(&pair);
        assert_eq!(decode_from_slice::<Pair>(&bytes).unwrap(), pair);
    }

    #[test]
    fn pair_decode_vector() {
        let bytes = [0x04, 0x02, 0x01, 0x02, 0x03, 0x00];
        let pair = decode_from_slice::<Pair>(&bytes).unwrap();
        assert_eq!(pair, Pair { key: Key { type_value: 2, key: vec![1, 2, 3] }, value: vec![] });
    }

    #[test]
    fn pair_encode_vector() {
        let pair = Pair { key: Key { type_value: 2, key: vec![1, 2, 3] }, value: vec![] };
        assert_eq!(encode_to_vec(&pair), vec![0x04, 0x02, 0x01, 0x02, 0x03, 0x00]);
    }

    #[test]
    fn pair_decoder_read_limit() {
        let mut decoder = PairDecoder::default();
        assert_eq!(decoder.read_limit(), 2);

        let mut bytes: &[u8] = &[0x01, 0x0a, 0x01, 0x0b];
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }

    #[test]
    fn proprietary_key_encodes() {
        let pk = ProprietaryKey::<ProprietaryType> {
            prefix: vec![1, 2, 3],
            subtype: 5,
            key: vec![9, 9],
        };
        assert_eq!(encode_to_vec(&pk), vec![0x03, 0x01, 0x02, 0x03, 0x05, 0x09, 0x09]);
    }

    #[test]
    fn proprietary_key_encodes_empty() {
        let pk = ProprietaryKey::<ProprietaryType> { prefix: vec![], subtype: 0, key: vec![] };
        assert_eq!(encode_to_vec(&pk), vec![0x00, 0x00]);
    }

    #[test]
    fn proprietary_key_encodes_no_prefix() {
        let prop_key =
            ProprietaryKey { prefix: vec![], subtype: 2u64, key: TEST_SUBKEYDATA.to_vec() };
        let bytes = encode_to_vec(&prop_key);

        assert_eq!(bytes, vec![0x00, 0x02, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79]);
    }

    #[test]
    fn proprietary_key_encodes_no_key() {
        let prop_key =
            ProprietaryKey { prefix: "prefix".as_bytes().to_vec(), subtype: 2u64, key: vec![] };
        let bytes = encode_to_vec(&prop_key);

        assert_eq!(bytes, vec![0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02]);
    }

    #[test]
    fn proprietary_key_encodes_prefix_and_key() {
        let prop_key = ProprietaryKey {
            prefix: "prefix".as_bytes().to_vec(),
            subtype: 2u64,
            key: TEST_SUBKEYDATA.to_vec(),
        };
        let bytes = encode_to_vec(&prop_key);
        assert_eq!(
            bytes,
            vec![
                0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b,
                0x65, 0x79
            ]
        );
    }

    #[test]
    fn proprietary_key_roundtrip() {
        let prop_key = ProprietaryKey {
            prefix: "prefix".as_bytes().to_vec(),
            subtype: 2u64,
            key: TEST_SUBKEYDATA.to_vec(),
        };
        let prop_key_bytes = encode_to_vec(&prop_key);
        let key = Key { type_value: 0xfc, key: prop_key_bytes };
        assert_eq!(core::convert::TryInto::<ProprietaryKey>::try_into(key).unwrap(), prop_key);
    }

    #[test]
    fn proprietary_key_decodes_no_prefix() {
        let bytes: Vec<u8> =
            vec![0x0b, 0xfc, 0x00, 0x02, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79];
        let prop_key =
            ProprietaryKey { prefix: vec![], subtype: 2u64, key: TEST_SUBKEYDATA.to_vec() };
        let decoded_key = decode_from_slice::<Key>(&bytes).unwrap();
        assert_eq!(
            core::convert::TryInto::<ProprietaryKey>::try_into(decoded_key).unwrap(),
            prop_key
        );
    }

    #[test]
    fn proprietary_key_decodes_no_key() {
        let bytes: Vec<u8> = vec![0x09, 0xfc, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02];
        let prop_key =
            ProprietaryKey { prefix: "prefix".as_bytes().to_vec(), subtype: 2u64, key: vec![] };
        let decoded_key = decode_from_slice::<Key>(&bytes).unwrap();
        assert_eq!(
            core::convert::TryInto::<ProprietaryKey>::try_into(decoded_key).unwrap(),
            prop_key
        );
    }

    #[test]
    fn proprietary_key_decodes_prefix_and_key() {
        let bytes: Vec<u8> = vec![
            0x11, 0xfc, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02, 0x74, 0x65, 0x73, 0x74,
            0x5f, 0x6b, 0x65, 0x79,
        ];
        let prop_key = ProprietaryKey {
            prefix: "prefix".as_bytes().to_vec(),
            subtype: 2u64,
            key: TEST_SUBKEYDATA.to_vec(),
        };
        let decoded_key = decode_from_slice::<Key>(&bytes).unwrap();
        assert_eq!(
            core::convert::TryInto::<ProprietaryKey>::try_into(decoded_key).unwrap(),
            prop_key
        );
    }
}
