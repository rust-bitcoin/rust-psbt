// SPDX-License-Identifier: CC0-1.0

//! Implementation of the "maps" concept defined in BIP-174.
//!
//! > The Partially Signed Bitcoin Transaction (PSBT) format consists of key-value maps.
//! > ...
//! > `<global-map> := <keypair>* 0x00`
//! > `<input-map> := <keypair>* 0x00`
//! > `<output-map> := <keypair>* 0x00`
//! > ...
//!
//! [BIP-174] defines each key-value pair as:
//!
//! - `<keypair> := <key> <value>`
//! - `<key> := <keylen> <keytype> <keydata>`
//!
//! This module provides the raw key types, decoders, encoders, and iterators
//! used by the global, input, and output map implementations.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

/// The `global-map`.
pub mod global;
/// The `input-map`.
pub mod input;
/// The `output-map`.
pub mod output;

use alloc::collections::btree_map;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;

use bitcoin::hex::DisplayHex;
use bitcoin_consensus_encoding::{
    ByteVecDecoder, ByteVecDecoderError, BytesEncoder, CompactSizeDecoderError, CompactSizeEncoder,
    CompactSizeU64Decoder, Decoder, Decoder2, DecoderStatus, Encoder2, Encoder3, ExactSizeEncoder,
    PrefixedBytesEncoder,
};

use crate::consts::PSBT_GLOBAL_PROPRIETARY;
use crate::encoding::{KeyValueEncoder, PsbtDecode, PsbtEncode};

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

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "type: {:#x}, key: {:x}", self.type_value, self.key.as_hex())
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

/// Error when attempting to construct a [`ProprietaryKey`] from a [`Key`]
/// whose type byte is not `0xFC` or whose key data is malformed.
#[derive(Debug)]
pub struct InvalidProprietaryKeyError;

impl fmt::Display for InvalidProprietaryKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid proprietary key")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidProprietaryKeyError {}

impl<Subtype> TryFrom<Key> for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    type Error = InvalidProprietaryKeyError;

    /// Constructs a [`ProprietaryKey`] from a [`Key`].
    ///
    /// # Errors
    ///
    /// Returns [`InvalidProprietaryKeyError`] if `key` does not start with `0xFC`.
    fn try_from(key: Key) -> Result<Self, Self::Error> {
        if key.type_value != 0xFC {
            return Err(InvalidProprietaryKeyError);
        }

        let mut inner = Decoder2::<ByteVecDecoder, CompactSizeU64Decoder>::default();

        let mut bytes = key.key.as_slice();
        if inner.push_bytes(&mut bytes).map_err(|_| InvalidProprietaryKeyError)?.needs_more() {
            return Err(InvalidProprietaryKeyError);
        }

        let (prefix, subtype) = inner.end().map_err(|_| InvalidProprietaryKeyError)?;

        Ok(Self { prefix, subtype: subtype.into(), key: bytes.to_vec() })
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

#[cfg(test)]
mod tests {
    use alloc::{format, vec};

    use super::*;
    use crate::encoding::{decode_from_slice, encode_to_vec};

    // Bytes represent the "test_key" string in utf8
    const TEST_SUBKEYDATA: [u8; 8] = [0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79];

    #[test]
    fn key_display_includes_type_and_keydata() {
        let key = Key { type_value: 0x02, key: vec![0xde, 0xad] };
        let s = format!("{}", key);
        assert!(s.contains("0x2"), "must contain type value: {}", s);
        assert!(s.contains("dead"), "must contain keydata hex: {}", s);
    }

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
