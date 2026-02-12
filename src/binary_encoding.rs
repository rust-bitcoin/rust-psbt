//! Scrachtpad to implement binary serialization for PSBT using consensus_encoding crate
use encoding::{
    ByteVecDecoder, ByteVecDecoderError, BytesEncoder, CompactSizeDecoder, CompactSizeDecoderError,
    CompactSizeEncoder, Decodable, Decoder, Encodable, Encoder3,
};

use crate::prelude::Vec;

/// The key of a key-value PSBT pair, in its raw byte form.
///
/// - `<key> := <keylen> <keytype> <keydata>`
///
/// We do not carry the `keylen` around, we just create the `VarInt` length when serializing and
/// deserializing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Key {
    /// The `keytype` of this PSBT map key.
    pub type_value: u64,
    /// The `keydata` itself in raw byte form.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

encoding::encoder_newtype! {
    /// The encoder for the [`Transaction`] type.
    pub struct KeyEncoder<'e>(
        Encoder3<
            CompactSizeEncoder,
            CompactSizeEncoder,
            BytesEncoder<'e>,
        >
    );
}

impl Encodable for Key {
    type Encoder<'a>
        = KeyEncoder<'a>
    where
        Self: 'a;

    fn encoder(&self) -> Self::Encoder<'_> {
        let encoded_size = CompactSizeEncoder::encoded_size(self.type_value as usize);
        KeyEncoder::new(Encoder3::new(
            CompactSizeEncoder::new(self.key.len() + encoded_size),
            CompactSizeEncoder::new(self.type_value as usize),
            BytesEncoder::without_length_prefix(&self.key),
        ))
    }
}

/// The decoder for the [`Key`] type.
pub struct KeyDecoder {
    state: KeyDecoderState,
}

impl Default for KeyDecoder {
    fn default() -> Self { Self::new() }
}

impl KeyDecoder {
    /// Constructs a new [`KeyDecoder`].
    pub const fn new() -> Self { Self { state: KeyDecoderState::KeyLength(ByteVecDecoder::new()) } }
}

/// An error consensus decoding a PSBT [`Key`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDecoderError(KeyDecoderErrorInner);

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyDecoderErrorInner {
    /// Error while decoding the key length.
    Length(ByteVecDecoderError),
    /// Error while decoding the key type.
    Type(CompactSizeDecoderError),
    /// Attempt to call `end()` before the key was complete. Holds
    /// a description of the current state.
    EarlyEnd(&'static str),
}

impl alloc::fmt::Display for KeyDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use KeyDecoderErrorInner as E;

        match self.0 {
            E::Length(ref e) => write!(f, "key decoder error: {}", e),
            E::Type(ref e) => write!(f, "key decoder error: {}", e),
            E::EarlyEnd(s) => write!(f, "early end of key (still decoding {})", s),
        }
    }
}

/// The state of the key decoder.
pub enum KeyDecoderState {
    /// Decoding the key length.
    KeyLength(ByteVecDecoder),
    /// Decoding the key type.
    KeyType(Vec<u8>, CompactSizeDecoder),
    /// Done decoding the [`Key`].
    Done(Key),
    /// When `end()`ing a sub-decoder, encountered an error which prevented us
    /// from constructing the next sub-decoder.
    Errored,
}

impl Decodable for Key {
    type Decoder = KeyDecoder;
    fn decoder() -> Self::Decoder { KeyDecoder::new() }
}

impl Decoder for KeyDecoder {
    type Output = Key;
    type Error = KeyDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        use {KeyDecoderError as E, KeyDecoderErrorInner as Inner, KeyDecoderState as State};

        loop {
            match &mut self.state {
                State::KeyLength(decoder) => {
                    if decoder.push_bytes(bytes).map_err(|e| E(Inner::Length(e)))? {
                        return Ok(true);
                    }
                }
                State::KeyType(key_as_bytes, decoder) => {
                    let key_as_bytes_slice = &mut key_as_bytes.as_slice();
                    if decoder.push_bytes(key_as_bytes_slice).map_err(|e| E(Inner::Type(e)))? {
                        return Ok(true);
                    }
                    *key_as_bytes = (*key_as_bytes_slice).to_vec();
                }
                State::Done(..) => return Ok(false),
                State::Errored => panic!("call to push_bytes() after decoder errored"),
            }

            match core::mem::replace(&mut self.state, State::Errored) {
                State::KeyLength(decoder) => {
                    let type_and_data = decoder.end().map_err(|e| E(Inner::Length(e)))?;

                    self.state = State::KeyType(type_and_data, CompactSizeDecoder::new());
                }
                State::KeyType(type_and_data, decoder) => {
                    let key_type = decoder.end().map_err(|e| E(Inner::Type(e)))?;

                    let key_type_u64 = u64::try_from(key_type).expect("the maximum encodable value in a compact size unsigned integer fits within u64");

                    let data = (*type_and_data).to_vec();

                    self.state = State::Done(Key { type_value: key_type_u64, key: data });
                }
                State::Done(..) => {
                    return Ok(false);
                }
                State::Errored => panic!("call to push_bytes() after decoder errored"),
            }
        }
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        use {KeyDecoderError as E, KeyDecoderErrorInner as Inner, KeyDecoderState as State};

        match self.state {
            State::KeyLength(_) => Err(E(Inner::EarlyEnd("length"))),
            State::KeyType(..) => Err(E(Inner::EarlyEnd("type"))),
            State::Done(key) => Ok(key),
            State::Errored => panic!("call to end() after decoder errored"),
        }
    }

    #[inline]
    fn read_limit(&self) -> usize {
        use KeyDecoderState as State;

        match &self.state {
            State::KeyLength(decoder) => decoder.read_limit(),
            State::KeyType(bytes, _) => bytes.len(),
            State::Done(_) => 0,
            // `read_limit` is not documented to panic or return an error, so we
            // return a dummy value if the decoder is in an error state.
            State::Errored => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use encoding::{Decodable, Decoder, Encodable, Encoder};

    use super::{Key, KeyDecoder, Vec};

    fn encode_key(key: Key) -> Vec<u8> {
        let mut key_encoder = key.encoder();
        let mut advance = true;
        let mut encoded = vec![];

        while advance {
            for &byte in key_encoder.current_chunk() {
                encoded.push(byte);
            }
            advance = key_encoder.advance();
        }

        encoded
    }

    #[test]
    fn roundtrip() {
        let original = Key { type_value: 0x06, key: vec![0x01, 0x02, 0x03, 0x04] };
        let encoded = encode_key(original.clone());
        let mut key_decoder = Key::decoder();
        let result = key_decoder.push_bytes(&mut encoded.as_slice());

        assert!(!result.unwrap());

        let decoded = key_decoder.end().unwrap();

        assert_eq!(original, decoded);
    }

    mod encode {
        use super::*;

        #[test]
        fn keytype_only() {
            let key = Key { type_value: 0x00, key: vec![] };
            let encoded = encode_key(key);

            assert_eq!(&encoded.as_slice(), &[0x01, 0x00]);
        }

        #[test]
        fn key_with_keydata() {
            let key = Key { type_value: 0x02, key: vec![0x01, 0x02, 0x03] };
            let encoded = encode_key(key);

            assert_eq!(encoded, vec![0x04, 0x02, 0x01, 0x02, 0x03]);
        }
    }

    mod decode {
        use super::*;

        #[test]
        fn keytype_only() {
            let bytes: Vec<u8> = vec![0x01, 0x00];
            let mut key_decoder = Key::decoder();
            let _ = key_decoder.push_bytes(&mut bytes.as_slice());
            let key = key_decoder.end().unwrap();

            assert_eq!(key.type_value, 0x00);
            assert!(key.key.is_empty());
        }

        #[test]
        fn key_with_keydata() {
            let bytes = vec![0x04, 0x02, 0x01, 0x02, 0x03];
            let mut key_decoder = Key::decoder();
            let _ = key_decoder.push_bytes(&mut bytes.as_slice());
            let key = key_decoder.end().unwrap();

            assert_eq!(key.type_value, 0x02);
            assert_eq!(key.key, vec![0x01, 0x02, 0x03]);
        }

        #[test]
        fn read_limit_after_length_state() {
            let decoder = Key::decoder();
            assert!(decoder.read_limit() > 0);
        }

        #[test]
        fn early_end_length() {
            let decoder = KeyDecoder::new();
            let result = decoder.end();

            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert_eq!(err_str, "early end of key (still decoding length)");
        }

        #[test]
        fn early_end_type() {
            let mut decoder = KeyDecoder::new();
            let mut bytes: &[u8] = &[0x01];
            let _ = decoder.push_bytes(&mut bytes);
            // Provide a partial, larger than 1 byte compact size unsigned integer
            let mut bytes: &[u8] = &[0xfd];
            let needs_more = decoder.push_bytes(&mut bytes).unwrap();
            assert!(needs_more); // needs_more should be true, because 0xfd requires 3 bytes

            let result = decoder.end();
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert_eq!(err_str, "early end of key (still decoding type)");
        }

        #[test]
        fn push_bytes_incremental_push() {
            let mut decoder = KeyDecoder::new();

            let full_bytes = vec![0x04, 0x02, 0x01, 0x02, 0x03];

            for byte in full_bytes {
                let mut slice: &[u8] = &[byte];
                let needs_more = decoder.push_bytes(&mut slice).unwrap();

                assert!(needs_more || slice.is_empty());
            }

            let key = decoder.end().unwrap();
            assert_eq!(key.type_value, 0x02);
            assert_eq!(key.key, vec![0x01, 0x02, 0x03]);
        }

        #[test]
        fn read_limit_after_done_state() {
            let mut decoder = KeyDecoder::new();
            let mut bytes: &[u8] = &[0x01, 0x00];
            let _ = decoder.push_bytes(&mut bytes);

            assert_eq!(decoder.read_limit(), 0);
        }

        #[test]
        fn empty_slice() {
            let mut decoder = KeyDecoder::new();
            let mut empty: &[u8] = &[];

            let result = decoder.push_bytes(&mut empty).unwrap();
            assert!(result);
        }

        #[test]
        fn read_limit_after_invalid_type() {
            let mut decoder = KeyDecoder::new();
            let mut bytes: &[u8] = &[0x01, 0x50];

            let _ = decoder.push_bytes(&mut bytes);

            assert_eq!(decoder.read_limit(), 0);
        }

        #[test]
        fn read_limit_in_keyasbytes_state() {
            let mut decoder = KeyDecoder::new();
            let mut bytes: &[u8] = &[0x03];
            let _ = decoder.push_bytes(&mut bytes);

            assert_eq!(decoder.read_limit(), 3);
        }
    }
}
