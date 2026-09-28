// SPDX-License-Identifier: CC0-1.0

//! Raw PSBT key-value pairs.
//!
//! Raw PSBT key-value pairs as defined at
//! <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>.

use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::fmt;

use bitcoin::consensus::encode::{
    self, deserialize, serialize, Decodable, Encodable, VarInt, MAX_VEC_SIZE,
};
use bitcoin::hex::DisplayHex;
use bitcoin::io::{self, Write};

use super::serialize::{Deserialize, Serialize};
use crate::v0::bitcoin::Error;

/// A PSBT key in its raw byte form.
///
/// `<key> := <keylen> <keytype> <keydata>`
#[derive(Debug, PartialEq, Hash, Eq, Clone, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Key {
    /// The type of this PSBT key.
    pub type_value: u64,
    /// The key data itself in raw byte form.
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub key: Vec<u8>,
}

/// A PSBT key-value pair in its raw byte form.
/// `<keypair> := <key> <value>`
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Pair {
    /// The key of this key-value pair.
    pub key: Key,
    /// The value data of this key-value pair in raw byte form.
    /// `<value> := <valuelen> <valuedata>`
    #[cfg_attr(feature = "serde", serde(with = "crate::serde_utils::hex_bytes"))]
    pub value: Vec<u8>,
}

/// Default implementation for proprietary key subtyping
pub type ProprietaryType = u64;

/// Proprietary keys (i.e. keys starting with 0xFC byte) with their internal
/// structure according to BIP 174.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
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

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "type: {:#x}, key: {:x}", self.type_value, self.key.as_hex())
    }
}

impl Key {
    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let VarInt(byte_size): VarInt = Decodable::consensus_decode(r)?;

        if byte_size == 0 {
            return Err(Error::NoMorePairs);
        }

        let type_value: VarInt = Decodable::consensus_decode(r)?;

        let key_byte_size = match byte_size.checked_sub(
            u64::try_from(type_value.size()).expect("size() returns 1-9, fits inside u64"),
        ) {
            Some(val) => val,
            None => {
                return Err(encode::Error::ParseFailed(
                    "encoded keytype is larger than specified length",
                ))?;
            }
        };

        if key_byte_size > MAX_VEC_SIZE as u64 {
            return Err(encode::Error::OversizedVectorAllocation {
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
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = bytes;
        Self::decode(&mut decoder)
    }
}

impl Pair {
    pub(crate) fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self { key: Key::decode(r)?, value: Decodable::consensus_decode(r)? })
    }
}

impl<Subtype> Encodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(w)?;
        let subtype_len = VarInt::from(self.subtype.into()).consensus_encode(w)?;
        w.write_all(&self.key)?;
        len += self.key.len() + subtype_len;
        Ok(len)
    }
}

impl<Subtype> Decodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
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

impl<Subtype> ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    /// Constructs full [Key] corresponding to this proprietary key type
    pub fn to_key(&self) -> Key { Key { type_value: 0xFC, key: serialize(self) } }
}

impl<Subtype> TryFrom<Key> for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    type Error = Error;

    /// Constructs a [`ProprietaryKey`] from a [`Key`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProprietaryKey`] if `key` does not start with `0xFC` byte.
    fn try_from(key: Key) -> Result<Self, Self::Error> {
        if key.type_value != 0xFC {
            return Err(Error::InvalidProprietaryKey);
        }

        Ok(deserialize(&key.key)?)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for ProprietaryKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        /// Default maximum size of a decoded object in bytes.
        ///
        /// Matches Bitcoin Core's default [serialization limit]. This is
        /// a high level anti-DoS limit which all bitcoin types should
        /// easily fit within.
        ///
        /// [serialization limit]: https://github.com/bitcoin/bitcoin/blob/a7c29df0e5ace05b6186612671d6103c112ec922/src/serialize.h#L32
        const MAX_COMPACT_SIZE: u64 = 0x0200_0000;
        let subtype = u.int_in_range(0..=MAX_COMPACT_SIZE)?;
        Ok(Self { prefix: Vec::<u8>::arbitrary(u)?, subtype, key: Vec::<u8>::arbitrary(u)? })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for Key {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { type_value: u.arbitrary()?, key: Vec::<u8>::arbitrary(u)? })
    }
}
