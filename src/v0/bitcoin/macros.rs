// SPDX-License-Identifier: CC0-1.0

#[allow(unused_macros)]
macro_rules! combine {
    ($thing:ident, $slf:ident, $other:ident) => {
        if let (&None, Some($thing)) = (&$slf.$thing, $other.$thing) {
            $slf.$thing = Some($thing);
        }
    };
}

macro_rules! impl_psbt_de_serialize {
    ($thing:ty) => {
        impl_psbt_serialize!($thing);
        impl_psbt_deserialize!($thing);
    };
}

macro_rules! impl_psbt_deserialize {
    ($thing:ty) => {
        impl $crate::v0::bitcoin::serialize::Deserialize for $thing {
            fn deserialize(bytes: &[u8]) -> core::result::Result<Self, $crate::v0::bitcoin::Error> {
                $crate::bitcoin::consensus::deserialize(&bytes[..])
                    .map_err(|e| $crate::v0::bitcoin::Error::from(e))
            }
        }
    };
}

macro_rules! impl_psbt_serialize {
    ($thing:ty) => {
        impl $crate::v0::bitcoin::serialize::Serialize for $thing {
            fn serialize(&self) -> alloc::vec::Vec<u8> {
                $crate::bitcoin::consensus::serialize(self)
            }
        }
    };
}

macro_rules! impl_psbtmap_serialize {
    ($thing:ty) => {
        impl $crate::v0::bitcoin::serialize::Serialize for $thing {
            fn serialize(&self) -> Vec<u8> { self.serialize_map() }
        }
    };
}

macro_rules! impl_psbtmap_deserialize {
    ($thing:ty) => {
        impl $crate::v0::bitcoin::serialize::Deserialize for $thing {
            fn deserialize(bytes: &[u8]) -> core::result::Result<Self, $crate::v0::bitcoin::Error> {
                let mut decoder = bytes;
                Self::decode(&mut decoder)
            }
        }
    };
}

macro_rules! impl_psbtmap_decoding {
    ($thing:ty) => {
        impl $thing {
            pub(crate) fn decode<R: bitcoin::io::Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<Self, $crate::v0::bitcoin::Error> {
                let mut rv: Self = core::default::Default::default();

                loop {
                    match $crate::v0::bitcoin::raw::Pair::decode(r) {
                        Ok(pair) => rv.insert_pair(pair)?,
                        Err($crate::v0::bitcoin::Error::NoMorePairs) => return Ok(rv),
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    };
}

macro_rules! impl_psbtmap_ser_de_serialize {
    ($thing:ty) => {
        impl_psbtmap_decoding!($thing);
        impl_psbtmap_serialize!($thing);
        impl_psbtmap_deserialize!($thing);
    };
}

#[rustfmt::skip]
macro_rules! impl_psbt_insert_pair {
    ($slf:ident.$unkeyed_name:ident <= <$raw_key:ident: _>|<$raw_value:ident: $unkeyed_value_type:ty>) => {
        if $raw_key.key.is_empty() {
            if $slf.$unkeyed_name.is_none() {
                let val: $unkeyed_value_type = $crate::v0::bitcoin::serialize::Deserialize::deserialize(&$raw_value)?;
                $slf.$unkeyed_name = Some(val)
            } else {
                return Err($crate::v0::bitcoin::Error::DuplicateKey($raw_key).into());
            }
        } else {
            return Err($crate::v0::bitcoin::Error::InvalidKey($raw_key).into());
        }
    };
    ($slf:ident.$keyed_name:ident <= <$raw_key:ident: $keyed_key_type:ty>|<$raw_value:ident: $keyed_value_type:ty>) => {
        if !$raw_key.key.is_empty() {
            let key_val: $keyed_key_type = $crate::v0::bitcoin::serialize::Deserialize::deserialize(&$raw_key.key)?;
            match $slf.$keyed_name.entry(key_val) {
                alloc::collections::btree_map::Entry::Vacant(empty_key) => {
                    let val: $keyed_value_type = $crate::v0::bitcoin::serialize::Deserialize::deserialize(&$raw_value)?;
                    empty_key.insert(val);
                }
                alloc::collections::btree_map::Entry::Occupied(_) => return Err($crate::v0::bitcoin::Error::DuplicateKey($raw_key).into()),
            }
        } else {
            return Err($crate::v0::bitcoin::Error::InvalidKey($raw_key).into());
        }
    };
}

#[rustfmt::skip]
macro_rules! psbt_insert_hash_pair {
    (&mut $slf:ident.$map:ident <= $raw_key:ident|$raw_value:ident|$hash:path|$hash_type_error:path) => {
        if $raw_key.key.is_empty() {
            return Err($crate::v0::bitcoin::Error::InvalidKey($raw_key));
        }
        let key_val: $hash = $crate::v0::bitcoin::serialize::Deserialize::deserialize(&$raw_key.key)?;
        match $slf.$map.entry(key_val) {
            alloc::collections::btree_map::Entry::Vacant(empty_key) => {
                let val: alloc::vec::Vec<u8> = $crate::v0::bitcoin::serialize::Deserialize::deserialize(&$raw_value)?;
                if <$hash as $crate::bitcoin::hashes::Hash>::hash(&val) != key_val {
                    return Err($crate::v0::bitcoin::Error::InvalidPreimageHashPair {
                        preimage: val.into_boxed_slice(),
                        hash: alloc::boxed::Box::from(key_val.as_ref()),
                        hash_type: $hash_type_error,
                    });
                }
                empty_key.insert(val);
            }
            alloc::collections::btree_map::Entry::Occupied(_) => return Err($crate::v0::bitcoin::Error::DuplicateKey($raw_key)),
        }
    }
}

#[rustfmt::skip]
macro_rules! impl_psbt_get_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident, $unkeyed_typeval:ident)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push($crate::v0::bitcoin::raw::Pair {
                key: $crate::v0::bitcoin::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: ::alloc::vec![],
                },
                value: $crate::v0::bitcoin::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push_map($slf:ident.$keyed_name:ident, $keyed_typeval:ident)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push($crate::v0::bitcoin::raw::Pair {
                key: $crate::v0::bitcoin::raw::Key {
                    type_value: $keyed_typeval,
                    key: $crate::v0::bitcoin::serialize::Serialize::serialize(key),
                },
                value: $crate::v0::bitcoin::serialize::Serialize::serialize(val),
            });
        }
    };
}

// macros for serde of hashes
macro_rules! impl_psbt_hash_de_serialize {
    ($hash_type:ty) => {
        impl_psbt_hash_serialize!($hash_type);
        impl_psbt_hash_deserialize!($hash_type);
    };
}

macro_rules! impl_psbt_hash_deserialize {
    ($hash_type:ty) => {
        impl $crate::v0::bitcoin::serialize::Deserialize for $hash_type {
            fn deserialize(bytes: &[u8]) -> core::result::Result<Self, $crate::v0::bitcoin::Error> {
                <$hash_type>::from_slice(&bytes[..])
                    .map_err(|e| $crate::v0::bitcoin::Error::from(e))
            }
        }
    };
}

macro_rules! impl_psbt_hash_serialize {
    ($hash_type:ty) => {
        impl $crate::v0::bitcoin::serialize::Serialize for $hash_type {
            fn serialize(&self) -> alloc::vec::Vec<u8> { self.as_byte_array().to_vec() }
        }
    };
}
