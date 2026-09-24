// SPDX-License-Identifier: CC0-1.0

/// Combines two `Option<Foo>` fields.
///
/// Sets `self.thing` to be `Some(other.thing)` iff `self.thing` is `None`.
/// If `self.thing` already contains a value then this macro does nothing.
macro_rules! v2_combine_option {
    ($thing:ident, $slf:ident, $other:ident) => {
        if let (&None, Some($thing)) = (&$slf.$thing, $other.$thing) {
            $slf.$thing = Some($thing);
        }
    };
}

/// Combines to `BTreeMap` fields by extending the map in `self.thing`.
macro_rules! v2_combine_map {
    ($thing:ident, $slf:ident, $other:ident) => {
        $slf.$thing.extend($other.$thing)
    };
}

// Implements our Serialize/Deserialize traits using bitcoin consensus serialization.
macro_rules! v2_impl_psbt_de_serialize {
    ($thing:ty) => {
        v2_impl_psbt_serialize!($thing);
        v2_impl_psbt_deserialize!($thing);
    };
}

macro_rules! v2_impl_psbt_deserialize {
    ($thing:ty) => {
        impl $crate::serialize::Deserialize for $thing {
            fn deserialize(bytes: &[u8]) -> Result<Self, $crate::serialize::Error> {
                bitcoin::consensus::deserialize(&bytes[..])
                    .map_err(|e| $crate::serialize::Error::from(e))
            }
        }
    };
}

macro_rules! v2_impl_psbt_serialize {
    ($thing:ty) => {
        impl $crate::serialize::Serialize for $thing {
            fn serialize(&self) -> alloc::vec::Vec<u8> { bitcoin::consensus::serialize(self) }
        }
    };
}

// Note we purposefully do not use the fully qualified path for `InsertPairError`.
#[rustfmt::skip]
macro_rules! v2_impl_psbt_insert_pair {
    ($slf:ident.$unkeyed_name:ident <= <$raw_key:ident: _>|<$raw_value:ident: $unkeyed_value_type:ty>) => {
        if $raw_key.key.is_empty() {
            if $slf.$unkeyed_name.is_none() {
                let val: $unkeyed_value_type = $crate::serialize::Deserialize::deserialize(&$raw_value)?;
                $slf.$unkeyed_name = Some(val)
            } else {
                return Err(InsertPairError::DuplicateKey($raw_key).into());
            }
        } else {
            return Err(InsertPairError::InvalidKeyDataNotEmpty($raw_key).into());
        }
    };
    ($slf:ident.$keyed_name:ident <= <$raw_key:ident: $keyed_key_type:ty>|<$raw_value:ident: $keyed_value_type:ty>) => {
        if !$raw_key.key.is_empty() {
            let key_val: $keyed_key_type = $crate::serialize::Deserialize::deserialize(&$raw_key.key)?;
            match $slf.$keyed_name.entry(key_val) {
                alloc::collections::btree_map::Entry::Vacant(empty_key) => {
                    let val: $keyed_value_type = $crate::serialize::Deserialize::deserialize(&$raw_value)?;
                    empty_key.insert(val);
                }
                alloc::collections::btree_map::Entry::Occupied(_) => return Err(InsertPairError::DuplicateKey($raw_key).into()),
            }
        } else {
            return Err(InsertPairError::InvalidKeyDataEmpty($raw_key).into());
        }
    };
}

#[rustfmt::skip]
macro_rules! v2_impl_psbt_get_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident, $unkeyed_typeval:ident)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push($crate::raw::Pair {
                key: $crate::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: ::alloc::vec![],
                },
                value: $crate::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push_map($slf:ident.$keyed_name:ident, $keyed_typeval:ident)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push($crate::raw::Pair {
                key: $crate::raw::Key {
                    type_value: $keyed_typeval,
                    key: $crate::serialize::Serialize::serialize(key),
                },
                value: $crate::serialize::Serialize::serialize(val),
            });
        }
    };
}

// macros for serde of hashes
macro_rules! v2_impl_psbt_hash_de_serialize {
    ($hash_type:ty) => {
        v2_impl_psbt_hash_serialize!($hash_type);
        v2_impl_psbt_hash_deserialize!($hash_type);
    };
}

macro_rules! v2_impl_psbt_hash_deserialize {
    ($hash_type:ty) => {
        impl $crate::serialize::Deserialize for $hash_type {
            fn deserialize(bytes: &[u8]) -> Result<Self, $crate::serialize::Error> {
                <$hash_type>::from_slice(&bytes[..]).map_err(|e| $crate::serialize::Error::from(e))
            }
        }
    };
}

macro_rules! v2_impl_psbt_hash_serialize {
    ($hash_type:ty) => {
        impl $crate::serialize::Serialize for $hash_type {
            fn serialize(&self) -> alloc::vec::Vec<u8> { self.as_byte_array().to_vec() }
        }
    };
}
