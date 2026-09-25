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

// Implements our Deserialize trait using bitcoin consensus deserialization.
macro_rules! v2_impl_psbt_de_serialize {
    ($thing:ty) => {
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

#[rustfmt::skip]
macro_rules! v2_impl_psbt_get_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident, $unkeyed_typeval:ident)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push($crate::raw::Pair {
                key: $crate::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: ::alloc::vec![],
                },
                value: $crate::encoding::encode_to_vec($unkeyed_name),
            });
        }
    };
    ($rv:ident.push_map($slf:ident.$keyed_name:ident, $keyed_typeval:ident)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push($crate::raw::Pair {
                key: $crate::raw::Key {
                    type_value: $keyed_typeval,
                    key: $crate::encoding::encode_to_vec(key),
                },
                value: $crate::encoding::encode_to_vec(val),
            });
        }
    };
}

// macros for serde of hashes
macro_rules! v2_impl_psbt_hash_de_serialize {
    ($hash_type:ty) => {
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
