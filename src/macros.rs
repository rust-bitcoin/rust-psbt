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
