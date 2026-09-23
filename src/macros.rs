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
