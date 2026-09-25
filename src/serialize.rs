// SPDX-License-Identifier: CC0-1.0

//! PSBT serialization.
//!
//! Traits to serialize PSBT values to and from raw bytes
//! according to the BIP-174 specification.

#[cfg(test)]
mod tests {
    use alloc::format;
    use core::convert::TryFrom;

    use bitcoin::hashes::Hash;
    use bitcoin::taproot::{LeafVersion, TapNodeHash, TapTree, TaprootBuilder};
    use bitcoin::ScriptBuf;

    // Composes tree matching a given depth map, filled with dumb script leaves,
    // each of which consists of a single push-int op code, with int value
    // increased for each consecutive leaf.
    pub fn compose_taproot_builder<'map>(
        opcode: u8,
        depth_map: impl IntoIterator<Item = &'map u8>,
    ) -> TaprootBuilder {
        let mut val = opcode;
        let mut builder = TaprootBuilder::new();
        for depth in depth_map {
            let script = ScriptBuf::from_hex(&format!("{:02x}", val)).unwrap();
            builder = builder.add_leaf(*depth, script).unwrap();
            let (new_val, _) = val.overflowing_add(1);
            val = new_val;
        }
        builder
    }

    #[test]
    fn taptree_hidden() {
        let mut builder = compose_taproot_builder(0x51, &[2, 2, 2]);
        builder = builder
            .add_leaf_with_ver(
                3,
                ScriptBuf::from_hex("b9").unwrap(),
                LeafVersion::from_consensus(0xC2).unwrap(),
            )
            .unwrap();
        builder = builder.add_hidden_node(3, TapNodeHash::all_zeros()).unwrap();
        assert!(TapTree::try_from(builder).is_err());
    }
}
