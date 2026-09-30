// SPDX-License-Identifier: CC0-1.0

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::bitcoin::hashes::{hash160, sha256d, Hash};
use crate::bitcoin::key::XOnlyPublicKey;
use crate::bitcoin::taproot::{self, ControlBlock, LeafVersion, TapLeafHash};
use crate::bitcoin::{absolute, ecdsa, relative, ScriptBuf};
use crate::map::input::Input;
use crate::miniscript::{MiniscriptKey, Preimage32, Satisfier, SigType, ToPublicKey};

/// A PSBT [`Satisfier`] for an input.
///
/// Contains reference to the [`Psbt`] because multiple inputs will share the same PSBT. All
/// operations on this structure will panic if index is more than number of inputs in pbst
///
/// [`Satisfier`]: crate::miniscript::Satisfier
pub(crate) struct InputSatisfier<'a> {
    pub(crate) input: &'a Input,
}

impl<Pk: MiniscriptKey + ToPublicKey> Satisfier<Pk> for InputSatisfier<'_> {
    fn lookup_tap_key_spend_sig(&self, pk: &Pk) -> Option<taproot::Signature> {
        if let Some(key) = self.input.tap_internal_key {
            if pk.to_x_only_pubkey() == key {
                return self.input.tap_key_sig;
            }
        }
        None
    }

    fn lookup_tap_leaf_script_sig(&self, pk: &Pk, lh: &TapLeafHash) -> Option<taproot::Signature> {
        self.input.tap_script_sigs.get(&(pk.to_x_only_pubkey(), *lh)).copied()
    }

    fn lookup_raw_pkh_pk(&self, pkh: &hash160::Hash) -> Option<bitcoin::PublicKey> {
        self.input
            .bip32_derivations
            .iter()
            .find(|&(pubkey, _)| pubkey.to_pubkeyhash(SigType::Ecdsa) == *pkh)
            .map(|(pubkey, _)| *pubkey)
    }

    fn lookup_tap_control_block_map(
        &self,
    ) -> Option<&BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)>> {
        Some(&self.input.tap_scripts)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        pkh: &(hash160::Hash, TapLeafHash),
    ) -> Option<(XOnlyPublicKey, taproot::Signature)> {
        self.input
            .tap_script_sigs
            .iter()
            .find(|&((pubkey, lh), _sig)| {
                pubkey.to_pubkeyhash(SigType::Schnorr) == pkh.0 && *lh == pkh.1
            })
            .map(|((x_only_pk, _leaf_hash), sig)| (*x_only_pk, *sig))
    }

    fn lookup_ecdsa_sig(&self, pk: &Pk) -> Option<ecdsa::Signature> {
        self.input.partial_sigs.get(&pk.to_public_key()).copied()
    }

    fn lookup_raw_pkh_ecdsa_sig(
        &self,
        pkh: &hash160::Hash,
    ) -> Option<(bitcoin::PublicKey, ecdsa::Signature)> {
        self.input
            .partial_sigs
            .iter()
            .find(|&(pubkey, _sig)| pubkey.to_pubkeyhash(SigType::Ecdsa) == *pkh)
            .map(|(pk, sig)| (*pk, *sig))
    }

    // TODO: Verify this is correct.
    fn check_after(&self, n: absolute::LockTime) -> bool {
        match n {
            absolute::LockTime::Blocks(height) =>
                if let Some(lock_time) = self.input.min_height {
                    return height <= lock_time;
                },
            absolute::LockTime::Seconds(time) =>
                if let Some(lock_time) = self.input.min_time {
                    return time <= lock_time;
                },
        }
        false
    }

    // TODO: Verify this is correct.
    fn check_older(&self, n: relative::LockTime) -> bool {
        match self.input.sequence {
            Some(seq) => match relative::LockTime::from_sequence(seq) {
                Err(_) => false,
                Ok(lock_time) => n.is_implied_by(lock_time),
            },
            None => false,
        }
    }

    fn lookup_hash160(&self, h: &Pk::Hash160) -> Option<Preimage32> {
        self.input.hash160_preimages.get(&Pk::to_hash160(h)).and_then(try_vec_as_preimage32)
    }

    fn lookup_sha256(&self, h: &Pk::Sha256) -> Option<Preimage32> {
        self.input.sha256_preimages.get(&Pk::to_sha256(h)).and_then(try_vec_as_preimage32)
    }

    fn lookup_hash256(&self, h: &Pk::Hash256) -> Option<Preimage32> {
        self.input
            .hash256_preimages
            .get(&sha256d::Hash::from_byte_array(Pk::to_hash256(h).to_byte_array())) // upstream psbt operates on hash256
            .and_then(try_vec_as_preimage32)
    }

    fn lookup_ripemd160(&self, h: &Pk::Ripemd160) -> Option<Preimage32> {
        self.input.ripemd160_preimages.get(&Pk::to_ripemd160(h)).and_then(try_vec_as_preimage32)
    }
}

#[allow(clippy::ptr_arg)] // We don't control the function signature this is used in.
fn try_vec_as_preimage32(vec: &Vec<u8>) -> Option<Preimage32> {
    if vec.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(vec);
        Some(arr)
    } else {
        None
    }
}
