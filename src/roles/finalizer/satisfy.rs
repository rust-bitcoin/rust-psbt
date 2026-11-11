// SPDX-License-Identifier: CC0-1.0

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::bitcoin::hashes::{hash160, sha256d, Hash};
use crate::bitcoin::key::XOnlyPublicKey;
use crate::bitcoin::taproot::{self, ControlBlock, LeafVersion, TapLeafHash};
use crate::bitcoin::{absolute, ecdsa, relative, ScriptBuf, Sequence};
use crate::map::input::Input;
use crate::miniscript::{MiniscriptKey, Preimage32, Satisfier, SigType, ToPublicKey};

/// Provides signatures, preimages, and lock-time information from a PSBT input
/// to the miniscript [`Satisfier`] trait.
///
/// Used by the [`Finalizer`](super::Finalizer) to determine whether the spending
/// conditions of an input can be satisfied and, if so, to produce the satisfaction
/// witness and script sig.
pub(crate) struct InputSatisfier<'a> {
    /// The PSBT input whose signing material is exposed.
    pub(crate) input: &'a Input,
    /// The transaction lock time as resolved from all inputs per [BIP-370].
    ///
    /// Used by [`check_after`](Self::check_after) to evaluate `OP_CHECKLOCKTIMEVERIFY`
    /// conditions.
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>
    pub(crate) lock_time: absolute::LockTime,
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

    fn check_after(&self, n: absolute::LockTime) -> bool {
        // Sequence defaults to MAX if not set.
        self.input.sequence.unwrap_or(Sequence::MAX).enables_absolute_lock_time()
            && n.is_implied_by(self.lock_time)
    }

    fn check_older(&self, n: relative::LockTime) -> bool {
        // Sequence defaults to MAX if not set.
        match relative::LockTime::from_sequence(self.input.sequence.unwrap_or(Sequence::MAX)) {
            Err(_) => false,
            Ok(lock_time) => n.is_implied_by(lock_time),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::{self, absolute, OutPoint, Sequence};
    use crate::map::input::Input;

    type Pk = bitcoin::PublicKey;

    fn assert_check_older(expected: bool, sequence: Option<Sequence>, required_height: u16) {
        let mut input = Input::new(&OutPoint::null());
        input.sequence = sequence;
        let sat = InputSatisfier { input: &input, lock_time: absolute::LockTime::ZERO };
        assert_eq!(
            expected,
            <InputSatisfier as Satisfier<Pk>>::check_older(
                &sat,
                bitcoin::relative::LockTime::from_height(required_height),
            ),
        );
    }

    #[test]
    fn check_older_rejects_disabled_csv() {
        // An omitted/max sequence disables CSV, check_older must return false.
        assert_check_older(false, None, 10);
    }

    #[test]
    fn check_older_rejects_insufficient_sequence() {
        // CSV is enabled but the sequence is less than required.
        assert_check_older(false, Some(Sequence::from_consensus(10)), 100);
    }

    #[test]
    fn check_older_accepts_sufficient_sequence() {
        // CSV is enabled and the sequence meets the required lock time.
        assert_check_older(true, Some(Sequence::from_consensus(10)), 10);
    }
}
