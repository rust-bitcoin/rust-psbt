// SPDX-License-Identifier: CC0-1.0

//! The BIP-370 Signer role.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::fmt;
use alloc::vec::Vec;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use bitcoin::bip32::{self, KeySource, Xpriv};
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{Message, Secp256k1, Signing};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache};
use bitcoin::{
    ecdsa, taproot, PrivateKey, PublicKey, ScriptBuf, TapLeafHash, TapSighashType, Transaction,
    TxOut, Txid, XOnlyPublicKey,
};

use crate::error::{write_err, DetermineLockTimeError};
use crate::psbt::Psbt;
use crate::{OutputType, PsbtSighashType, SignError};

/// Implements the BIP-370 Signer role.
///
/// A [`Signer`] owns the [`Psbt`] for a single signing session and an internal [`SighashCache`] built
/// from the unsigned transaction at construction.
///
/// Because no `&mut self` method mutates the tx-defining fields of the [`Psbt`], the cached
/// transaction stays valid for the lifetime of the [`Signer`]; the cache is reused across signing
/// calls so the shared sighash intermediates are computed once.
///
/// The session is split into two phases. [`Signer::session`] lends the [`Psbt`] and the cache to a
/// [`SigningSession`] for the duration of a closure; the session creates [`SignableInput`]s that
/// are bound to it, so a signable input can never be used by (or escape) any other session.
///
/// The session produces signatures without writing them; [`Signer::apply`] writes them afterwards,
/// once the session closure and its signable inputs are dropped.
#[derive(Debug)]
pub struct Signer {
    psbt: Psbt,
    cache: SighashCache<Transaction>,
}

impl Signer {
    /// Creates a `Signer` for a single signing session, building the internal [`SighashCache`] from
    /// the unsigned transaction. Fails if the [`Psbt`]'s lock time cannot be determined.
    pub fn new(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let cache = SighashCache::new(psbt.unsigned_tx()?);
        Ok(Self { psbt, cache })
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.psbt.id().expect("Signer guarantees lock time can be determined")
    }

    /// Creates an unsigned transaction from the inner [`Psbt`].
    pub fn unsigned_tx(&self) -> Transaction {
        self.psbt.unsigned_tx().expect("Signer guarantees lock time can be determined")
    }

    /// Returns a reference to the inner [`Psbt`].
    pub fn as_psbt(&self) -> &Psbt { &self.psbt }

    /// Lends the [`Psbt`] and sighash cache to a [`SigningSession`] for the frozen signing window.
    ///
    /// The session creates [`SignableInput`]s that are bound to it: a signable input can only be
    /// signed by the session that created it, and cannot outlive the closure. The session produces
    /// signatures without writing them; call [`Signer::apply`] afterwards to write the signatures
    /// into the [`Psbt`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use psbt_v2::{Count, Global, Input, Output, Psbt, Signer};
    /// # use psbt_v2::bitcoin::{absolute, transaction, Amount, Network, OutPoint, PrivateKey, ScriptBuf, Transaction, TxIn, TxOut};
    /// # use psbt_v2::bitcoin::secp256k1::{Secp256k1, SecretKey};
    /// # use std::collections::BTreeMap;
    /// # fn create_psbt() -> Psbt {
    /// #     let secp = Secp256k1::new();
    /// #     let key = PrivateKey::new(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Bitcoin);
    /// #     let pk = key.public_key(&secp);
    /// #     let prevout = TxOut {
    /// #         value: Amount::from_sat(1_000),
    /// #         script_pubkey: ScriptBuf::new_p2wpkh(&pk.wpubkey_hash().unwrap()),
    /// #     };
    /// #     let funding = Transaction {
    /// #         version: transaction::Version::TWO,
    /// #         lock_time: absolute::LockTime::ZERO,
    /// #         input: vec![TxIn::default()],
    /// #         output: vec![prevout.clone()],
    /// #     };
    /// #     let mut input = Input::new(&OutPoint { txid: funding.compute_txid(), vout: 0 });
    /// #     input.witness_utxo = Some(prevout.clone());
    /// #     input.non_witness_utxo = Some(funding);
    /// #     input.bip32_derivations.insert(pk, Default::default());
    /// #     Psbt {
    /// #         global: Global { input_count: Count::from(1), output_count: Count::from(1), ..Global::default() },
    /// #         inputs: vec![input],
    /// #         outputs: vec![Output::new(TxOut {
    /// #             value: Amount::from_sat(900),
    /// #             script_pubkey: ScriptBuf::new(),
    /// #         })],
    /// #     }
    /// # }
    /// # let psbt = create_psbt();
    /// let secp = Secp256k1::new();
    /// let key = PrivateKey::new(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Bitcoin);
    /// let keys = BTreeMap::from([(key.public_key(&secp), key)]);
    ///
    /// let mut signer = Signer::new(psbt).unwrap();
    /// let sigs = signer.session(|mut session| {
    ///     let input = session.signable_input(0).unwrap();
    ///     session.get_input_sigs(&input, &keys, &secp)
    /// });
    /// let psbt = signer.apply([sigs]).unwrap();
    /// assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    /// ```
    ///
    /// Signable inputs are bound to their issuing session and cannot escape it, so a signable input
    /// created from one PSBT can never be presented to a session built from a different PSBT.
    /// Returning one from the session closure is a type error.
    ///
    pub fn session<R>(&mut self, f: impl for<'a, 'id> FnOnce(SigningSession<'a, 'id>) -> R) -> R {
        f(SigningSession { psbt: &self.psbt, cache: &mut self.cache, id: PhantomData })
    }

    /// Writes signatures produced by a [`SigningSession`] into the [`Psbt`].
    ///
    /// Clears `PSBT_GLOBAL_TX_MODIFIABLE` for each input signed.
    ///
    /// Fails on the first entry whose index is out of bounds (only possible for signatures created
    /// for a different [`Psbt`]). Entries that produced no signatures are accepted and skipped.
    pub fn apply(mut self, sigs: impl IntoIterator<Item = InputSigs>) -> Result<Psbt, SignError> {
        for InputSigs { index, signatures } in sigs {
            let psbt_input = self.psbt.checked_input_mut(index)?;

            if signatures.is_empty() {
                continue;
            }

            match signatures {
                TypedSigs::Ecdsa(signatures) => {
                    // BIP-370: a signer must update PSBT_GLOBAL_TX_MODIFIABLE after signing inputs.
                    let sighash_ty = signatures
                        .first()
                        .expect("signatures emptiness checked above")
                        .1
                        .sighash_type;
                    for (pk, sig) in signatures {
                        psbt_input.partial_sigs.insert(pk, sig);
                    }

                    self.psbt.clear_tx_modifiable(PsbtSighashType::from(sighash_ty));
                }
                TypedSigs::Taproot(signatures) => {
                    // BIP-370: a signer must update PSBT_GLOBAL_TX_MODIFIABLE after signing inputs.
                    let sighash_ty = signatures
                        .first()
                        .expect("signatures emptiness checked above")
                        .1
                        .sighash_type;
                    for (tap_key_material, sig) in signatures {
                        match tap_key_material {
                            TapKeyMaterial::KeyPath(_) => {
                                let _ = psbt_input.tap_key_sig.insert(sig);
                            }
                            TapKeyMaterial::ScriptPath(key_material) => {
                                psbt_input.tap_script_sigs.insert(key_material, sig);
                            }
                        }
                    }

                    self.psbt.clear_tx_modifiable(PsbtSighashType::from(sighash_ty));
                }
            }
        }

        Ok(self.psbt)
    }

    /// Sets the PSBT_GLOBAL_TX_MODIFIABLE as required after signing an ECDSA input.
    ///
    /// > For PSBTv2s, a signer must update the PSBT_GLOBAL_TX_MODIFIABLE field after signing
    /// > inputs so that it accurately reflects the state of the PSBT.
    pub fn ecdsa_clear_tx_modifiable(&mut self, ty: EcdsaSighashType) {
        self.psbt.clear_tx_modifiable(PsbtSighashType::from(ty))
    }

    /// Returns the inner [`Psbt`].
    pub fn psbt(self) -> Psbt { self.psbt }
}

/// A frozen, shared view of a [`Signer`]'s [`Psbt`] and [`SighashCache`] for producing signatures.
///
/// While a [`SigningSession`] (or any [`SignableInput`] it created) is alive, the `Signer` is
/// immutably borrowed, so the `Psbt` cannot be mutated.
///
/// The session is bounded by an unforgeable lifetime `'id`: every [`SignableInput`] it creates
/// carries the "session id", so a signable input can only be signed by the session that created it, and
/// cannot outlive the session closure.
///
/// The [`SigningSession`] produces signatures without writing them; call [`Signer::apply`] to write them
/// into the `Psbt` after the session and its signable inputs are dropped.
pub struct SigningSession<'a, 'id> {
    psbt: &'a Psbt,
    /// The sighash cache the [`Signer`] is committed to.
    pub(crate) cache: &'a mut SighashCache<Transaction>,
    /// The unforgeable id [`Signer::session`] uses for this session alone.
    id: SessionId<'id>,
}

/// The taproot key material the signature is associated with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TapKeyMaterial {
    /// The signature was created for key path spending.
    KeyPath(XOnlyPublicKey),
    /// The signature was created for script path spending.
    ScriptPath((XOnlyPublicKey, TapLeafHash)),
}

/// The signatures, with the public key material associated with it, differentiated by algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypedSigs {
    /// ECDSA (legacy and segwit v0) inputs.
    Ecdsa(Vec<(PublicKey, ecdsa::Signature)>),
    /// Taproot inputs.
    Taproot(Vec<(TapKeyMaterial, taproot::Signature)>),
}

/// Signatures for one input, produced by the signing methods of a [`SigningSession`]
/// ([`SigningSession::get_input_sigs`], [`SigningSession::get_some`], [`SigningSession::get_all`])
/// and written into the [`Psbt`] by [`Signer::apply`].
///
/// An `InputSigs` can be empty: an input whose keys the key provider holds none of produces no
/// signatures (normal for partial/multisig signing flows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSigs {
    /// The input index these signatures are for.
    pub index: usize,
    /// The `(key material, signature)` pairs, one per key the key provider held for this input.
    pub signatures: TypedSigs,
}

impl TypedSigs {
    /// Returns `true` if there are no signatures.
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Returns the number of signatures produced. Can be zero.
    pub fn len(&self) -> usize {
        match &self {
            Self::Ecdsa(items) => items.len(),
            Self::Taproot(items) => items.len(),
        }
    }
}

impl InputSigs {
    /// Returns `true` if this input produced no signatures.
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Returns the number of signatures produced for this input. Can be zero.
    pub fn len(&self) -> usize { self.signatures.len() }
}

impl<'a, 'id> SigningSession<'a, 'id> {
    /// Strictly creates a [`SignableInput`] for `index` from the borrowed [`Psbt`].
    ///
    /// The signable input is bound to this session; see the [`SignableInput`] docs for the
    /// checks that are run.
    ///
    /// Taproot inputs that are not ANYONECANPAY are rejected with
    /// [`SignError::AllPrevoutsRequired`]: a taproot sighash commits to every input's
    /// prevout, so taproot inputs can only be created for a complete input set (see
    /// [`Self::signable_inputs`]) and can only be signed through [`Self::get_all`].
    pub fn signable_input(&self, index: usize) -> Result<SignableInput<'id>, SignError> {
        let signable_input = SignableInput::verify(self.psbt, index)?;

        if matches!(signable_input.output_type, OutputType::Tr)
            && !signable_input.sighash_type().is_anyone_can_pay()
        {
            return Err(SignError::AllPrevoutsRequired);
        }

        Ok(signable_input)
    }

    /// Creates a [`SignableInput`] for `index` against the [`Psbt`], without verifying data.
    ///
    /// This method assumes the caller verified data offline.
    ///
    /// Taproot inputs are rejected with [`SignError::AllPrevoutsRequired`]: a taproot sighash
    /// commits to every input's prevout, so taproot inputs can only be created for a complete input
    /// set (see [`Self::assume_checked_inputs`]) and can only be signed through [`Self::get_all`].
    pub fn assume_checked_input(&self, index: usize) -> Result<SignableInput<'id>, SignError> {
        let signable_input = SignableInput::assume_checked(self.psbt, index)?;

        if matches!(signable_input.output_type, OutputType::Tr)
            && !signable_input.sighash_type().is_anyone_can_pay()
        {
            return Err(SignError::AllPrevoutsRequired);
        }

        Ok(signable_input)
    }

    /// Strictly creates the complete set of [`SignableInput`]s for every input.
    ///
    /// All-or-nothing: if any input fails its checks, returns the per-input errors and no signable
    /// inputs.
    /// inputs. The returned [`AllSignableInputs`] proves every input was validated, which is what
    /// makes non-ANYONECANPAY taproot inputs signable through [`Self::get_all`].
    pub fn signable_inputs(
        &self,
    ) -> Result<AllSignableInputs<'a, 'id>, BTreeMap<usize, SignError>> {
        AllSignableInputs::new(self.psbt, SignableInput::verify)
    }

    /// Creates the complete set of [`SignableInput`]s for every input, without verifying data.
    ///
    /// This method assumes the caller verified the inputs' data offline. All-or-nothing: if any
    /// input is malformed, returns the per-input errors and no signable inputs. The returned
    /// [`AllSignableInputs`] proves every input was checked, which is what makes non-ANYONECANPAY
    /// taproot inputs signable through [`Self::get_all`].
    pub fn assume_checked_inputs(
        &self,
    ) -> Result<AllSignableInputs<'a, 'id>, BTreeMap<usize, SignError>> {
        AllSignableInputs::new(self.psbt, SignableInput::assume_checked)
    }

    /// Produces the signatures for a single input without writing them.
    ///
    /// Signs with every key `k` yields for this input's `bip32_derivations`; inputs for which `k`
    /// holds no key are silently skipped (normal for partial/multisig signing flows).
    ///
    /// The signable input must have been created by this session (enforced by the type system), so
    /// its sighash policy, script, and amount always agree with this session's [`Psbt`]. A signable
    /// input created by [`Self::signable_input`] or [`Self::assume_checked_input`] cannot ever be a
    /// non-ANYONECANPAY taproot input, these inputs only exist inside an [`AllSignableInputs`], and
    /// are signed through [`Self::get_all`]. An ANYONECANPAY taproot input commits only to its own
    /// prevout and is signed here.
    ///
    /// This method is infallible, all input-validation ran when the signable input was created.
    pub fn get_input_sigs<C, K>(
        &mut self,
        input: &SignableInput<'id>,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> InputSigs
    where
        C: Signing,
        K: GetKey,
    {
        self.input_sigs(input, &[], k, secp)
    }

    /// Produces the signatures for a subset of standalone signable inputs without writing them.
    ///
    /// Signs each input with every key `k` yields for it; inputs for which `k` holds no key are
    /// silently skipped (normal for partial/multisig signing flows).
    ///
    /// The inputs must have been created by this session (enforced by the type system) and cannot
    /// ever be a non-ANYONECANPAY taproot input, these inputs only exist inside an
    /// [`AllSignableInputs`] and are signed through [`Self::get_all`], so no completeness proof is
    /// needed: each standalone sighash commits only to its own input's prevout.
    ///
    /// This method is infallible, all input-validation ran when the signable inputs were created.
    pub fn get_some<C, K>(
        &mut self,
        inputs: &[SignableInput<'id>],
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Vec<InputSigs>
    where
        C: Signing,
        K: GetKey,
    {
        inputs.iter().map(|input| self.input_sigs(input, &[], k, secp)).collect()
    }

    /// Produces the signatures for every signable input of a complete set without writing them.
    ///
    /// This is the only method that signs non-ANYONECANPAY taproot inputs: an [`AllSignableInputs`]
    /// proves every input of the [`Psbt`] was validated, so the complete prevout slice the taproot
    /// sighash commits to was collected once at creation.
    ///
    /// This method is infallible, all input-validation ran when the signable inputs were created.
    pub fn get_all<C, K>(
        &mut self,
        inputs: &AllSignableInputs<'a, 'id>,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Vec<InputSigs>
    where
        C: Signing,
        K: GetKey,
    {
        inputs
            .inputs
            .iter()
            .map(|input| self.input_sigs(input, &inputs.prevouts, k, secp))
            .collect()
    }

    /// Produces the signatures for one signable input without writing them.
    ///
    /// `all_prevouts` must be the complete prevout slice for non-ANYONECANPAY taproot inputs (the
    /// `prevouts` field of [`AllSignableInputs`]); it is unused otherwise.
    fn input_sigs<C, K>(
        &mut self,
        input: &SignableInput<'id>,
        all_prevouts: &[&'a TxOut],
        k: &K,
        secp: &Secp256k1<C>,
    ) -> InputSigs
    where
        C: Signing,
        K: GetKey,
    {
        match input.output_type() {
            OutputType::Tr => self.taproot_signatures(input, all_prevouts, k, secp),
            _ => self.ecdsa_signatures(input, k, secp),
        }
    }

    fn taproot_signatures<C, K>(
        &mut self,
        input: &SignableInput<'id>,
        all_prevouts: &[&'a TxOut],
        k: &K,
        secp: &Secp256k1<C>,
    ) -> InputSigs
    where
        C: Signing,
        K: GetKey,
    {
        let mut signatures = Vec::new();
        let psbt_input = self
            .psbt
            .checked_input(input.index)
            .expect("the index is already checked by SignableInput");
        for (&xonly, (leaf_hashes, key_source)) in psbt_input.tap_key_origins.iter() {
            let sk = if let Ok(Some(secret_key)) =
                k.get_key(&KeyRequest::Bip32(key_source.clone()), secp)
            {
                secret_key
            } else if let Ok(Some(sk)) = k.get_key(&KeyRequest::XOnlyPubkey(xonly), secp) {
                sk
            } else {
                continue;
            };

            // Considering the responsibility of the PSBT's finalizer to extract valid signatures,
            // the goal of this algorithm is to provide signatures to the best of our ability:
            // 1) If the conditions for key path spend are met, proceed to provide the signature for key path spend
            // 2) If the conditions for script path spend are met, proceed to provide the signature for script path spend

            // key path spend
            if let Some(internal_key) = psbt_input.tap_internal_key {
                // BIP-0371: The internal key does not have leaf hashes, so can be indicated with a hashes len of 0.

                // Based on input.tap_internal_key.is_some() alone, it is not sufficient to determine whether it is a key path spend.
                // According to BIP-0371, we also need to consider the condition leaf_hashes.is_empty() for a more accurate determination.
                if internal_key == xonly
                    && leaf_hashes.is_empty()
                    && psbt_input.tap_key_sig.is_none()
                {
                    let secp = &Secp256k1::new();
                    let key_pair = Keypair::from_secret_key(secp, &sk.inner)
                        .tap_tweak(secp, psbt_input.tap_merkle_root)
                        .to_keypair();

                    let (msg, sighash_type) = self.taproot_sighash(input, all_prevouts, None);
                    #[cfg(feature = "rand")]
                    let signature = secp.sign_schnorr(&msg, &key_pair);
                    #[cfg(not(feature = "rand"))]
                    let signature = secp.sign_schnorr_no_aux_rand(&msg, &key_pair);

                    let sig = taproot::Signature { signature, sighash_type };

                    signatures.push((TapKeyMaterial::KeyPath(internal_key), sig));
                }
            }

            // script path spend
            if let Some((leaf_hashes, _)) = psbt_input.tap_key_origins.get(&xonly) {
                let leaf_hashes = leaf_hashes
                    .iter()
                    .filter(|lh| !psbt_input.tap_script_sigs.contains_key(&(xonly, **lh)))
                    .cloned()
                    .collect::<Vec<_>>();

                if !leaf_hashes.is_empty() {
                    let key_pair = Keypair::from_secret_key(secp, &sk.inner);

                    for lh in leaf_hashes {
                        let (msg, sighash_type) =
                            self.taproot_sighash(input, all_prevouts, Some(lh));

                        #[cfg(feature = "rand")]
                        let signature = secp.sign_schnorr(&msg, &key_pair);
                        #[cfg(not(feature = "rand"))]
                        let signature = secp.sign_schnorr_no_aux_rand(&msg, &key_pair);

                        let sig = taproot::Signature { signature, sighash_type };
                        signatures.push((TapKeyMaterial::ScriptPath((xonly, lh)), sig));
                    }
                }
            }
        }
        InputSigs { index: input.index, signatures: TypedSigs::Taproot(signatures) }
    }

    fn ecdsa_signatures<C, K>(
        &mut self,
        input: &SignableInput<'id>,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> InputSigs
    where
        C: Signing,
        K: GetKey,
    {
        let mut signatures = Vec::new();
        let psbt_input = self
            .psbt
            .checked_input(input.index)
            .expect("the index is already checked by SignableInput");
        let (msg, sighash_type) = self.ecdsa_sighash(input);
        for (pk, key_source) in psbt_input.bip32_derivations.iter() {
            // Try BIP-32 derivation first, then raw pubkey. Key-provider errors are swallowed
            // per-key; an input we hold no key for is simply skipped (partial signing is a normal
            // multisig flow).
            let sk = if let Ok(Some(sk)) = k.get_key(&KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) = k.get_key(&KeyRequest::Pubkey(*pk), secp) {
                sk
            } else {
                continue;
            };

            let sig =
                ecdsa::Signature { signature: secp.sign_ecdsa(&msg, &sk.inner), sighash_type };

            let pk = sk.public_key(secp);
            signatures.push((pk, sig));
        }
        InputSigs { index: input.index, signatures: TypedSigs::Ecdsa(signatures) }
    }

    fn taproot_sighash(
        &mut self,
        input: &SignableInput<'id>,
        all_prevouts: &[&'a TxOut],
        leaf_hash: Option<TapLeafHash>,
    ) -> (Message, TapSighashType) {
        let tap_ty = input
            .sighash_ty
            .taproot_hash_ty()
            .expect("sighash type validated when the signable input was created");
        let prev_outs = if matches!(
            tap_ty,
            TapSighashType::AllPlusAnyoneCanPay
                | TapSighashType::NonePlusAnyoneCanPay
                | TapSighashType::SinglePlusAnyoneCanPay
        ) {
            Prevouts::One(input.index, &input.prevout)
        } else {
            Prevouts::All(all_prevouts)
        };

        let sighash = if let Some(leaf_hash) = leaf_hash {
            self.cache
                .taproot_script_spend_signature_hash(input.index, &prev_outs, leaf_hash, tap_ty)
                .expect("input index in bounds (checked above)")
        } else {
            self.cache
                .taproot_key_spend_signature_hash(input.index, &prev_outs, tap_ty)
                .expect("prevout slice is complete, input index in bounds (checked above)")
        };
        (Message::from(sighash), tap_ty)
    }

    /// Computes the sighash a new signature over `input` commits to.
    ///
    /// The [`Sighash`] variant is determined by the input's [`OutputType`].
    ///
    /// `all_prevouts` must be the complete prevout slice (the `prevouts` field of
    /// [`AllSignableInputs`]) when `input` is a non-ANYONECANPAY taproot input, whose sighash
    /// commits to every input's prevout; the slice is built once per complete set and shared by
    /// all its taproot inputs.
    ///
    /// This method is infallible: the [`SighashCache`] and the [`SignableInput`] are unchangeable,
    /// so the invariants ensured when the signable input was created stay true for the whole
    /// signing session.
    fn ecdsa_sighash(&mut self, input: &SignableInput<'id>) -> (Message, EcdsaSighashType) {
        let ecdsa_ty = input
            .sighash_ty
            .ecdsa_hash_ty()
            .expect("sighash type validated when the signable input was created");
        let sighash = match input.output_type {
            OutputType::Bare | OutputType::Sh => Message::from(
                self.cache
                    .legacy_signature_hash(input.index, &input.script_code, ecdsa_ty.to_u32())
                    .expect("input index in bounds (checked above)"),
            ),
            OutputType::Wpkh | OutputType::ShWpkh => Message::from(
                self.cache
                    .p2wpkh_signature_hash(
                        input.index,
                        &input.script_code,
                        input.prevout.value,
                        ecdsa_ty,
                    )
                    .expect("standard sighash type validated at creation"),
            ),
            OutputType::Wsh | OutputType::ShWsh => Message::from(
                self.cache
                    .p2wsh_signature_hash(
                        input.index,
                        &input.script_code,
                        input.prevout.value,
                        ecdsa_ty,
                    )
                    .expect("standard sighash type validated at creation"),
            ),
            OutputType::Tr => unreachable!("Tr handled in the Schnorr arm above"),
        };
        (sighash, ecdsa_ty)
    }
}

/// Returns a session body that strictly verifies and signs the single input at `index` with
/// every key `keys` yields for it.
///
/// Binds `keys` and `secp` now, runs inside a [`Signer::session`] closure later:
///
/// ```ignore
/// let sigs = signer.session(sign_input(0, &keys, &secp))?;
/// let psbt = signer.apply([sigs?])?;
/// ```
///
/// The input is strictly verified first; see [`SignableInput`] for the checks. For the
/// caller-attested path use [`sign_input_unchecked`].
pub fn sign_input<'k, K, C>(
    index: usize,
    keys: &'k K,
    secp: &'k Secp256k1<C>,
) -> impl for<'a, 'id> FnOnce(SigningSession<'a, 'id>) -> Result<InputSigs, SignError> + 'k
where
    K: GetKey,
    C: Signing,
{
    move |mut session| {
        let input = session.signable_input(index)?;
        Ok(session.get_input_sigs(&input, keys, secp))
    }
}

/// Returns a session body that strictly verifies every input and signs each one with every key
/// `keys` yields for it.
///
/// All-or-nothing: if any input fails its checks, the per-input errors are returned and nothing
/// is signed. See [`sign_input`] for binding a single input and [`sign_all_unchecked`] for the
/// caller-attested path.
pub fn sign_all<'k, K, C>(
    keys: &'k K,
    secp: &'k Secp256k1<C>,
) -> impl for<'a, 'id> FnOnce(
    SigningSession<'a, 'id>,
) -> Result<Vec<InputSigs>, BTreeMap<usize, SignError>>
       + 'k
where
    K: GetKey,
    C: Signing,
{
    move |mut session| {
        let inputs = session.signable_inputs()?;
        Ok(session.get_all(&inputs, keys, secp))
    }
}

/// Returns a session body that signs the single input at `index` with every key `keys` yields
/// for it, trusting the caller to have verified the input's funding UTXO data out-of-band.
///
/// Signing with an unattested amount enables the fee-inflation attack: a crafted `witness_utxo`
/// can overstate an input's value, so the resulting transaction overpays the fee. For the
/// strictly verified path use [`sign_input`].
pub fn sign_input_unchecked<'k, K, C>(
    index: usize,
    keys: &'k K,
    secp: &'k Secp256k1<C>,
) -> impl for<'a, 'id> FnOnce(SigningSession<'a, 'id>) -> Result<InputSigs, SignError> + 'k
where
    K: GetKey,
    C: Signing,
{
    move |mut session| {
        let input = session.assume_checked_input(index)?;
        Ok(session.get_input_sigs(&input, keys, secp))
    }
}

/// Returns a session body that signs every input with every key `keys` yields for it, trusting
/// the caller to have verified the inputs' funding UTXO data out-of-band.
///
/// All-or-nothing: if any input is malformed, the per-input errors are returned and nothing is
/// signed. Signing with an unattested amount enables the fee-inflation attack: a crafted
/// `witness_utxo` can overstate an input's value, so the resulting transaction overpays the fee.
/// For the strictly verified path use [`sign_all`].
pub fn sign_all_unchecked<'k, K, C>(
    keys: &'k K,
    secp: &'k Secp256k1<C>,
) -> impl for<'a, 'id> FnOnce(
    SigningSession<'a, 'id>,
) -> Result<Vec<InputSigs>, BTreeMap<usize, SignError>>
       + 'k
where
    K: GetKey,
    C: Signing,
{
    move |mut session| {
        let inputs = session.assume_checked_inputs()?;
        Ok(session.get_all(&inputs, keys, secp))
    }
}

/// An unforgeable id binding a [`SignableInput`] to the [`SigningSession`] that created it.
///
/// `'id` is a higher-ranked lifetime created by [`Signer::session`] on each call. The fn-pointer
/// `PhantomData` makes it invariant, so a identified value can never be coerced to a different
/// identifier: only the session that created a signable input can sign with it.
type SessionId<'id> = PhantomData<fn(&'id ()) -> &'id ()>;

/// Evidence that an input is fit to sign.
///
/// Produced only by a [`SigningSession`]: strictly, as a standalone input
/// ([`SigningSession::signable_input`], [`SigningSession::assume_checked_input`]), or as part of a
/// complete set ([`SigningSession::signable_inputs`], [`SigningSession::assume_checked_inputs`]).
///
/// A signable input created standalone is never non-ANYONECANPAY taproot, it is rejected with
/// [`SignError::AllPrevoutsRequired`] at creation, because a non-ANYONECANPAY taproot sighash
/// commits to every input's prevout and only a complete input set ([`AllSignableInputs`])
/// guarantees they are all present. Non-ANYONECANPAY taproot inputs therefore only exist inside an
/// [`AllSignableInputs`] and are signed only through [`SigningSession::get_all`].
///
/// A signable input is identified by the session that created it and is a snapshot of the input's
/// verified signing data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignableInput<'id> {
    /// The input index this validated input refers to.
    index: usize,
    /// The output type of this input's spent output.
    output_type: OutputType,
    /// The verified spent output committed to by the sighash.
    prevout: TxOut,
    /// The script code the sighash engine consumes.
    script_code: ScriptBuf,
    /// The sighash type a new signature commits to.
    sighash_ty: PsbtSighashType,
    /// The id of the [`SigningSession`] that created this signable input.
    session_id: SessionId<'id>,
}

/// The complete set of a [`Psbt`]'s signable inputs, created by
/// [`SigningSession::signable_inputs`] or [`SigningSession::assume_checked_inputs`].
///
/// Completeness holds by construction: the set is built by iterating every input of the [`Psbt`],
/// all-or-nothing, so holding one proves every input was validated , and, since a non-ANYONECANPAY
/// taproot input can only be created this way, that every input's funding UTXO is present.
///
/// The set carries the complete prevout slice the non-ANYONECANPAY taproot sighash commits to,
/// collected once at creation, so [`SigningSession::get_all`] signs any number of non-ANYONECANPAY
/// taproot inputs with a single prevout collection instead of one per input.
///
/// The set is opaque: its elements cannot be extracted, so a non-ANYONECANPAY taproot input can
/// never reach [`SigningSession::get_input_sigs`], non-ANYONECANPAY taproot inputs are signed only
/// through [`SigningSession::get_all`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AllSignableInputs<'a, 'id> {
    inputs: Vec<SignableInput<'id>>,
    prevouts: Vec<&'a TxOut>,
}

impl<'id> SignableInput<'id> {
    /// Runs the full BIP-174 signer checks and returns evidence of success.
    ///
    /// This is the untrusted path: in addition to the structural checks of
    /// [`Self::assume_checked`], it verifies the funding UTXO against a full transaction (rejecting
    /// witness-only non-P2TR inputs), checks that the redeem/witness scripts match the
    /// scriptPubKey, that the declared taproot key material produces the prevout's output key, and
    /// that any existing signatures' sighash types agree with the declared one.
    fn verify(psbt: &Psbt, index: usize) -> Result<Self, SignError> {
        let input = Self::check_data(psbt, index)?;

        // Strict funding UTXO: a witness-only UTXO cannot be verified for a non-P2TR input.
        let psbt_input = psbt.checked_input(index).map_err(SignError::IndexOutOfBounds)?;
        psbt_input.funding_utxo_untrusted().map_err(SignError::FundingUtxo)?;

        // Redeem/witness script matching against the scriptPubKey.
        let spk = &input.prevout.script_pubkey;
        if let Some(ref redeem_script) = psbt_input.redeem_script {
            if ScriptBuf::new_p2sh(&redeem_script.script_hash()) != *spk {
                return Err(SignError::RedeemScriptMismatch);
            }
        }
        if let Some(ref witness_script) = psbt_input.witness_script {
            match input.output_type {
                OutputType::Wsh if ScriptBuf::new_p2wsh(&witness_script.wscript_hash()) != *spk => {
                    return Err(SignError::WitnessScriptMismatchWsh);
                }
                OutputType::ShWsh =>
                    if let Some(ref redeem_script) = psbt_input.redeem_script {
                        if ScriptBuf::new_p2wsh(&witness_script.wscript_hash()) != *redeem_script
                            || ScriptBuf::new_p2sh(&redeem_script.script_hash()) != *spk
                        {
                            return Err(SignError::WitnessScriptMismatchShWsh);
                        }
                    },
                _ => (),
            }
        }

        // The declared taproot key material must produce the output key committed to by the
        // prevout's scriptPubKey: a mismatching internal key would elicit signatures that do not
        // verify on-chain. Script-path-only inputs (no internal key declared) cannot be checked.
        if matches!(input.output_type, OutputType::Tr) {
            if let Some(internal_key) = psbt_input.tap_internal_key {
                let secp = Secp256k1::verification_only();
                let output_key =
                    ScriptBuf::new_p2tr(&secp, internal_key, psbt_input.tap_merkle_root);
                if output_key != *spk {
                    return Err(SignError::TaprootInternalKeyMismatch);
                }
            }
        }

        // Existing signatures' sighash types must agree with the expected one.
        let mismatch = |sighash: PsbtSighashType| sighash != input.sighash_ty;
        let has_mismatch = psbt_input
            .tap_key_sig
            .is_some_and(|sig| mismatch(PsbtSighashType::from(sig.sighash_type)))
            || psbt_input
                .tap_script_sigs
                .values()
                .any(|sig| mismatch(PsbtSighashType::from(sig.sighash_type)))
            || psbt_input
                .partial_sigs
                .values()
                .any(|sig| mismatch(PsbtSighashType::from(sig.sighash_type)));
        if has_mismatch {
            return Err(SignError::SighashMismatch);
        }

        Ok(input)
    }

    /// Creates a new [`SignableInput`] trusting the caller to have verified the funding UTXO data
    /// out-of-band.
    ///
    /// Signing with an unattested amount enables the fee-inflation attack: a crafted `witness_utxo`
    /// can overstate an input's value, so the resulting transaction overpays the fee.
    fn assume_checked(psbt: &Psbt, index: usize) -> Result<Self, SignError> {
        Self::check_data(psbt, index)
    }

    /// Structural integrity: the input is well-formed enough to sign.
    ///
    /// - index is within bounds.
    /// - the funding UTXO is present and structurally consistent.
    /// - the script code is present.
    /// - the declared sighash type is valid.
    /// - SIGHASH_SINGLE bounds hold.
    ///
    /// Shared by both [`Self::verify`] and [`Self::assume_checked`]; runs no consistency checks
    /// against the scriptPubKey or existing signatures.
    fn check_data(psbt: &Psbt, index: usize) -> Result<Self, SignError> {
        let input = psbt.checked_input(index).map_err(SignError::IndexOutOfBounds)?;
        let prevout = input.funding_utxo().map_err(SignError::FundingUtxo)?.clone();
        // `output_type` re-derives the funding UTXO, which cannot fail here: any funding error
        // already surfaced above. Only the scriptPubKey classification can fail.
        let output_type = input.output_type().map_err(|_| SignError::UnknownOutputType)?;

        // A witness UTXO cannot back a legacy (non-witness) signature.
        if input.witness_utxo.is_some() && matches!(output_type, OutputType::Bare) {
            return Err(SignError::NonWitnessSig);
        }

        // The sighash type a new signature should use: the declared type, or the per-output-type
        // default (Default for taproot, ALL otherwise) when none is declared.
        let sighash_ty = match input.sighash_type {
            None if matches!(output_type, OutputType::Tr) =>
                PsbtSighashType::from(TapSighashType::Default),
            None => PsbtSighashType::ALL,
            Some(ty) => ty,
        };

        // SIGHASH_SINGLE bounds: a missing output makes the legacy sighash sign the constant hash 1.
        if sighash_ty.is_single() && index >= psbt.outputs.len() {
            return Err(SignError::SighashSingleMissingOutput);
        }

        // The script code the sighash engine consumes must be present.
        let script_code = match output_type {
            OutputType::Bare | OutputType::Wpkh => prevout.script_pubkey.clone(),
            OutputType::Sh | OutputType::ShWpkh =>
                input.redeem_script.clone().ok_or(SignError::MissingRedeemScript)?,
            OutputType::Wsh | OutputType::ShWsh =>
                input.witness_script.clone().ok_or(SignError::MissingWitnessScript)?,
            OutputType::Tr => ScriptBuf::new(),
        };

        // The declared sighash type must be valid for the input's algorithm.
        match output_type {
            OutputType::Tr => {
                input.taproot_hash_ty().map_err(|_| SignError::InvalidSighashType)?;
            }
            _ => {
                input.ecdsa_hash_ty().map_err(|_| SignError::InvalidSighashType)?;
            }
        }

        Ok(Self { index, output_type, prevout, script_code, sighash_ty, session_id: PhantomData })
    }

    /// The input index this evidence refers to.
    pub fn index(&self) -> usize { self.index }

    /// The input's prevout script type, which selects the signing algorithm and the sighash engine path.
    pub fn output_type(&self) -> OutputType { self.output_type }

    /// The sighash type a new signature over this input will commit to.
    ///
    /// The declared type, or the per-output-type default (Default for taproot, ALL otherwise) when
    /// none is declared.
    pub fn sighash_type(&self) -> PsbtSighashType { self.sighash_ty }
}

impl<'a, 'id> AllSignableInputs<'a, 'id> {
    /// Builds the complete set from already-validated inputs, collecting their prevouts once.
    fn new(
        psbt: &'a Psbt,
        check: impl Fn(&Psbt, usize) -> Result<SignableInput<'id>, SignError>,
    ) -> Result<Self, BTreeMap<usize, SignError>> {
        let mut signable_inputs = Vec::new();
        let mut prevouts = Vec::new();
        let mut errors: BTreeMap<usize, SignError> = BTreeMap::new();
        for index in 0..usize::from(psbt.global.input_count) {
            match check(psbt, index) {
                Ok(input) => {
                    signable_inputs.push(input);
                    prevouts.push(
                        psbt.checked_input(index)
                            .expect("input inside bounds, checked above")
                            .funding_utxo()
                            .expect("input inside bounds, checked above"),
                    );
                }
                Err(e) => {
                    errors.insert(index, e);
                }
            }
        }

        if errors.is_empty() {
            Ok(Self { inputs: signable_inputs, prevouts })
        } else {
            Err(errors)
        }
    }

    /// The number of signable inputs in the set.
    pub fn len(&self) -> usize { self.inputs.len() }

    /// Whether the set has no signable inputs.
    pub fn is_empty(&self) -> bool { self.inputs.is_empty() }
}

/// Data required to call [`GetKey`] to get the private key to sign an input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRequest {
    /// Request a private key using the associated public key.
    Pubkey(PublicKey),
    /// Request a private key using BIP-32 fingerprint and derivation path.
    Bip32(KeySource),
    /// Request a private key using the associated x-only public key.
    XOnlyPubkey(XOnlyPublicKey),
}

/// Trait to get a private key from a key request, key is then used to sign an input.
pub trait GetKey {
    /// An error occurred while getting the key.
    type Error: core::fmt::Debug;

    /// Attempts to get the private key for `key_request`.
    ///
    /// # Returns
    /// - `Some(key)` if the key is found.
    /// - `None` if the key was not found but no error was encountered.
    /// - `Err` if an error was encountered while looking for the key.
    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error>;
}

impl GetKey for Xpriv {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) | KeyRequest::XOnlyPubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                let key = if self.fingerprint(secp) == *fingerprint {
                    let k = self.derive_priv(secp, path)?;
                    Some(k.to_priv())
                } else if self.parent_fingerprint == *fingerprint
                    && !path.is_empty()
                    && path[0] == self.child_number
                {
                    let k = self.derive_priv(secp, &path[1..].iter().as_slice())?;
                    Some(k.to_priv())
                } else {
                    None
                };
                Ok(key)
            }
        }
    }
}

/// Map of input index -> pubkey associated with secret key used to create signature for that input.
pub type SigningKeys = BTreeMap<usize, Vec<PublicKey>>;

/// Map of input index -> the error encountered while attempting to sign that input.
pub type SigningErrors = BTreeMap<usize, SignError>;

#[rustfmt::skip]
macro_rules! impl_get_key_for_set {
    ($set:ident) => {

impl GetKey for $set<Xpriv> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>
    ) -> Result<Option<PrivateKey>, Self::Error> {
        // OK to stop at the first error because Xpriv::get_key() can only fail
        // if this isn't a KeyRequest::Bip32, which would fail for all Xprivs.
        self.iter()
            .find_map(|xpriv| xpriv.get_key(key_request, secp).transpose())
            .transpose()
    }
}}}

impl_get_key_for_set!(Vec);
impl_get_key_for_set!(BTreeSet);
#[cfg(feature = "std")]
impl_get_key_for_set!(HashSet);

#[rustfmt::skip]
macro_rules! impl_get_key_for_pubkey_map {
    ($map:ident) => {

impl GetKey for $map<PublicKey, PrivateKey> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        _secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        use $crate::bitcoin::secp256k1;

        match key_request {
            KeyRequest::Pubkey(pk) => Ok(self.get(&pk).cloned()),
            KeyRequest::XOnlyPubkey(xonly) => {
                let pubkey_even = xonly.public_key(secp256k1::Parity::Even).into();
                let key = self.get(&pubkey_even).cloned();

                if key.is_some() {
                    return Ok(key);
                }

                let pubkey_odd = xonly.public_key(secp256k1::Parity::Odd).into();
                if let Some(priv_key) = self.get(&pubkey_odd) {
                    let negated_priv_key  = priv_key.negate();
                    return Ok(Some(negated_priv_key));
                }

                Ok(None)
            },
            KeyRequest::Bip32(_) => Err(GetKeyError::NotSupported),
        }
    }
}}}
impl_get_key_for_pubkey_map!(BTreeMap);
#[cfg(feature = "std")]
impl_get_key_for_pubkey_map!(HashMap);

#[rustfmt::skip]
macro_rules! impl_get_key_for_xonly_map {
    ($map:ident) => {

impl GetKey for $map<XOnlyPublicKey, PrivateKey> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: &KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::XOnlyPubkey(xonly) => Ok(self.get(xonly).cloned()),
            KeyRequest::Pubkey(pk) => {
                let (xonly, parity) = pk.inner.x_only_public_key();

                if let Some(mut priv_key) = self.get(&xonly).cloned() {
                    let computed_pk = priv_key.public_key(secp);
                    let (_, computed_parity) = computed_pk.inner.x_only_public_key();

                    if computed_parity != parity {
                        priv_key = priv_key.negate();
                    }

                    return Ok(Some(priv_key));
                }

                Ok(None)
            },
            KeyRequest::Bip32(_) => Err(GetKeyError::NotSupported),
        }
    }
}}}
impl_get_key_for_xonly_map!(BTreeMap);
#[cfg(feature = "std")]
impl_get_key_for_xonly_map!(HashMap);

/// Errors when getting a key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetKeyError {
    /// A bip32 error.
    Bip32(bip32::Error),
    /// The GetKey operation is not supported for this key request.
    NotSupported,
}

impl fmt::Display for GetKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Bip32(ref e) => write_err!(f, "a bip32 error"; e),
            Self::NotSupported =>
                f.write_str("the GetKey operation is not supported for this key request"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GetKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotSupported => None,
            Self::Bip32(ref e) => Some(e),
        }
    }
}

impl From<bip32::Error> for GetKeyError {
    fn from(e: bip32::Error) -> Self { Self::Bip32(e) }
}

#[cfg(test)]
mod test {
    use alloc::vec;

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::key::PublicKey;
    use bitcoin::script::Builder;
    use bitcoin::sighash::EcdsaSighashType;
    use bitcoin::transaction::Version;
    use bitcoin::{
        opcodes, taproot, Amount, OutPoint, ScriptBuf, Transaction, TxOut, XOnlyPublicKey,
    };

    use super::*;
    use crate::error::FundingUtxoError;
    use crate::global::Global;
    use crate::map::input::Input;
    use crate::map::output::Output;
    use crate::{Count, IndexOutOfBoundsError};

    /// Builds a single-input PSBT spending a P2WPKH output, with both witness and non-witness
    /// UTXOs set. Used as the base for the strict/trusted matrix below.
    fn wpkh_psbt() -> Psbt {
        let pubkey = PublicKey::from_slice(&[2u8; 33]).unwrap();
        let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());
        let tx_out = TxOut { value: Amount::from_sat(1_000), script_pubkey };
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![tx_out.clone()],
        };
        let out_point = OutPoint { txid: funding_tx.compute_txid(), vout: 0 };
        let mut input = Input::new(&out_point);
        input.witness_utxo = Some(tx_out);
        input.non_witness_utxo = Some(funding_tx);
        Psbt {
            global: Global {
                input_count: Count::from(1),
                output_count: Count::from(1),
                ..Global::default()
            },
            inputs: vec![input],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            })],
        }
    }

    /// Strip the non-witness UTXO to simulate a witness-only input (untrusted-inflatable).
    fn witness_only(psbt: &mut Psbt) { psbt.inputs[0].non_witness_utxo = None; }

    /// A strictly-verifiable single-input P2WPKH PSBT whose input's key is recorded in
    /// `bip32_derivations`, plus the matching key map (the PSBT's pubkey -> its private key).
    fn keyed_psbt() -> (Psbt, BTreeMap<PublicKey, PrivateKey>) {
        use bitcoin::key::PrivateKey;
        use bitcoin::secp256k1::SecretKey;
        use bitcoin::Network;

        let secp = Secp256k1::new();
        let priv_key =
            PrivateKey::new(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Bitcoin);
        let pubkey = priv_key.public_key(&secp);
        let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());
        let tx_out = TxOut { value: Amount::from_sat(1_000), script_pubkey };
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![tx_out.clone()],
        };
        let out_point = OutPoint { txid: funding_tx.compute_txid(), vout: 0 };
        let mut input = Input::new(&out_point);
        input.witness_utxo = Some(tx_out);
        input.non_witness_utxo = Some(funding_tx);
        input.bip32_derivations.insert(pubkey, bitcoin::bip32::KeySource::default());
        let psbt = Psbt {
            global: Global {
                input_count: Count::from(1),
                output_count: Count::from(1),
                ..Global::default()
            },
            inputs: vec![input],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            })],
        };
        let mut key_map: BTreeMap<PublicKey, PrivateKey> = BTreeMap::new();
        key_map.insert(pubkey, priv_key);
        (psbt, key_map)
    }

    /// A witness-only single-input P2TR key-path PSBT whose internal key is recorded in
    /// `tap_key_origins`, plus the matching key map (the PSBT's pubkey -> its private key).
    ///
    /// A witness-only P2TR UTXO is strictly verifiable: the taproot sighash commits to the
    /// prevout's amount and scriptPubKey.
    fn tr_psbt() -> (Psbt, BTreeMap<PublicKey, PrivateKey>) {
        use bitcoin::key::PrivateKey;
        use bitcoin::secp256k1::SecretKey;
        use bitcoin::Network;

        let secp = Secp256k1::new();
        let priv_key =
            PrivateKey::new(SecretKey::from_slice(&[1u8; 32]).unwrap(), Network::Bitcoin);
        let pubkey = priv_key.public_key(&secp);
        let xonly = pubkey.inner.x_only_public_key().0;
        let script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly, None);
        let tx_out = TxOut { value: Amount::from_sat(1_000), script_pubkey };
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![tx_out.clone()],
        };
        let out_point = OutPoint { txid: funding_tx.compute_txid(), vout: 0 };
        let mut input = Input::new(&out_point);
        input.witness_utxo = Some(tx_out);
        input.tap_internal_key = Some(xonly);
        input.tap_key_origins.insert(xonly, (vec![], KeySource::default()));
        let psbt = Psbt {
            global: Global {
                input_count: Count::from(1),
                output_count: Count::from(1),
                ..Global::default()
            },
            inputs: vec![input],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            })],
        };
        let mut key_map: BTreeMap<PublicKey, PrivateKey> = BTreeMap::new();
        key_map.insert(pubkey, priv_key);
        (psbt, key_map)
    }

    /// Builds a single-input PSBT funding `tx_out`, with both witness and non-witness UTXOs set
    /// consistently.
    fn funded_psbt(tx_out: TxOut) -> Psbt {
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![tx_out.clone()],
        };
        let out_point = OutPoint { txid: funding_tx.compute_txid(), vout: 0 };
        let mut input = Input::new(&out_point);
        input.witness_utxo = Some(tx_out);
        input.non_witness_utxo = Some(funding_tx);
        Psbt {
            global: Global {
                input_count: Count::from(1),
                output_count: Count::from(1),
                ..Global::default()
            },
            inputs: vec![input],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            })],
        }
    }

    fn single_input_psbt() -> Psbt {
        Psbt {
            global: Global {
                input_count: Count::from(1),
                output_count: Count::from(1),
                ..Global::default()
            },
            inputs: vec![Input::new(&OutPoint::null())],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            })],
        }
    }

    fn two_inputs_one_output_psbt() -> Psbt {
        Psbt {
            global: Global {
                input_count: Count::from(2),
                output_count: Count::from(1),
                ..Global::default()
            },
            inputs: vec![Input::new(&OutPoint::null()), Input::new(&OutPoint::null())],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            })],
        }
    }

    #[test]
    fn verify_rejects_witness_only_non_p2tr() {
        let mut psbt = wpkh_psbt();
        witness_only(&mut psbt);
        assert_eq!(
            SignableInput::verify(&psbt, 0),
            Err(SignError::FundingUtxo(FundingUtxoError::UnverifiableUtxo))
        );
    }

    #[test]
    fn assume_checked_accepts_witness_only_non_p2tr() {
        let mut psbt = wpkh_psbt();
        witness_only(&mut psbt);
        let input =
            SignableInput::assume_checked(&psbt, 0).expect("trusted path accepts witness-only");
        assert_eq!(input.index(), 0);
        assert_eq!(input.output_type(), OutputType::Wpkh);
    }

    #[test]
    fn assume_checked_still_rejects_mismatching_txid() {
        let mut psbt = wpkh_psbt();
        // Point the input at a different txid than its non-witness UTXO.
        psbt.inputs[0].previous_txid = OutPoint::null().txid;
        assert_eq!(
            SignableInput::assume_checked(&psbt, 0),
            Err(SignError::FundingUtxo(FundingUtxoError::MismatchingTxid))
        );
    }

    #[test]
    fn assume_checked_rejects_sighash_single_missing_output() {
        let mut psbt = wpkh_psbt();
        psbt.outputs.clear(); // no output at index 0
        psbt.global.output_count = Count::from(0);
        psbt.inputs[0].sighash_type = Some(EcdsaSighashType::Single.into());
        assert_eq!(
            SignableInput::assume_checked(&psbt, 0),
            Err(SignError::SighashSingleMissingOutput)
        );
    }

    #[test]
    fn verify_accepts_wsh_with_matching_witness_script() {
        let witness_script = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
        let script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let mut psbt = funded_psbt(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].witness_script = Some(witness_script);

        assert!(SignableInput::verify(&psbt, 0).is_ok());
    }

    #[test]
    fn verify_rejects_wsh_with_wrong_witness_script() {
        let witness_script = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
        let wrong_witness_script = Builder::new().push_opcode(opcodes::OP_FALSE).into_script();
        let script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let mut psbt = funded_psbt(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].witness_script = Some(wrong_witness_script);

        assert_eq!(SignableInput::verify(&psbt, 0), Err(SignError::WitnessScriptMismatchWsh));
    }

    #[test]
    fn verify_rejects_shwsh_with_wrong_witness_script() {
        // The witness script must hash to the redeem script even when the redeem script
        // correctly hashes to the scriptPubKey: a single-sided mismatch still rejects.
        let real_witness_script = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
        let wrong_witness_script = Builder::new().push_opcode(opcodes::OP_FALSE).into_script();
        let redeem_script = ScriptBuf::new_p2wsh(&real_witness_script.wscript_hash());
        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
        let mut psbt = funded_psbt(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].redeem_script = Some(redeem_script);
        psbt.inputs[0].witness_script = Some(wrong_witness_script);

        assert_eq!(SignableInput::verify(&psbt, 0), Err(SignError::WitnessScriptMismatchShWsh));
    }

    #[test]
    fn verify_rejects_tap_key_sig_sighash_mismatch() {
        // A taproot key sig whose sighash type disagrees with the input's declared sighash
        // type, with no other signatures present.
        let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly, None);
        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::ALL);
        psbt.inputs[0].tap_key_sig = Some(taproot::Signature {
            signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&[1u8; 64]).unwrap(),
            sighash_type: TapSighashType::None,
        });

        assert_eq!(SignableInput::verify(&psbt, 0), Err(SignError::SighashMismatch));
    }

    #[test]
    fn verify_rejects_partial_sig_sighash_mismatch() {
        // A partial sig whose sighash type disagrees with the input's declared sighash
        // type, with no other signatures present.
        let pubkey = PublicKey::from_slice(&[2u8; 33]).unwrap();
        let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());
        let mut psbt = funded_psbt(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::ALL);
        psbt.inputs[0].partial_sigs.insert(
            pubkey,
            ecdsa::Signature {
                signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&[1u8; 64]).unwrap(),
                sighash_type: EcdsaSighashType::None,
            },
        );

        assert_eq!(SignableInput::verify(&psbt, 0), Err(SignError::SighashMismatch));
    }

    #[test]
    fn assume_checked_accepts_sighash_single_with_output() {
        // SIGHASH_SINGLE with a matching output at the same index is accepted.
        let mut psbt = wpkh_psbt();
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::Single));

        assert!(SignableInput::assume_checked(&psbt, 0).is_ok());
    }

    #[test]
    fn assume_checked_accepts_taproot_default_sighash() {
        // An explicit SIGHASH_DEFAULT (0x00) is valid for taproot but non-standard for
        // ECDSA: the input must validate through the taproot sighash check.
        let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly, None);
        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(TapSighashType::Default));

        assert!(SignableInput::assume_checked(&psbt, 0).is_ok());
    }

    #[test]
    fn signable_input_reports_the_index_it_was_created_from() {
        let pubkey = PublicKey::from_slice(&[2u8; 33]).unwrap();
        let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());
        let mut psbt = two_inputs_one_output_psbt();
        psbt.inputs[1].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });

        let input = SignableInput::assume_checked(&psbt, 1).expect("input 1 passes checks");
        assert_eq!(input.index(), 1);
    }

    #[test]
    fn sighash_matches_direct_computation() {
        // The signer's sighash must equal an independent SighashCache computation for the input.
        let mut signer = Signer::new(wpkh_psbt()).unwrap();
        let (msg, ty) = signer.session(|mut session| {
            let input = session.signable_input(0).unwrap();
            session.ecdsa_sighash(&input)
        });

        // Recompute independently from the input's (validated) funding UTXO.
        let tx = signer.unsigned_tx();
        let mut cache = SighashCache::new(&tx);
        let utxo = signer.as_psbt().inputs[0].funding_utxo().unwrap();
        let expected = cache
            .p2wpkh_signature_hash(0, &utxo.script_pubkey, utxo.value, EcdsaSighashType::All)
            .unwrap();
        assert_eq!(msg, Message::from(expected));
        assert_eq!(ty, EcdsaSighashType::All);
    }

    #[test]
    fn taproot_input_sighash_is_schnorr() {
        use bitcoin::sighash::Prevouts;

        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly, None);
        let tx_out = TxOut { value: Amount::from_sat(1_000), script_pubkey };
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![tx_out.clone()],
        };
        let out_point = OutPoint { txid: funding_tx.compute_txid(), vout: 0 };
        let mut input = Input::new(&out_point);
        input.witness_utxo = Some(tx_out.clone());
        input.non_witness_utxo = Some(funding_tx);
        let psbt = Psbt {
            global: Global {
                input_count: Count::from(1),
                output_count: Count::from(1),
                ..Global::default()
            },
            inputs: vec![input],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            })],
        };
        let mut signer = Signer::new(psbt).unwrap();
        let (msg, ty) = signer.session(|mut session| {
            let inputs = session.signable_inputs().expect("taproot passes signer checks");
            let input = &inputs.inputs[0];
            session.taproot_sighash(input, &inputs.prevouts, None)
        });

        // Recompute independently: key-path spend over the single prevout.
        let tx = signer.unsigned_tx();
        let mut cache = SighashCache::new(&tx);
        let expected = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[tx_out]), TapSighashType::Default)
            .unwrap();
        assert_eq!(msg, Message::from(expected));
        assert_eq!(ty, TapSighashType::Default);
    }

    #[test]
    fn signable_input_rejects_taproot_but_signable_inputs_accepts_it() {
        // A standalone signable input is never taproot: a taproot sighash commits to every
        // input's prevout, so taproot inputs are only created for a complete input set.
        let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly, None);
        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });

        let mut signer = Signer::new(psbt.clone()).unwrap();
        assert_eq!(
            signer.session(|p| p.signable_input(0).map(|input| input.index())),
            Err(SignError::AllPrevoutsRequired)
        );
        assert_eq!(
            signer.session(|p| p.assume_checked_input(0).map(|input| input.index())),
            Err(SignError::AllPrevoutsRequired)
        );

        let mut signer = Signer::new(psbt).unwrap();
        let len = signer
            .session(|p| p.signable_inputs().map(|inputs| inputs.len()))
            .expect("complete set accepts taproot");
        assert_eq!(len, 1);
    }

    #[test]
    fn sign_all_signs_taproot_script_path() {
        let secp = Secp256k1::new();
        let (mut psbt, key_map) = tr_psbt();

        // Turn the key-path input into a script-path input: the key is recorded for one leaf, so
        // the key-path branch (which requires empty leaf hashes) is skipped and the signature is
        // produced for the leaf.
        let xonly = psbt.inputs[0].tap_internal_key.unwrap();
        let leaf_hash = TapLeafHash::from_byte_array([1u8; 32]);
        psbt.inputs[0].tap_key_origins.insert(xonly, (vec![leaf_hash], KeySource::default()));

        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(sign_all(&key_map, &secp)).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].len(), 1);

        let psbt = signer.apply(sigs).unwrap();
        let sig = psbt.inputs[0].tap_script_sigs.get(&(xonly, leaf_hash)).expect("script-path sig");
        assert_eq!(sig.sighash_type, TapSighashType::Default);
    }

    #[test]
    fn verify_rejects_tap_script_sig_sighash_mismatch() {
        // A taproot script-path signature whose sighash type disagrees with the input's declared
        // sighash type, with no other signatures present.
        let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly, None);
        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::ALL);
        psbt.inputs[0].tap_script_sigs.insert(
            (xonly, TapLeafHash::from_byte_array([1u8; 32])),
            taproot::Signature {
                signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&[1u8; 64]).unwrap(),
                sighash_type: TapSighashType::None,
            },
        );

        assert_eq!(SignableInput::verify(&psbt, 0), Err(SignError::SighashMismatch));
    }

    #[test]
    fn get_input_sigs_signs_anyonecanpay_taproot_standalone() {
        let secp = Secp256k1::new();
        let (mut psbt, key_map) = tr_psbt();
        // An ANYONECANPAY taproot sighash commits only to this input's prevout, so it is signable
        // standalone (SIGHASH_ALL plus ANYONECANPAY avoids the SINGLE output bound).
        psbt.inputs[0].sighash_type =
            Some(PsbtSighashType::from(TapSighashType::AllPlusAnyoneCanPay));

        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(|mut session| {
            let input = session.signable_input(0).expect("ACP taproot is signable standalone");
            assert_eq!(input.output_type(), OutputType::Tr);
            session.get_input_sigs(&input, &key_map, &secp)
        });
        assert_eq!(sigs.len(), 1);

        let psbt = signer.apply([sigs]).unwrap();
        assert!(psbt.inputs[0].tap_key_sig.is_some());
    }

    #[test]
    fn taproot_key_path_signature_verifies() {
        use bitcoin::sighash::Prevouts;

        let secp = Secp256k1::new();
        let (psbt, key_map) = tr_psbt();
        let tx_out = psbt.inputs[0].witness_utxo.clone().unwrap();

        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(sign_all(&key_map, &secp)).unwrap();
        assert_eq!(sigs.len(), 1);
        let signature = match &sigs[0].signatures {
            TypedSigs::Taproot(sigs) => &sigs[0].1.signature,
            TypedSigs::Ecdsa(_) => panic!("taproot input must produce schnorr signatures"),
        };

        // Recompute the sighash independently and verify the signature against the tweaked output
        // key committed to by the prevout scriptPubKey.
        let spk = tx_out.script_pubkey.clone();
        let tx = signer.unsigned_tx();
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[tx_out]), TapSighashType::Default)
            .unwrap();
        let output_key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).unwrap();
        secp.verify_schnorr(signature, &Message::from(sighash), &output_key)
            .expect("key-path signature verifies against the tweaked output key");
    }

    #[test]
    fn verify_rejects_mismatching_taproot_internal_key() {
        // The declared internal key does not tweak to the output key committed to by the prevout's
        // scriptPubKey: the strict path rejects, the attested path trusts the caller.
        let secp = Secp256k1::verification_only();
        use bitcoin::secp256k1::SecretKey;
        let (other, _) = SecretKey::from_slice(&[9u8; 32])
            .unwrap()
            .x_only_public_key(&Secp256k1::signing_only());
        let script_pubkey = ScriptBuf::new_p2tr(&secp, other, None);
        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].tap_internal_key = Some(XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap());

        assert_eq!(SignableInput::verify(&psbt, 0), Err(SignError::TaprootInternalKeyMismatch));
        assert!(SignableInput::assume_checked(&psbt, 0).is_ok());
    }

    #[test]
    fn signing_skips_existing_taproot_signatures() {
        let secp = Secp256k1::new();

        // An existing key-path signature is not replaced.
        let (psbt, key_map) = tr_psbt();
        let existing = bitcoin::secp256k1::schnorr::Signature::from_slice(&[1u8; 64]).unwrap();
        let mut psbt = psbt;
        psbt.inputs[0].tap_key_sig =
            Some(taproot::Signature { signature: existing, sighash_type: TapSighashType::Default });
        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(sign_all(&key_map, &secp)).unwrap();
        assert!(sigs.iter().all(|input_sigs| input_sigs.is_empty()));
        let psbt = signer.apply(sigs).unwrap();
        assert_eq!(psbt.inputs[0].tap_key_sig.unwrap().signature, existing);

        // An existing script-path signature for a leaf is not duplicated.
        let (mut psbt, key_map) = tr_psbt();
        let xonly = psbt.inputs[0].tap_internal_key.unwrap();
        let leaf_hash = TapLeafHash::from_byte_array([1u8; 32]);
        psbt.inputs[0].tap_key_origins.insert(xonly, (vec![leaf_hash], KeySource::default()));
        psbt.inputs[0].tap_script_sigs.insert(
            (xonly, leaf_hash),
            taproot::Signature { signature: existing, sighash_type: TapSighashType::Default },
        );
        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(sign_all(&key_map, &secp)).unwrap();
        assert!(sigs.iter().all(|input_sigs| input_sigs.is_empty()));
    }

    #[test]
    fn get_some_signs_a_subset_of_standalone_inputs() {
        let secp = Secp256k1::new();
        let (mut psbt, key_map) = keyed_psbt();
        // Duplicate the keyed input so the PSBT has two signable standalone inputs.
        psbt.inputs.push(psbt.inputs[0].clone());
        psbt.global.input_count = Count::from(2);

        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(|mut session| {
            let first = session.signable_input(0).unwrap();
            let second = session.signable_input(1).unwrap();
            session.get_some(&[first, second], &key_map, &secp)
        });

        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs.iter().map(|s| s.index).collect::<alloc::vec::Vec<_>>(), vec![0, 1]);
        assert!(sigs.iter().all(|s| s.len() == 1));
    }

    #[test]
    fn sign_input_produces_partial_sig() {
        let secp = Secp256k1::new();
        let (psbt, key_map) = keyed_psbt();
        let pubkey = *key_map.keys().next().unwrap();

        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(|mut session| {
            let input = session.signable_input(0).unwrap();
            session.get_input_sigs(&input, &key_map, &secp)
        });
        if let TypedSigs::Ecdsa(signatures) = &sigs.signatures {
            let used: Vec<PublicKey> = signatures.iter().map(|(pk, _)| *pk).collect();
            let psbt = signer.apply([sigs]).expect("fresh signable input signatures");
            assert_eq!(used, vec![pubkey]);
            assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        } else {
            panic!("no ECDSA signatures were generated")
        }
    }

    #[test]
    fn bindable_sign_input_signs_the_bound_input() {
        let secp = Secp256k1::new();
        let (psbt, key_map) = keyed_psbt();

        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(sign_input(0, &key_map, &secp)).unwrap();
        assert_eq!(sigs.index, 0);
        assert_eq!(sigs.len(), 1);
        let psbt = signer.apply([sigs]).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn bindable_sign_all_signs_every_input() {
        let secp = Secp256k1::new();
        let (psbt, key_map) = keyed_psbt();

        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(sign_all(&key_map, &secp)).unwrap();
        assert_eq!(sigs.len(), 1);
        let psbt = signer.apply(sigs).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn sign_input_is_strict_while_sign_input_unchecked_signs_witness_only() {
        let secp = Secp256k1::new();
        let (mut psbt, key_map) = keyed_psbt();
        witness_only(&mut psbt);

        // Strict: a witness-only non-P2TR input cannot be verified.
        let mut signer = Signer::new(psbt.clone()).unwrap();
        assert_eq!(
            signer.session(sign_input(0, &key_map, &secp)),
            Err(SignError::FundingUtxo(FundingUtxoError::UnverifiableUtxo))
        );

        // Unchecked: the caller attests the funding data out-of-band.
        let sigs = signer.session(sign_input_unchecked(0, &key_map, &secp)).unwrap();
        assert_eq!(sigs.len(), 1);
        let psbt = signer.apply([sigs]).unwrap();
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn bindable_sign_all_unchecked_signs_witness_only() {
        let secp = Secp256k1::new();
        let (mut psbt, key_map) = keyed_psbt();
        witness_only(&mut psbt);

        let mut signer = Signer::new(psbt).unwrap();
        let sigs = signer.session(sign_all_unchecked(&key_map, &secp)).unwrap();
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn bindable_sign_input_reports_out_of_bounds() {
        let secp = Secp256k1::new();
        let (psbt, key_map) = keyed_psbt();

        let mut signer = Signer::new(psbt).unwrap();
        assert_eq!(
            signer.session(sign_input(1, &key_map, &secp)),
            Err(SignError::IndexOutOfBounds(IndexOutOfBoundsError::Inputs { index: 1, length: 1 }))
        );
    }

    #[test]
    fn apply_rejects_out_of_bounds_index_even_when_empty() {
        // An entry with no signatures is skipped only after its index is bounds-checked.
        let (psbt, _) = keyed_psbt();
        let signer = Signer::new(psbt).unwrap();
        let empty = InputSigs { index: 1, signatures: TypedSigs::Ecdsa(vec![]) };
        let err = signer.apply([empty]).expect_err("out-of-bounds index is rejected");
        assert_eq!(
            err,
            SignError::IndexOutOfBounds(IndexOutOfBoundsError::Inputs { index: 1, length: 1 })
        );
    }

    #[cfg(all(feature = "rand", feature = "std"))]
    mod get_key {
        #[cfg(any(feature = "miniscript", all(feature = "rand", feature = "std")))]
        use super::*;

        #[cfg(all(feature = "rand", feature = "std"))]
        fn gen_keys() -> (PrivateKey, PublicKey, Secp256k1<bitcoin::secp256k1::All>) {
            use bitcoin::secp256k1::{rand, SecretKey};
            use bitcoin::Network;

            let secp = Secp256k1::new();
            let sk = SecretKey::new(&mut rand::thread_rng());
            let priv_key = PrivateKey::new(sk, Network::Testnet4);
            let pk = PublicKey::from_private_key(&secp, &priv_key);

            (priv_key, pk, secp)
        }

        #[test]
        #[cfg(all(feature = "rand", feature = "std"))]
        fn pubkey_map_get_key_negates_odd_parity_keys() {
            let (mut priv_key, mut pk, secp) = gen_keys();
            let (xonly, parity) = pk.inner.x_only_public_key();

            let mut pubkey_map: HashMap<PublicKey, PrivateKey> = HashMap::new();

            if parity == bitcoin::secp256k1::Parity::Even {
                priv_key = PrivateKey {
                    compressed: priv_key.compressed,
                    network: priv_key.network,
                    inner: priv_key.inner.negate(),
                };
                pk = priv_key.public_key(&secp);
            }

            pubkey_map.insert(pk, priv_key);

            let req_result = pubkey_map.get_key(&KeyRequest::XOnlyPubkey(xonly), &secp).unwrap();

            let retrieved_key = req_result.unwrap();

            let retrieved_pub_key = retrieved_key.public_key(&secp);
            let (retrieved_xonly, retrieved_parity) = retrieved_pub_key.inner.x_only_public_key();

            assert_eq!(xonly, retrieved_xonly);
            assert_eq!(
                retrieved_parity,
                bitcoin::secp256k1::Parity::Even,
                "Key should be normalized to have even parity, even when original had odd parity"
            );
        }

        #[test]
        #[cfg(feature = "miniscript")]
        fn xpriv_bip32_request_succeeds() {
            use bitcoin::bip32::DerivationPath;
            use bitcoin::Network;
            use miniscript::hex::hex;
            let secp = Secp256k1::new();

            let seed = hex!("000102030405060708090a0b0c0d0e0f");
            let parent_xpriv: Xpriv = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
            let path: DerivationPath = "m/1/2/3".parse().unwrap();
            let path_prefix: DerivationPath = "m/1".parse().unwrap();

            let expected_private_key = parent_xpriv.derive_priv(&secp, &path).unwrap().to_priv();

            let derived_xpriv = parent_xpriv.derive_priv(&secp, &path_prefix).unwrap();

            let derived_key = derived_xpriv
                .get_key(&KeyRequest::Bip32((parent_xpriv.fingerprint(&secp), path)), &secp)
                .unwrap();

            assert_eq!(derived_key, Some(expected_private_key));
        }

        #[test]
        #[cfg(feature = "miniscript")]
        fn xpriv_bip32_request_wrong_first_segment() {
            use bitcoin::bip32::DerivationPath;
            use bitcoin::Network;
            use miniscript::hex::hex;
            let secp = Secp256k1::new();

            let seed = hex!("000102030405060708090a0b0c0d0e0f");
            let parent_xpriv: Xpriv = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
            let path: DerivationPath = "m/2/3".parse().unwrap();
            let path_prefix: DerivationPath = "m/1".parse().unwrap();

            let derived_xpriv = parent_xpriv.derive_priv(&secp, &path_prefix).unwrap();

            let derived_key = derived_xpriv
                .get_key(&KeyRequest::Bip32((parent_xpriv.fingerprint(&secp), path)), &secp)
                .unwrap();

            // Fingerprint matches but first path segment (2) != child_number (1).
            assert_eq!(derived_key, None);
        }

        #[test]
        #[cfg(feature = "miniscript")]
        fn xpriv_bip32_request_fp_mismatch() {
            use bitcoin::bip32::DerivationPath;
            use bitcoin::Network;
            use miniscript::hex::hex;
            let secp = Secp256k1::new();

            let seed = hex!("000102030405060708090a0b0c0d0e0f");
            let other_seed = hex!("aabbccddeeff00112233445566778899");
            let parent_xpriv: Xpriv = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
            let other_xpriv: Xpriv = Xpriv::new_master(Network::Bitcoin, &other_seed).unwrap();
            let path: DerivationPath = "m/1".parse().unwrap();

            let derived_xpriv = parent_xpriv.derive_priv(&secp, &path).unwrap();

            let derived_key = derived_xpriv
                .get_key(&KeyRequest::Bip32((other_xpriv.fingerprint(&secp), path)), &secp)
                .unwrap();

            // Fingerprint mismatch but path nonempty and first segment matches child_number.
            assert_eq!(derived_key, None);
        }
    }
}
