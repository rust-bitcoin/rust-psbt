// SPDX-License-Identifier: CC0-1.0

//! The BIP-370 Signer role.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::fmt;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use bitcoin::bip32::{self, KeySource, Xpriv};
use bitcoin::secp256k1::{Message, Secp256k1, Signing};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache};
use bitcoin::{
    ecdsa, PrivateKey, PublicKey, ScriptBuf, TapSighashType, Transaction, TxOut, Txid,
    XOnlyPublicKey,
};

use crate::error::{write_err, DetermineLockTimeError};
use crate::psbt::Psbt;
use crate::{IndexOutOfBoundsError, OutputType, PsbtSighashType, SignError};

/// Implements the BIP-370 Signer role.
///
/// A [`Signer`] owns the [`Psbt`] for a single signing session and an internal [`SighashCache`] built
/// from the unsigned transaction at construction.
///
/// Because no `&mut self` method mutates the tx-defining fields of the [`Psbt`], the cached
/// transaction stays valid for the lifetime of the [`Signer`]; the cache is reused across signing
/// calls so the shared sighash intermediates are computed once.
///
/// The session is split into two phases. [`Signer::session`] hands out a [`SigningSession`]
/// that borrows the [`Psbt`] immutably and creates [`SignableInput`]s tied to that borrow.
///
/// The session produces signatures without writing them; [`Signer::apply`] writes them afterwards,
/// once the session and its signable inputs are dropped.
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

    /// Returns a reference to the inner [`Psbt`], e.g. to produce [`SignableInput`]s against it.
    pub fn as_psbt(&self) -> &Psbt { &self.psbt }

    /// Lends the [`Psbt`] and sighash cache to a [`SigningSession`] for the frozen signing window.
    ///
    /// The provider creates [`SignableInput`] inputs (tied to the borrow, so the [`Psbt`] cannot be
    /// mutated while any signable input is alive) and produces signatures without writing them. Call
    /// [`Signer::apply`] afterwards to write the signatures into the [`Psbt`].
    pub fn session(&mut self) -> SigningSession<'_> {
        SigningSession { psbt: &self.psbt, cache: &mut self.cache }
    }

    /// Writes signatures produced by a [`SigningSession`] into the [`Psbt`].
    ///
    /// Clears `PSBT_GLOBAL_TX_MODIFIABLE` for each input signed.
    ///
    /// Fails on the first entry whose index is out of bounds (only possible for signatures created
    /// for a different [`Psbt`].
    pub fn apply(mut self, sigs: impl IntoIterator<Item = InputSigs>) -> Result<Psbt, SignError> {
        for InputSigs { index, signatures } in sigs {
            let length = self.psbt.inputs.len();
            let psbt_input = self.psbt.inputs.get_mut(index).ok_or(SignError::IndexOutOfBounds(
                IndexOutOfBoundsError::Inputs { index, length },
            ))?;
            // BIP-370: a signer must update PSBT_GLOBAL_TX_MODIFIABLE after signing inputs.
            let sighash_ty = signatures.first().map(|(_, sig)| sig.sighash_type);
            for (pk, sig) in signatures {
                psbt_input.partial_sigs.insert(pk, sig);
            }
            if let Some(ty) = sighash_ty {
                self.psbt.clear_tx_modifiable(PsbtSighashType::from(ty));
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
/// The [`SigningSession`] produces signatures without writing them; call [`Signer::apply`] to write them
/// into the `Psbt` after the session and its signable inputs are dropped.
pub struct SigningSession<'a> {
    psbt: &'a Psbt,
    /// The sighash cache the [`Signer`] is commited to.
    pub(crate) cache: &'a mut SighashCache<Transaction>,
}

/// Signatures for one input, produced by [`SigningSession::get_input_sigs`] and written into
/// the [`Psbt`] by [`Signer::apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSigs {
    /// The input index these signatures are for.
    pub index: usize,
    /// The `(pubkey, signature)` pairs, one per key the key provider held for this input.
    pub signatures: Vec<(PublicKey, ecdsa::Signature)>,
}

impl<'a> SigningSession<'a> {
    /// Strictly creates a [`SignableInput`] for `index` from the borrowed [`Psbt`].
    ///
    /// See [`SignableInput::verify`].
    pub fn signable_input(&self, index: usize) -> Result<SignableInput<'a>, SignError> {
        SignableInput::verify(self.psbt, index)
    }

    /// Creates a [`SignableInput`] for `index` against the [`Psbt`], without verifying data.
    ///
    /// This method assumes the caller verified data offline.
    ///
    /// See [`SignableInput::assume_checked`].
    pub fn assume_checked_input(&self, index: usize) -> Result<SignableInput<'a>, SignError> {
        SignableInput::assume_checked(self.psbt, index)
    }

    /// Strictly creates a [`SignableInput`] for every input.
    ///
    /// All-or-nothing: if any input fails its checks, returns the per-input errors and no signable
    /// inputs.
    pub fn signable_inputs(&self) -> Result<Vec<SignableInput<'a>>, BTreeMap<usize, SignError>> {
        let mut signable_inputs = Vec::new();
        let mut errors: BTreeMap<usize, SignError> = BTreeMap::new();
        for index in 0..self.psbt.global.input_count {
            match SignableInput::verify(self.psbt, index) {
                Ok(input) => signable_inputs.push(input),
                Err(e) => {
                    errors.insert(index, e);
                }
            }
        }
        if errors.is_empty() {
            Ok(signable_inputs)
        } else {
            Err(errors)
        }
    }

    /// Produces the signatures for a single input without writing them.
    ///
    /// Signs with every key `k` yields for this input's `bip32_derivations`; inputs for which `k`
    /// holds no key are silently skipped (normal for partial/multisig signing flows). Taproot
    /// inputs sign nothing (schnorr signing is as yet unsupported).
    ///
    /// This method is infallible, all input-validation ran when the signable input was created.
    pub fn get_input_sigs<C, K>(
        &mut self,
        input: &SignableInput<'a>,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> InputSigs
    where
        C: Signing,
        K: GetKey,
    {
        let (msg, sighash) = input.sighash(self.cache);
        let Sighash::Ecdsa(sighash_ty) = sighash else {
            // Taproot inputs sign nothing (schnorr signing is as yet unsupported).
            return InputSigs { index: input.index, signatures: Vec::new() };
        };

        let psbt_input = self
            .psbt
            .checked_input(input.index)
            .expect("the index is already checked by SignableInput");
        let mut signatures = Vec::new();
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

            let sig = ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk.inner),
                sighash_type: sighash_ty,
            };

            let pk = sk.public_key(secp);
            signatures.push((pk, sig));
        }
        InputSigs { index: input.index, signatures }
    }

    /// Produces the signatures for every signable input for which the key is available without writing them.
    pub fn get_all<C, K>(
        &mut self,
        inputs: &[SignableInput<'a>],
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Vec<InputSigs>
    where
        C: Signing,
        K: GetKey,
    {
        inputs.iter().map(|input| self.get_input_sigs(input, k, secp)).collect()
    }
}

/// Evidence that an input is fit to sign.
///
/// Produced by [`SignableInput::verify`] (the untrusted path) or [`SignableInput::assume_checked`]
/// (the caller-attested path); both borrow the [`Psbt`] for the signable input's lifetime, so the borrow
/// checker forbids mutating the [`Psbt`] while the struct is alive.
///
/// A signable input is a snapshot of the input's verified signing data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignableInput<'a> {
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
    /// For taproot inputs, a snapshot of every input's spent output. Empty for non-taproot inputs.
    spent_outputs: Vec<TxOut>,
    /// The [`Psbt`] this signable input was created from.
    ///
    /// Ties the signable input's lifetime to a shared borrow of the [`Psbt`], so the borrow checker
    /// forbids mutating the [`Psbt`] while the signable input is alive.
    psbt: &'a Psbt,
}

/// The sighash type a new signature over a [`SignableInput`] commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sighash {
    /// ECDSA (legacy and segwit v0) inputs.
    Ecdsa(EcdsaSighashType),
    /// Schnorr (taproot) inputs.
    Schnorr(TapSighashType),
}

impl<'a> SignableInput<'a> {
    /// Runs the full BIP-174 signer checks and returns evidence of success.
    ///
    /// This is the untrusted path: in addition to the structural checks of
    /// [`Self::assume_checked`], it verifies the funding UTXO against a full transaction (rejecting
    /// witness-only non-P2TR inputs), checks that the redeem/witness scripts match the
    /// scriptPubKey, and that any existing signatures' sighash types agree with the declared one.
    pub fn verify(psbt: &'a Psbt, index: usize) -> Result<Self, SignError> {
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
    pub fn assume_checked(psbt: &'a Psbt, index: usize) -> Result<Self, SignError> {
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
    fn check_data(psbt: &'a Psbt, index: usize) -> Result<Self, SignError> {
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

        // For taproot, snapshot every input's spent output: the non-ANYONECANPAY sighash commits
        // to all of them. The trusted accessor is used uniformly (attested funding data).
        let spent_outputs = if matches!(output_type, OutputType::Tr) {
            psbt.inputs
                .iter()
                .map(|i| i.funding_utxo().cloned())
                .collect::<Result<_, _>>()
                .map_err(SignError::FundingUtxo)?
        } else {
            Vec::new()
        };

        Ok(Self { index, output_type, prevout, script_code, sighash_ty, spent_outputs, psbt })
    }

    /// The input index this evidence refers to.
    pub fn index(&self) -> usize { self.index }

    /// The input's prevout script type, which selects the signing algorithm and the sighash engine path.
    pub fn output_type(&self) -> OutputType { self.output_type }

    /// Computes the sighash a new signature over `input` commits to.
    ///
    /// The [`Sighash`] variant is determined by the input's [`OutputType`].
    ///
    /// This method is infallible, as its only called by [`SigningSession`], the [`SighashCache`]
    /// and the [`Psbt`] and this same [`SignableInput`] are unchangeable, so the invariants ensured
    /// by [`SignableInput`] stay true for the whole signing session.
    pub(crate) fn sighash(&self, cache: &'a mut SighashCache<Transaction>) -> (Message, Sighash) {
        match self.output_type {
            OutputType::Tr => {
                let tap_ty = self
                    .sighash_ty
                    .taproot_hash_ty()
                    .expect("sighash type validated when the signable input was created");
                let sighash = if matches!(
                    tap_ty,
                    TapSighashType::AllPlusAnyoneCanPay
                        | TapSighashType::NonePlusAnyoneCanPay
                        | TapSighashType::SinglePlusAnyoneCanPay
                ) {
                    // SIGHASH_ANYONECANPAY commits to only this input's prevout.
                    cache
                        .taproot_key_spend_signature_hash(
                            self.index,
                            &Prevouts::One(self.index, &self.prevout),
                            tap_ty,
                        )
                        .expect("input index in bounds (checked above)")
                } else {
                    cache
                        .taproot_key_spend_signature_hash(
                            self.index,
                            &Prevouts::All(&self.spent_outputs),
                            tap_ty,
                        )
                        .expect("prevouts size matched, input index in bounds (checked above)")
                };
                (Message::from(sighash), Sighash::Schnorr(tap_ty))
            }
            _ => {
                let ecdsa_ty = self
                    .sighash_ty
                    .ecdsa_hash_ty()
                    .expect("sighash type validated when the signable input was created");
                let sighash = match self.output_type {
                    OutputType::Bare | OutputType::Sh => Message::from(
                        cache
                            .legacy_signature_hash(self.index, &self.script_code, ecdsa_ty.to_u32())
                            .expect("input index in bounds (checked above)"),
                    ),
                    OutputType::Wpkh | OutputType::ShWpkh => Message::from(
                        cache
                            .p2wpkh_signature_hash(
                                self.index,
                                &self.script_code,
                                self.prevout.value,
                                ecdsa_ty,
                            )
                            .expect("standard sighash type validated at creation"),
                    ),
                    OutputType::Wsh | OutputType::ShWsh => Message::from(
                        cache
                            .p2wsh_signature_hash(
                                self.index,
                                &self.script_code,
                                self.prevout.value,
                                ecdsa_ty,
                            )
                            .expect("standard sighash type validated at creation"),
                    ),
                    OutputType::Tr => unreachable!("Tr handled in the Schnorr arm above"),
                };
                (sighash, Sighash::Ecdsa(ecdsa_ty))
            }
        }
    }
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
            global: Global { input_count: 1, output_count: 1, ..Global::default() },
            inputs: vec![input],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            })],
        }
    }

    /// Strip the non-witness UTXO to simulate a witness-only input (untrusted-inflatable).
    fn witness_only(psbt: &mut Psbt) { psbt.inputs[0].non_witness_utxo = None; }

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
            global: Global { input_count: 1, output_count: 1, ..Global::default() },
            inputs: vec![input],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            })],
        }
    }

    fn single_input_psbt() -> Psbt {
        Psbt {
            global: Global { input_count: 1, output_count: 1, ..Global::default() },
            inputs: vec![Input::new(&OutPoint::null())],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            })],
        }
    }

    fn two_inputs_one_output_psbt() -> Psbt {
        Psbt {
            global: Global { input_count: 2, output_count: 1, ..Global::default() },
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
        psbt.global.output_count = 0;
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
        let (msg, ty) = {
            let provider = signer.session();
            let input = provider.signable_input(0).unwrap();
            input.sighash(provider.cache)
        };

        // Recompute independently from the input's (validated) funding UTXO.
        let tx = signer.unsigned_tx();
        let mut cache = SighashCache::new(&tx);
        let utxo = signer.as_psbt().inputs[0].funding_utxo().unwrap();
        let expected = cache
            .p2wpkh_signature_hash(0, &utxo.script_pubkey, utxo.value, EcdsaSighashType::All)
            .unwrap();
        assert_eq!(msg, Message::from(expected));
        assert_eq!(ty, Sighash::Ecdsa(EcdsaSighashType::All));
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
            global: Global { input_count: 1, output_count: 1, ..Global::default() },
            inputs: vec![input],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            })],
        };
        let mut signer = Signer::new(psbt).unwrap();
        let (msg, ty) = {
            let provider = signer.session();
            let input = provider.signable_input(0).expect("taproot passes signer checks");
            input.sighash(provider.cache)
        };

        // Recompute independently: key-path spend over the single prevout.
        let tx = signer.unsigned_tx();
        let mut cache = SighashCache::new(&tx);
        let expected = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&[tx_out]), TapSighashType::Default)
            .unwrap();
        assert_eq!(msg, Message::from(expected));
        assert_eq!(ty, Sighash::Schnorr(TapSighashType::Default));
    }

    #[test]
    fn sign_input_produces_partial_sig() {
        use alloc::collections::BTreeMap;

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
            global: Global { input_count: 1, output_count: 1, ..Global::default() },
            inputs: vec![input],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::new(),
            })],
        };

        let mut signer = Signer::new(psbt).unwrap();
        let mut key_map: BTreeMap<PublicKey, PrivateKey> = BTreeMap::new();
        key_map.insert(pubkey, priv_key);
        let sigs = {
            let mut provider = signer.session();
            let input = provider.signable_input(0).unwrap();
            provider.get_input_sigs(&input, &key_map, &secp)
        };
        let used: Vec<PublicKey> = sigs.signatures.iter().map(|(pk, _)| *pk).collect();
        let psbt = signer.apply([sigs]).expect("fresh signable input signatures");
        assert_eq!(used, vec![pubkey]);
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
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
