// SPDX-License-Identifier: CC0-1.0

//! PSBT Version 2.
//!
//! A second version of the Partially Signed Bitcoin Transaction format and described in [BIP-174].
//!
//! Allows for inputs and outputs to be added to the PSBT after creation.
//!
//! # Roles
//!
//! BIP-174 describes various roles, these are implemented in this module as follows:
//!
//! - The **Creator** role Use the [`Creator`] type - or if creator and constructor are a single entity just use the `Constructor`.
//! - The **Constructor**: Use the [`Constructor`] type.
//! - The **Updater** role: Use the [`Updater`] type and then update additional fields of the [`Psbt`] directly.
//! - The **Signer** role: Use the [`Signer`] type.
//! - The **Finalizer** role: Use the [`Finalizer`] type (requires "miniscript" feature).
//! - The **Extractor** role: Use the [`Extractor`](crate::extractor::Extractor) type.
//!
//! To combine PSBTs use either `psbt.combine_with(other)` or `v2::combine(this, that)`.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

use alloc::borrow::Borrow;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::collections::{HashMap, HashSet};

use bitcoin::bip32::{self, KeySource, Xpriv};
use bitcoin::hex::DisplayHex;
use bitcoin::key::{PrivateKey, PublicKey};
use bitcoin::locktime::absolute;
use bitcoin::secp256k1::{Message, Secp256k1, Signing};
use bitcoin::sighash::{EcdsaSighashType, SighashCache, TapSighashType};
use bitcoin::{ecdsa, transaction, Amount, ScriptBuf, Sequence, Transaction, TxOut, Txid};
use bitcoin_consensus_encoding::{ArrayDecoder, BytesEncoder, Decoder, DecoderStatus, Encoder4};

#[cfg(feature = "base64")]
pub use self::display_from_str::ParsePsbtError;
use crate::encoding::{encode_to_vec, PsbtDecode, PsbtEncode};
use crate::error::{
    write_err, DeserializeError, DetermineLockTimeError, FeeError, FundingUtxoError,
    IndexOutOfBoundsError, InputsNotModifiableError, OutputsNotModifiableError,
    PsbtNotModifiableError, SignError,
};
#[cfg(feature = "miniscript")]
pub use crate::finalizer::{
    FinalizeError, FinalizeInputError, Finalizer, InputError, InterpreterCheckError,
    InterpreterCheckInputError,
};
use crate::global::{self, Global};
use crate::input::{self, Input};
use crate::output::{self, Output};
use crate::sighash_type::PsbtSighashType;
#[cfg(feature = "miniscript")]
use crate::PartialSigsSighashTypeError;

/// The magic bytes that identify a PSBT (`"psbt"` in ASCII).
const PSBT_MAGIC: &[u8; 4] = b"psbt";
/// The byte that separates the magic bytes from the global map (`0xff`).
const PSBT_SEPARATOR: u8 = 0xff;

bitcoin_consensus_encoding::encoder_newtype! {
    /// Encoder for a complete PSBT v2.
    pub struct PsbtV2Encoder<'e>(
        Encoder4<
            BytesEncoder<'static>,
            global::GlobalMapEncoder<'e>,
            crate::encoding::SliceEncoder<'e, Input>,
            crate::encoding::SliceEncoder<'e, Output>,
        >
    );
}

impl PsbtEncode for Psbt {
    type Encoder<'e> = PsbtV2Encoder<'e>;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        // `<psbt> := <magic> <global-map> <input-map>* <output-map>*`
        static HEADER: [u8; 5] =
            [PSBT_MAGIC[0], PSBT_MAGIC[1], PSBT_MAGIC[2], PSBT_MAGIC[3], PSBT_SEPARATOR];
        PsbtV2Encoder::new(Encoder4::new(
            BytesEncoder::without_length_prefix(&HEADER),
            self.global.psbt_encoder(),
            crate::encoding::SliceEncoder::without_length_prefix(&self.inputs),
            crate::encoding::SliceEncoder::without_length_prefix(&self.outputs),
        ))
    }
}

/// Decoder for PSBT v2.
#[derive(Debug)]
pub struct PsbtV2Decoder {
    stage: DecoderStage,
}

/// The state of the PSBT v2 decoder.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum DecoderStage {
    /// Decoding the magic bytes (`"psbt"`).
    Magic(ArrayDecoder<4>),
    /// Decoding the separator (`0xff`).
    Separator,
    /// Decoding the global map.
    Global(global::GlobalDecoder),
    /// Decoding the input maps.
    Inputs(Global, input::InputsDecoder),
    /// Decoding the output maps.
    Outputs(Global, Vec<Input>, output::OutputsDecoder),
    /// Done decoding the [`Psbt`].
    Done(Psbt),
    /// Sentinel used during state transitions.
    Errored,
}

impl Decoder for PsbtV2Decoder {
    type Output = Psbt;
    type Error = DeserializeError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        loop {
            // Attempt to push bytes into the active decoder, return on success (more bytes required).
            match &mut self.stage {
                DecoderStage::Magic(decoder) => match decoder.push_bytes(bytes) {
                    Ok(status) if status.needs_more() => return Ok(DecoderStatus::NeedsMore),
                    Ok(_) => {}
                    Err(_) => unreachable!("ArrayDecoder never panics in push_bytes"),
                },
                DecoderStage::Separator =>
                    if bytes.is_empty() {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                DecoderStage::Global(decoder) =>
                    if decoder.push_bytes(bytes)?.needs_more() {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                DecoderStage::Inputs(_, decoder) =>
                    if decoder
                        .push_bytes(bytes)
                        .map_err(DeserializeError::DecodeInputs)?
                        .needs_more()
                    {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                DecoderStage::Outputs(_, _, decoder) =>
                    if decoder
                        .push_bytes(bytes)
                        .map_err(DeserializeError::DecodeOutputs)?
                        .needs_more()
                    {
                        return Ok(DecoderStatus::NeedsMore);
                    },
                DecoderStage::Done(_) => return Ok(DecoderStatus::Ready),
                DecoderStage::Errored => {
                    panic!("call to push_bytes() after decoder errored")
                }
            }

            // If the above failed, end the current decoder and go to the next state.
            match core::mem::replace(&mut self.stage, DecoderStage::Errored) {
                DecoderStage::Magic(decoder) => {
                    let magic = decoder.end().expect("magic ready after push_bytes");
                    if magic != *PSBT_MAGIC {
                        return Err(DeserializeError::InvalidMagic(magic));
                    }
                    self.stage = DecoderStage::Separator;
                }
                DecoderStage::Separator => {
                    let sep = bytes[0];
                    *bytes = &bytes[1..];
                    if sep != PSBT_SEPARATOR {
                        return Err(DeserializeError::InvalidSeparator(Some(sep)));
                    }
                    self.stage = DecoderStage::Global(global::GlobalDecoder::default());
                }
                DecoderStage::Global(decoder) => {
                    let global = decoder.end()?;
                    let input_count = global.input_count;
                    self.stage =
                        DecoderStage::Inputs(global, input::InputsDecoder::new(input_count));
                }
                DecoderStage::Inputs(global, decoder) => {
                    let inputs = decoder.end().map_err(DeserializeError::DecodeInputs)?;
                    let output_count = global.output_count;
                    self.stage = DecoderStage::Outputs(
                        global,
                        inputs,
                        output::OutputsDecoder::new(output_count),
                    );
                }
                DecoderStage::Outputs(global, inputs, decoder) => {
                    let outputs = decoder.end().map_err(DeserializeError::DecodeOutputs)?;
                    self.stage = DecoderStage::Done(Psbt { global, inputs, outputs });
                }
                DecoderStage::Done(..) => return Ok(DecoderStatus::Ready),
                DecoderStage::Errored => unreachable!("checked above"),
            }
        }
    }

    fn end(self) -> Result<Psbt, Self::Error> {
        match self.stage {
            DecoderStage::Done(psbt) => Ok(psbt),
            DecoderStage::Magic(_) => Err(DeserializeError::EarlyEnd("magic")),
            DecoderStage::Separator => Err(DeserializeError::EarlyEnd("separator")),
            DecoderStage::Global(_) => Err(DeserializeError::EarlyEnd("global")),
            DecoderStage::Inputs(..) => Err(DeserializeError::EarlyEnd("inputs")),
            DecoderStage::Outputs(..) => Err(DeserializeError::EarlyEnd("outputs")),
            DecoderStage::Errored => panic!("PsbtV2Decoder ended in Errored state"),
        }
    }

    fn read_limit(&self) -> usize {
        match &self.stage {
            DecoderStage::Magic(magic) => magic.read_limit(),
            DecoderStage::Separator => 1,
            DecoderStage::Global(dec) => dec.read_limit(),
            DecoderStage::Inputs(_, dec) => dec.read_limit(),
            DecoderStage::Outputs(_, _, dec) => dec.read_limit(),
            DecoderStage::Done(_) | DecoderStage::Errored => 0,
        }
    }
}

impl Default for PsbtV2Decoder {
    fn default() -> Self { Self { stage: DecoderStage::Magic(ArrayDecoder::default()) } }
}

impl PsbtDecode for Psbt {
    type Decoder = PsbtV2Decoder;
}

/// Combines these two PSBTs as described by BIP-174 (i.e. combine is the same for BIP-370).
///
/// This function is commutative `combine(this, that) = combine(that, this)`.
pub fn combine(this: Psbt, that: Psbt) -> Result<Psbt, CombineError> { this.combine_with(that) }
// TODO: Consider adding an iterator API that combines a list of PSBTs.

/// Implements the BIP-370 Creator role.
///
/// The `Creator` type is only directly needed if one of the following holds:
///
/// - The creator and constructor are separate entities.
/// - You need to set the fallback lock time.
/// - You need to set the sighash single flag.
///
/// If not use the [`Constructor`]  to carry out both roles e.g., `Constructor::<Modifiable>::default()`.
///
/// See `examples/v2-separate-creator-constructor.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Creator(Psbt);

impl Creator {
    /// Creates a new PSBT Creator.
    pub fn new() -> Self {
        let psbt = Psbt {
            global: Global::default(),
            inputs: Default::default(),
            outputs: Default::default(),
        };
        Self(psbt)
    }

    /// Sets the fallback lock time.
    pub fn fallback_lock_time(mut self, fallback: absolute::LockTime) -> Self {
        self.0.global.fallback_lock_time = Some(fallback);
        self
    }

    /// Sets the "has sighash single" flag in then transaction modifiable flags.
    pub fn sighash_single(mut self) -> Self {
        self.0.global.set_sighash_single_flag();
        self
    }

    /// Sets the inputs modifiable bit in the transaction modifiable flags.
    pub fn inputs_modifiable(mut self) -> Self {
        self.0.global.set_inputs_modifiable_flag();
        self
    }

    /// Sets the outputs modifiable bit in the transaction modifiable flags.
    pub fn outputs_modifiable(mut self) -> Self {
        self.0.global.set_outputs_modifiable_flag();
        self
    }

    /// Sets the transaction version.
    ///
    /// You likely do not need this, it is provided for completeness.
    ///
    /// The default is [`transaction::Version::TWO`].
    pub fn transaction_version(mut self, version: transaction::Version) -> Self {
        self.0.global.tx_version = version;
        self
    }

    /// Builds a [`Constructor`] that can add inputs and outputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::psbt::{Creator, Constructor, Modifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .outputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<Modifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<Modifiable>::default();
    /// ```
    pub fn constructor_modifiable(self) -> Constructor<Modifiable> {
        let mut psbt = self.0;
        psbt.global.set_inputs_modifiable_flag();
        psbt.global.set_outputs_modifiable_flag();
        Constructor(psbt, PhantomData)
    }

    /// Builds a [`Constructor`] that can only add inputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::psbt::{Creator, Constructor, InputsOnlyModifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<InputsOnlyModifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_inputs_only_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<InputsOnlyModifiable>::default();
    /// ```
    pub fn constructor_inputs_only_modifiable(self) -> Constructor<InputsOnlyModifiable> {
        let mut psbt = self.0;
        psbt.global.set_inputs_modifiable_flag();
        psbt.global.clear_outputs_modifiable_flag();
        Constructor(psbt, PhantomData)
    }

    /// Builds a [`Constructor`] that can only add outputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use psbt_v2::psbt::{Creator, Constructor, OutputsOnlyModifiable};
    ///
    /// // Creator role separate from Constructor role.
    /// let psbt = Creator::new()
    ///     .inputs_modifiable()
    ///     .psbt();
    /// let _constructor = Constructor::<OutputsOnlyModifiable>::new(psbt);
    ///
    /// // However, since a single entity is likely to be both a Creator and Constructor.
    /// let _constructor = Creator::new().constructor_outputs_only_modifiable();
    ///
    /// // Or the more terse:
    /// let _constructor = Constructor::<OutputsOnlyModifiable>::default();
    /// ```
    pub fn constructor_outputs_only_modifiable(self) -> Constructor<OutputsOnlyModifiable> {
        let mut psbt = self.0;
        psbt.global.clear_inputs_modifiable_flag();
        psbt.global.set_outputs_modifiable_flag();
        Constructor(psbt, PhantomData)
    }

    /// Returns the created [`Psbt`].
    ///
    /// This is only required if the Creator and Constructor are separate entities. If the Creator
    /// is also acting as the Constructor use one of the `Self::constructor_foo` functions.
    pub fn psbt(self) -> Psbt { self.0 }
}

impl Default for Creator {
    fn default() -> Self { Self::new() }
}

/// Marker for a `Constructor` with both inputs and outputs modifiable.
pub enum Modifiable {}
/// Marker for a `Constructor` with inputs modifiable.
pub enum InputsOnlyModifiable {}
/// Marker for a `Constructor` with outputs modifiable.
pub enum OutputsOnlyModifiable {}

mod sealed {
    pub trait Mod {}
    impl Mod for super::Modifiable {}
    impl Mod for super::InputsOnlyModifiable {}
    impl Mod for super::OutputsOnlyModifiable {}
}

/// Marker for if either inputs or outputs are modifiable, or both.
pub trait Mod: sealed::Mod + Sync + Send + Sized + Unpin {}

impl Mod for Modifiable {}
impl Mod for InputsOnlyModifiable {}
impl Mod for OutputsOnlyModifiable {}

/// Implements the BIP-370 Constructor role.
///
/// Uses the builder pattern, and generics to make adding inputs and outputs infallible.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Constructor<T>(Psbt, PhantomData<T>);

impl<T: Mod> Constructor<T> {
    /// Marks that the `Psbt` can not have any more inputs added to it.
    pub fn no_more_inputs(mut self) -> Self {
        self.0.global.clear_inputs_modifiable_flag();
        self
    }

    /// Marks that the `Psbt` can not have any more outputs added to it.
    pub fn no_more_outputs(mut self) -> Self {
        self.0.global.clear_outputs_modifiable_flag();
        self
    }

    /// Returns a PSBT [`Updater`] once construction is completed.
    pub fn updater(self) -> Result<Updater, DetermineLockTimeError> {
        self.no_more_inputs().no_more_outputs().psbt().map(Updater)
    }

    /// Returns the [`Psbt`] in its current state.
    ///
    /// This function can be used either to get the [`Psbt`] to pass to another constructor or to
    /// get the [`Psbt`] ready for update if `no_more_inputs` and `no_more_outputs` have already
    /// explicitly been called.
    pub fn psbt(self) -> Result<Psbt, DetermineLockTimeError> {
        let _ = self.0.determine_lock_time()?;
        Ok(self.0)
    }
}

impl Constructor<Modifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, PsbtNotModifiableError> {
        if !psbt.global.is_inputs_modifiable() {
            Err(InputsNotModifiableError.into())
        } else if !psbt.global.is_outputs_modifiable() {
            Err(OutputsNotModifiableError.into())
        } else {
            Ok(Self(psbt, PhantomData))
        }
    }

    /// Adds an input to the PSBT.
    pub fn input(mut self, input: Input) -> Self {
        self.0.inputs.push(input);
        self.0.global.input_count += 1;
        self
    }

    /// Adds an output to the PSBT.
    ///
    /// # Errors
    ///
    /// If `output` breaks the BIP-370 and BIP-375 output rules, see [`Output::validate`].
    pub fn output(mut self, output: Output) -> Result<Self, output::ValidationError> {
        output.validate()?;
        self.0.outputs.push(output);
        self.0.global.output_count += 1;
        Ok(self)
    }
}
// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<Modifiable> {
    fn default() -> Self { Creator::new().constructor_modifiable() }
}

impl Constructor<InputsOnlyModifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, InputsNotModifiableError> {
        if psbt.global.is_inputs_modifiable() {
            Ok(Self(psbt, PhantomData))
        } else {
            Err(InputsNotModifiableError)
        }
    }

    /// Adds an input to the PSBT.
    pub fn input(mut self, input: Input) -> Self {
        self.0.inputs.push(input);
        self.0.global.input_count += 1;
        self
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<InputsOnlyModifiable> {
    fn default() -> Self { Creator::new().constructor_inputs_only_modifiable() }
}

impl Constructor<OutputsOnlyModifiable> {
    /// Creates a new Constructor.
    ///
    /// This function should only be needed if the PSBT Creator and Constructor roles are being
    /// performed by separate entities, if not use one of the builder functions on the [`Creator`]
    /// e.g., `constructor_modifiable()`.
    pub fn new(psbt: Psbt) -> Result<Self, OutputsNotModifiableError> {
        if psbt.global.is_outputs_modifiable() {
            Ok(Self(psbt, PhantomData))
        } else {
            Err(OutputsNotModifiableError)
        }
    }

    /// Adds an output to the PSBT.
    ///
    /// # Errors
    ///
    /// If `output` breaks the BIP-370 and BIP-375 output rules, see [`Output::validate`].
    pub fn output(mut self, output: Output) -> Result<Self, output::ValidationError> {
        output.validate()?;
        self.0.outputs.push(output);
        self.0.global.output_count += 1;
        Ok(self)
    }
}

// Useful if the Creator and Constructor are a single entity.
impl Default for Constructor<OutputsOnlyModifiable> {
    fn default() -> Self { Creator::new().constructor_outputs_only_modifiable() }
}

/// Implements the BIP-370 Updater role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Updater(Psbt);

impl Updater {
    /// Creates an `Updater`.
    ///
    /// An updater can only update a PSBT that has a valid combination of lock times.
    pub fn new(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let _ = psbt.determine_lock_time()?;
        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Txid {
        self.0.id().expect("Updater guarantees lock time can be determined")
    }

    /// Updater role, update the sequence number for input at `index`.
    pub fn set_sequence(
        mut self,
        n: Sequence,
        input_index: usize,
    ) -> Result<Self, IndexOutOfBoundsError> {
        let input = self.0.checked_input_mut(input_index)?;
        input.sequence = Some(n);
        Ok(self)
    }

    /// Returns the inner [`Psbt`].
    pub fn psbt(self) -> Psbt { self.0 }
}

impl TryFrom<Psbt> for Updater {
    type Error = DetermineLockTimeError;

    fn try_from(psbt: Psbt) -> Result<Self, Self::Error> { Self::new(psbt) }
}

/// Implements the BIP-370 Signer role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Signer(Psbt);

impl Signer {
    /// Creates a `Signer`.
    ///
    /// An updater can only update a PSBT that has a valid combination of lock times.
    pub fn new(psbt: Psbt) -> Result<Self, DetermineLockTimeError> {
        let _ = psbt.determine_lock_time()?;
        Ok(Self(psbt))
    }

    /// Returns this PSBT's unique identification.
    pub fn id(&self) -> Result<Txid, DetermineLockTimeError> { self.0.id() }

    /// Creates an unsigned transaction from the inner [`Psbt`].
    pub fn unsigned_tx(&self) -> Transaction {
        self.0.unsigned_tx().expect("Signer guarantees lock time can be determined")
    }

    /// Attempts to create _all_ the required signatures for this PSBT using `k`.
    ///
    /// **NOTE**: Taproot inputs are, as yet, not supported by this function. We currently only
    /// attempt to sign ECDSA inputs.
    ///
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa`. This
    /// function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// Either Ok(SigningKeys) or Err((SigningKeys, SigningErrors)), where
    /// - SigningKeys: A map of input index -> pubkey associated with secret key used to sign.
    /// - SigningKeys: A map of input index -> the error encountered while attempting to sign.
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    pub fn sign<C, K>(
        self,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<(Psbt, SigningKeys), (SigningKeys, SigningErrors)>
    where
        C: Signing,
        K: GetKey,
    {
        let tx = self.unsigned_tx();
        let mut psbt = self.psbt();

        psbt.sign(tx, k, secp).map(|signing_keys| (psbt, signing_keys))
    }

    /// Sets the PSBT_GLOBAL_TX_MODIFIABLE as required after signing an ECDSA input.
    ///
    /// > For PSBTv2s, a signer must update the PSBT_GLOBAL_TX_MODIFIABLE field after signing
    /// > inputs so that it accurately reflects the state of the PSBT.
    pub fn ecdsa_clear_tx_modifiable(&mut self, ty: EcdsaSighashType) {
        self.0.clear_tx_modifiable(ty as u8)
    }

    /// Returns the inner [`Psbt`].
    pub fn psbt(self) -> Psbt { self.0 }
}

/// A Partially Signed Transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Psbt {
    /// The global map.
    pub global: Global,
    /// The corresponding key-value map for each input in the unsigned transaction.
    pub inputs: Vec<Input>,
    /// The corresponding key-value map for each output in the unsigned transaction.
    pub outputs: Vec<Output>,
}

impl Psbt {
    // TODO: Add inherent methods to get each of the role types.

    /// Returns this PSBT's unique identification.
    pub(crate) fn id(&self) -> Result<Txid, DetermineLockTimeError> {
        let mut tx = self.unsigned_tx()?;
        // Updaters may change the sequence so to calculate ID we set it to zero.
        tx.input.iter_mut().for_each(|input| input.sequence = Sequence::ZERO);

        Ok(tx.compute_txid())
    }

    /// Creates an unsigned transaction from the inner [`Psbt`].
    ///
    /// Quidado! this transaction should not be used to determine the ID of
    /// the [`Pbst`], use `Self::id()` instead.
    pub(crate) fn unsigned_tx(&self) -> Result<Transaction, DetermineLockTimeError> {
        let lock_time = self.determine_lock_time()?;

        Ok(Transaction {
            version: self.global.tx_version,
            lock_time,
            input: self.inputs.iter().map(|input| input.unsigned_tx_in()).collect(),
            output: self.outputs.iter().map(|ouput| ouput.tx_out()).collect(),
        })
    }

    /// Determines the lock time as specified in [BIP-370] if it is possible to do so.
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time>
    pub fn determine_lock_time(&self) -> Result<absolute::LockTime, DetermineLockTimeError> {
        let require_time_based_lock_time =
            self.inputs.iter().any(|input| input.requires_time_based_lock_time());
        let require_height_based_lock_time =
            self.inputs.iter().any(|input| input.requires_height_based_lock_time());

        if require_time_based_lock_time && require_height_based_lock_time {
            return Err(DetermineLockTimeError);
        }

        let have_lock_time = self.inputs.iter().any(|input| input.has_lock_time());

        let lock = if have_lock_time {
            let all_inputs_satisfied_with_height_based_lock_time =
                self.inputs.iter().all(|input| input.is_satisfied_with_height_based_lock_time());

            // > The lock time chosen is then the maximum value of the chosen type of lock time.
            if all_inputs_satisfied_with_height_based_lock_time {
                // We either have only height based or we have both, in which case we must use height based.
                let height = self
                    .inputs
                    .iter()
                    .map(|input| input.min_height)
                    .max()
                    .expect("we know we have at least one non-none min_height field")
                    .expect("so we know that max is non-none");
                absolute::LockTime::from(height)
            } else {
                let time = self
                    .inputs
                    .iter()
                    .map(|input| input.min_time)
                    .max()
                    .expect("we know we have at least one non-none min_height field")
                    .expect("so we know that max is non-none");
                absolute::LockTime::from(time)
            }
        } else {
            // > If none of the inputs have a PSBT_IN_REQUIRED_TIME_LOCKTIME and
            // > PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, then PSBT_GLOBAL_FALLBACK_LOCKTIME must be used.
            // > If PSBT_GLOBAL_FALLBACK_LOCKTIME is not provided, then it is assumed to be 0.
            self.global.fallback_lock_time.unwrap_or(absolute::LockTime::ZERO)
        };

        Ok(lock)
    }

    /// Returns true if all inputs for this PSBT have been finalized.
    pub fn is_finalized(&self) -> bool { self.inputs.iter().all(|input| input.is_finalized()) }

    /// Serializes a value as bytes in hex.
    pub fn serialize_hex(&self) -> String { self.serialize().to_lower_hex_string() }

    /// Serializes as raw binary data
    pub fn serialize(&self) -> Vec<u8> { encode_to_vec(self) }

    /// Deserializes a value from raw binary data.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DeserializeError> {
        let mut remaining = bytes;
        crate::encoding::decode_from_slice_unbounded::<Self>(&mut remaining)
    }

    /// Returns an iterator for the funding UTXOs of the psbt
    ///
    /// For each PSBT input that contains UTXO information `Ok` is returned containing that information.
    /// The order of returned items is same as the order of inputs.
    ///
    /// ## Errors
    ///
    /// The function returns error when UTXO information is not present or is invalid.
    pub fn iter_funding_utxos(&self) -> impl Iterator<Item = Result<&TxOut, FundingUtxoError>> {
        self.inputs.iter().map(|input| input.funding_utxo())
    }

    /// Combines this [`Psbt`] with `other` PSBT as described by BIP-174.
    ///
    /// BIP-370 does not include any additional requirements for the Combiner role.
    ///
    /// This function is commutative `A.combine_with(B) = B.combine_with(A)`.
    ///
    /// See [`combine()`] for a non-consuming version of this function.
    pub fn combine_with(mut self, other: Self) -> Result<Self, CombineError> {
        self.global.combine(other.global)?;

        for (self_input, other_input) in self.inputs.iter_mut().zip(other.inputs) {
            self_input.combine(other_input)?;
        }

        for (self_output, other_output) in self.outputs.iter_mut().zip(other.outputs) {
            self_output.combine(other_output)?;
        }

        Ok(self)
    }

    /// Sets the PSBT_GLOBAL_TX_MODIFIABLE as required after signing.
    // TODO: Consider using consts instead of magic numbers.
    fn clear_tx_modifiable(&mut self, sighash_type: u8) {
        let ty = sighash_type;
        // If the Signer added a signature that does not use SIGHASH_ANYONECANPAY,
        // the Input Modifiable flag must be set to False.
        if !(ty == 0x81 || ty == 0x82 || ty == 0x83) {
            self.global.clear_inputs_modifiable_flag();
        }

        // If the Signer added a signature that does not use SIGHASH_NONE,
        // the Outputs Modifiable flag must be set to False.
        if !(ty == 0x02 || ty == 0x82) {
            self.global.clear_outputs_modifiable_flag();
        }

        // If the Signer added a signature that uses SIGHASH_SINGLE,
        // the Has SIGHASH_SINGLE flag must be set to True.
        if ty == 0x03 || ty == 0x83 {
            self.global.set_sighash_single_flag();
        }
    }

    /// Performs the BIP-174 signer validity checks for the input at `index`.
    fn signer_checks(&self, index: usize) -> Result<(), SignError> {
        self.check_input_index(index)?;
        let input = &self.inputs[index];
        let prevout_type = self.output_type(index);
        let prevout = input.funding_utxo()?;

        // If a witness UTXO is provided, no non-witness signature may be created.
        if input.witness_utxo.is_some() {
            if let Ok(OutputType::Bare) = prevout_type {
                return Err(SignError::NonWitnessSig);
            }
        }

        // If a non-witness UTXO is provided, its hash must match the prevout txid.
        if let Some(ref tx) = input.non_witness_utxo {
            if tx.compute_txid() != input.previous_txid {
                return Err(SignError::NonWitnessUtxoTxidMismatch);
            }
        }

        // If a redeemScript is provided, the scriptPubKey must be for that redeemScript.
        if let Some(ref redeem_script) = input.redeem_script {
            let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
            if prevout.script_pubkey != script_pubkey {
                return Err(SignError::RedeemScriptMismatch);
            }
        }

        // If a witnessScript is provided the redeemScript must be for that witnessScript, and the
        // scriptPubKey must be for that witnessScript.
        if let Some(ref witness_script) = input.witness_script {
            match prevout_type {
                Ok(OutputType::Wsh)
                    if ScriptBuf::new_p2wsh(&witness_script.wscript_hash())
                        != *prevout.script_pubkey =>
                {
                    return Err(SignError::WitnessScriptMismatchWsh);
                }
                Ok(OutputType::ShWsh) =>
                    if let Some(ref redeem_script) = input.redeem_script {
                        if ScriptBuf::new_p2wsh(&witness_script.wscript_hash()) != *redeem_script
                            || ScriptBuf::new_p2sh(&redeem_script.script_hash())
                                != *prevout.script_pubkey
                        {
                            return Err(SignError::WitnessScriptMismatchShWsh);
                        }
                    },
                _ => (),
            }
        }

        // Use provided sighash or DEFAULT for taproot output and ALL for non-taproot outputs.
        let expected_sighash_type = match (input.sighash_type, prevout_type) {
            (None, Ok(OutputType::Tr)) => PsbtSighashType::from(TapSighashType::Default),
            (None, _) => PsbtSighashType::ALL,
            (Some(sighash_type), _) => sighash_type,
        };

        let sighash_mismatches = |sighash: PsbtSighashType| sighash != expected_sighash_type;

        let has_mismatch = input
            .tap_key_sig
            .is_some_and(|sig| sighash_mismatches(PsbtSighashType::from(sig.sighash_type)))
            || input
                .tap_script_sigs
                .values()
                .any(|sig| sighash_mismatches(PsbtSighashType::from(sig.sighash_type)))
            || input
                .partial_sigs
                .values()
                .any(|sig| sighash_mismatches(PsbtSighashType::from(sig.sighash_type)));

        if has_mismatch {
            return Err(SignError::SighashMismatch);
        }

        Ok(())
    }

    /// Attempts to create _all_ the required signatures for this PSBT using `k`.
    ///
    /// **NOTE**: Taproot inputs are, as yet, not supported by this function. We currently only
    /// attempt to sign ECDSA inputs.
    ///
    /// If you just want to sign an input with one specific key consider using `sighash_ecdsa`. This
    /// function does not support scripts that contain `OP_CODESEPARATOR`.
    ///
    /// # Returns
    ///
    /// Either Ok(SigningKeys) or Err((SigningKeys, SigningErrors)), where
    /// - SigningKeys: A map of input index -> pubkey associated with secret key used to sign.
    /// - SigningKeys: A map of input index -> the error encountered while attempting to sign.
    ///
    /// If an error is returned some signatures may already have been added to the PSBT. Since
    /// `partial_sigs` is a [`BTreeMap`] it is safe to retry, previous sigs will be overwritten.
    fn sign<C, K>(
        &mut self,
        tx: Transaction,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<SigningKeys, (SigningKeys, SigningErrors)>
    where
        C: Signing,
        K: GetKey,
    {
        let mut cache = SighashCache::new(&tx);

        let mut used = BTreeMap::new();
        let mut errors = BTreeMap::new();

        // Check all inputs before providing any signature (BIP-174).
        for i in 0..self.global.input_count {
            if let Err(e) = self.signer_checks(i) {
                errors.insert(i, e);
            }
        }

        if !errors.is_empty() {
            return Err((used, errors));
        }

        for i in 0..self.global.input_count {
            if let Ok(SigningAlgorithm::Ecdsa) = self.signing_algorithm(i) {
                match self.bip32_sign_ecdsa(k, i, &mut cache, secp) {
                    Ok(v) => {
                        used.insert(i, v);
                    }
                    Err(e) => {
                        errors.insert(i, e);
                    }
                }
            };
        }
        if errors.is_empty() {
            Ok(used)
        } else {
            Err((used, errors))
        }
    }

    /// Attempts to create all signatures required by this PSBT's `bip32_derivation` field, adding
    /// them to `partial_sigs`.
    ///
    /// # Returns
    ///
    /// - Ok: A list of the public keys used in signing.
    /// - Err: Error encountered trying to calculate the sighash AND we had the signing key.
    fn bip32_sign_ecdsa<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<PublicKey>, SignError>
    where
        C: Signing,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let msg_sighash_ty_res = self.sighash_ecdsa(input_index, cache);
        let sighash_ty = msg_sighash_ty_res.clone().ok().map(|(_msg, sighash_ty)| sighash_ty);

        let input = &mut self.inputs[input_index]; // Index checked in call to `sighash_ecdsa`.
        let mut used = vec![]; // List of pubkeys used to sign the input.

        for (pk, key_source) in input.bip32_derivations.iter() {
            let sk = if let Ok(Some(sk)) = k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) = k.get_key(KeyRequest::Pubkey(*pk), secp) {
                sk
            } else {
                continue;
            };

            // Only return the error if we have a secret key to sign this input.
            let (msg, sighash_ty) = match msg_sighash_ty_res {
                Err(e) => return Err(e),
                Ok((msg, sighash_ty)) => (msg, sighash_ty),
            };

            let sig = ecdsa::Signature {
                signature: secp.sign_ecdsa(&msg, &sk.inner),
                sighash_type: sighash_ty,
            };

            let pk = sk.public_key(secp);

            input.partial_sigs.insert(pk, sig);
            used.push(pk);
        }

        let ty = sighash_ty.expect("at this stage we know its ok");
        self.clear_tx_modifiable(ty as u8);

        Ok(used)
    }

    /// Returns the sighash message to sign an ECDSA input along with the sighash type.
    ///
    /// Uses the [`EcdsaSighashType`] from this input if one is specified. If no sighash type is
    /// specified uses [`EcdsaSighashType::All`]. This function does not support scripts that
    /// contain `OP_CODESEPARATOR`.
    pub fn sighash_ecdsa<T: Borrow<Transaction>>(
        &self,
        input_index: usize,
        cache: &mut SighashCache<T>,
    ) -> Result<(Message, EcdsaSighashType), SignError> {
        if self.signing_algorithm(input_index)? != SigningAlgorithm::Ecdsa {
            return Err(SignError::WrongSigningAlgorithm);
        }

        let input = self.checked_input(input_index)?;
        let utxo = input.funding_utxo()?;
        let spk = &utxo.script_pubkey; // scriptPubkey for input spend utxo.

        let hash_ty = input.ecdsa_hash_ty().map_err(|_| SignError::InvalidSighashType)?; // Only support standard sighash types.

        match self.output_type(input_index)? {
            OutputType::Bare => {
                let sighash = cache
                    .legacy_signature_hash(input_index, spk, hash_ty.to_u32())
                    .expect("input checked above");
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::Sh => {
                let script_code =
                    input.redeem_script.as_ref().ok_or(SignError::MissingRedeemScript)?;
                let sighash = cache
                    .legacy_signature_hash(input_index, script_code, hash_ty.to_u32())
                    .expect("input checked above");
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::Wpkh => {
                let sighash = cache.p2wpkh_signature_hash(input_index, spk, utxo.value, hash_ty)?;
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::ShWpkh => {
                let redeem_script = input.redeem_script.as_ref().expect("checked above");
                let sighash =
                    cache.p2wpkh_signature_hash(input_index, redeem_script, utxo.value, hash_ty)?;
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::Wsh | OutputType::ShWsh => {
                let witness_script =
                    input.witness_script.as_ref().ok_or(SignError::MissingWitnessScript)?;
                let sighash = cache
                    .p2wsh_signature_hash(input_index, witness_script, utxo.value, hash_ty)
                    .map_err(SignError::SegwitV0Sighash)?;
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::Tr => {
                // This PSBT signing API is WIP, taproot to come shortly.
                Err(SignError::Unsupported)
            }
        }
    }

    /// Gets a reference to the input at `input_index` after checking that it is a valid index.
    fn checked_input(&self, index: usize) -> Result<&Input, IndexOutOfBoundsError> {
        self.check_input_index(index)?;
        Ok(&self.inputs[index])
    }

    /// Gets a mutable reference to the input at `input_index` after checking that it is a valid index.
    fn checked_input_mut(&mut self, index: usize) -> Result<&mut Input, IndexOutOfBoundsError> {
        self.check_input_index(index)?;
        Ok(&mut self.inputs[index])
    }
    /// Checks that `index` is valid for this PSBT.
    fn check_input_index(&self, index: usize) -> Result<(), IndexOutOfBoundsError> {
        if index >= self.inputs.len() {
            return Err(IndexOutOfBoundsError::Inputs { index, length: self.inputs.len() });
        }
        if index >= self.global.input_count {
            return Err(IndexOutOfBoundsError::Count { index, count: self.global.input_count });
        }
        Ok(())
    }

    /// Returns the algorithm used to sign this PSBT's input at `input_index`.
    fn signing_algorithm(&self, input_index: usize) -> Result<SigningAlgorithm, SignError> {
        let output_type = self.output_type(input_index)?;
        Ok(output_type.signing_algorithm())
    }

    /// Returns the [`OutputType`] of the spend utxo for this PSBT's input at `input_index`.
    fn output_type(&self, input_index: usize) -> Result<OutputType, SignError> {
        let input = self.checked_input(input_index)?;
        let utxo = input.funding_utxo()?;
        let spk = utxo.script_pubkey.clone();

        // Anything that is not segwit and is not p2sh is `Bare`.
        if !(spk.is_witness_program() || spk.is_p2sh()) {
            return Ok(OutputType::Bare);
        }

        if spk.is_p2wpkh() {
            return Ok(OutputType::Wpkh);
        }

        if spk.is_p2wsh() {
            return Ok(OutputType::Wsh);
        }

        if spk.is_p2sh() {
            if input.redeem_script.as_ref().map(|s| s.is_p2wpkh()).unwrap_or(false) {
                return Ok(OutputType::ShWpkh);
            }
            if input.redeem_script.as_ref().map(|x| x.is_p2wsh()).unwrap_or(false) {
                return Ok(OutputType::ShWsh);
            }
            return Ok(OutputType::Sh);
        }

        if spk.is_p2tr() {
            return Ok(OutputType::Tr);
        }

        // Something is wrong with the input scriptPubkey or we do not know how to sign
        // because there has been a new softfork that we do not yet support.
        Err(SignError::UnknownOutputType)
    }

    /// Calculates transaction fee.
    ///
    /// 'Fee' being the amount that will be paid for mining a transaction with the current inputs
    /// and outputs i.e., the difference in value of the total inputs and the total outputs.
    pub fn fee(&self) -> Result<Amount, FeeError> {
        // For the inputs we have to get the value from the input UTXOs.
        let mut input_value: u64 = 0;
        for input in self.iter_funding_utxos() {
            input_value =
                input_value.checked_add(input?.value.to_sat()).ok_or(FeeError::InputOverflow)?;
        }
        // For the outputs we have the value directly in the `Output`.
        let mut output_value: u64 = 0;
        for output in &self.outputs {
            output_value =
                output_value.checked_add(output.amount.to_sat()).ok_or(FeeError::OutputOverflow)?;
        }

        input_value.checked_sub(output_value).map(Amount::from_sat).ok_or(FeeError::Negative)
    }

    /// Checks the sighash types of input partial sigs (ECDSA).
    ///
    /// This can be used at anytime but is primarily used during PSBT finalizing.
    #[cfg(feature = "miniscript")]
    pub(crate) fn check_partial_sigs_sighash_type(
        &self,
    ) -> Result<(), PartialSigsSighashTypeError> {
        for (input_index, input) in self.inputs.iter().enumerate() {
            let target_ecdsa_sighash_ty = match input.sighash_type {
                Some(psbt_hash_ty) => psbt_hash_ty.ecdsa_hash_ty().map_err(|error| {
                    PartialSigsSighashTypeError::NonStandardInputSighashType { input_index, error }
                })?,
                None => EcdsaSighashType::All,
            };

            for (key, ecdsa_sig) in &input.partial_sigs {
                let flag = EcdsaSighashType::from_standard(ecdsa_sig.sighash_type as u32).map_err(
                    |error| PartialSigsSighashTypeError::NonStandardPartialSigsSighashType {
                        input_index,
                        error,
                    },
                )?;
                if target_ecdsa_sighash_ty != flag {
                    return Err(PartialSigsSighashTypeError::WrongSighashFlag {
                        input_index,
                        required: target_ecdsa_sighash_ty,
                        got: flag,
                        pubkey: *key,
                    });
                }
            }
        }
        Ok(())
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
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error>;
}

impl GetKey for Xpriv {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                let key = if self.fingerprint(secp) == fingerprint {
                    let k = self.derive_priv(secp, &path)?;
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
        key_request: KeyRequest,
        secp: &Secp256k1<C>
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(_) => Err(GetKeyError::NotSupported),
            KeyRequest::Bip32((fingerprint, path)) => {
                for xpriv in self.iter() {
                    if xpriv.parent_fingerprint == fingerprint {
                        let k = xpriv.derive_priv(secp, &path)?;
                        return Ok(Some(k.to_priv()));
                    }
                }
                Ok(None)
            }
        }
    }
}}}

impl_get_key_for_set!(Vec);
impl_get_key_for_set!(BTreeSet);
#[cfg(feature = "std")]
impl_get_key_for_set!(HashSet);

#[rustfmt::skip]
macro_rules! impl_get_key_for_map {
    ($map:ident) => {

impl GetKey for $map<PublicKey, PrivateKey> {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        _: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            KeyRequest::Pubkey(pk) => Ok(self.get(&pk).cloned()),
            KeyRequest::Bip32(_) => Err(GetKeyError::NotSupported),
        }
    }
}}}
impl_get_key_for_map!(BTreeMap);
#[cfg(feature = "std")]
impl_get_key_for_map!(HashMap);

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

/// The various output types supported by the Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OutputType {
    /// An output of type: pay-to-pubkey or pay-to-pubkey-hash.
    Bare,
    /// A pay-to-witness-pubkey-hash output (P2WPKH).
    Wpkh,
    /// A pay-to-witness-script-hash output (P2WSH).
    Wsh,
    /// A nested segwit output, pay-to-witness-pubkey-hash nested in a pay-to-script-hash.
    ShWpkh,
    /// A nested segwit output, pay-to-witness-script-hash nested in a pay-to-script-hash.
    ShWsh,
    /// A pay-to-script-hash output excluding wrapped segwit (P2SH).
    Sh,
    /// A taproot output (P2TR).
    Tr,
}

impl OutputType {
    /// The signing algorithm used to sign this output type.
    pub fn signing_algorithm(&self) -> SigningAlgorithm {
        match self {
            Self::Bare | Self::Wpkh | Self::Wsh | Self::ShWpkh | Self::ShWsh | Self::Sh =>
                SigningAlgorithm::Ecdsa,
            Self::Tr => SigningAlgorithm::Schnorr,
        }
    }
}

/// Signing algorithms supported by the Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningAlgorithm {
    /// The Elliptic Curve Digital Signature Algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    Ecdsa,
    /// The Schnorr signature algorithm (see [wikipedia]).
    ///
    /// [wikipedia]: https://en.wikipedia.org/wiki/Schnorr_signature
    Schnorr,
}

/// An error occurred while decoding a v2 PSBT.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
    /// Magic bytes for a PSBT must be the ASCII for "psbt" serialized in most
    /// significant byte order.
    InvalidMagic,
    /// The separator for a PSBT must be `0xff`.
    InvalidSeparator,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Error decoding global map.
    Global(global::DecodeError),
    /// Error decoding input map.
    Input(input::DecodeError),
    /// Error decoding output map.
    Output(output::DecodeError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("invalid magic"),
            Self::InvalidSeparator => f.write_str("invalid separator"),
            Self::NoMorePairs => f.write_str("no more key-value pairs for this psbt map"),
            Self::Global(ref e) => write_err!(f, "global map decode error"; e),
            Self::Input(ref e) => write_err!(f, "input map decode error"; e),
            Self::Output(ref e) => write_err!(f, "output map decode error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidMagic | Self::InvalidSeparator | Self::NoMorePairs => None,
            Self::Global(ref e) => Some(e),
            Self::Input(ref e) => Some(e),
            Self::Output(ref e) => Some(e),
        }
    }
}

impl From<global::DecodeError> for DecodeError {
    fn from(e: global::DecodeError) -> Self { Self::Global(e) }
}

impl From<input::DecodeError> for DecodeError {
    fn from(e: input::DecodeError) -> Self { Self::Input(e) }
}

impl From<output::DecodeError> for DecodeError {
    fn from(e: output::DecodeError) -> Self { Self::Output(e) }
}

/// If the "base64" feature is enabled we implement `Display` and `FromStr` using base64 encoding.
#[cfg(feature = "base64")]
mod display_from_str {
    use core::fmt;
    use core::str::FromStr;

    use bitcoin::base64::display::Base64Display;
    use bitcoin::base64::prelude::{Engine as _, BASE64_STANDARD};

    use super::*;

    impl fmt::Display for Psbt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", Base64Display::new(&self.serialize(), &BASE64_STANDARD))
        }
    }

    impl FromStr for Psbt {
        type Err = ParsePsbtError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let data = BASE64_STANDARD.decode(s).map_err(ParsePsbtError::Base64Encoding)?;
            Self::deserialize(&data).map_err(ParsePsbtError::PsbtEncoding)
        }
    }

    /// Error encountered during PSBT decoding from Base64 string.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum ParsePsbtError {
        /// Error in internal PSBT data structure.
        PsbtEncoding(DeserializeError),
        /// Error in PSBT Base64 encoding.
        Base64Encoding(bitcoin::base64::DecodeError),
    }

    impl fmt::Display for ParsePsbtError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::PsbtEncoding(ref e) =>
                    write_err!(f, "error in internal PSBT data structure"; e),
                Self::Base64Encoding(ref e) => write_err!(f, "error in PSBT base64 encoding"; e),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParsePsbtError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::PsbtEncoding(e) => Some(e),
                Self::Base64Encoding(e) => Some(e),
            }
        }
    }
}

/// Error combining two input maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CombineError {
    /// Error while combining the global maps.
    Global(global::CombineError),
    /// Error while combining the input maps.
    Input(input::CombineError),
    /// Error while combining the output maps.
    Output(output::CombineError),
}

impl fmt::Display for CombineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global(ref e) => write_err!(f, "error while combining the global maps"; e),
            Self::Input(ref e) => write_err!(f, "error while combining the input maps"; e),
            Self::Output(ref e) => write_err!(f, "error while combining the output maps"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Global(ref e) => Some(e),
            Self::Input(ref e) => Some(e),
            Self::Output(ref e) => Some(e),
        }
    }
}

impl From<global::CombineError> for CombineError {
    fn from(e: global::CombineError) -> Self { Self::Global(e) }
}

impl From<input::CombineError> for CombineError {
    fn from(e: input::CombineError) -> Self { Self::Input(e) }
}

impl From<output::CombineError> for CombineError {
    fn from(e: output::CombineError) -> Self { Self::Output(e) }
}

#[cfg(test)]
mod tests {
    use ::bitcoin::key::XOnlyPublicKey;
    use ::bitcoin::script::Builder;
    use ::bitcoin::{opcodes, taproot, OutPoint};

    use super::*;

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

    fn valid_psbt() -> Psbt {
        use crate::bitcoin::hashes::Hash as _;

        Psbt {
            global: Global { input_count: 1, output_count: 1, ..Global::default() },
            inputs: vec![Input::new(&OutPoint {
                txid: Txid::hash(b"some arbitrary bytes"),
                vout: 0x15,
            })],
            outputs: vec![Output::new(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_hex(
                    "76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac",
                )
                .unwrap(),
            })],
        }
    }

    #[test]
    fn encode_nonempty() {
        let psbt = single_input_psbt();
        let bytes = psbt.serialize();
        assert!(!bytes.is_empty());
        assert_eq!(&bytes[..5], b"psbt\xff", "must start with PSBT magic");
    }

    #[test]
    fn creator_psbt_roundtrip() {
        let psbt = Creator::new().inputs_modifiable().outputs_modifiable().psbt();
        let bytes = psbt.serialize();
        assert_eq!(&bytes[..5], b"psbt\xff");
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode creator PSBT");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn creator_psbt_inputs_modifiable_only_roundtrip() {
        let psbt = Creator::new().inputs_modifiable().psbt();
        let bytes = psbt.serialize();
        assert_eq!(&bytes[..5], b"psbt\xff");
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode creator PSBT");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn creator_psbt_outputs_modifiable_only_roundtrip() {
        let psbt = Creator::new().outputs_modifiable().psbt();
        let bytes = psbt.serialize();
        assert_eq!(&bytes[..5], b"psbt\xff");
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode creator PSBT");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn creator_psbt_no_flags_roundtrip() {
        let psbt = Creator::new().psbt();
        let bytes = psbt.serialize();
        assert_eq!(&bytes[..5], b"psbt\xff");
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode creator PSBT");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn deserialize_one_input_no_outputs() {
        use crate::bitcoin::hashes::Hash as _;
        let psbt = Psbt {
            global: Global { input_count: 1, output_count: 0, ..Global::default() },
            inputs: vec![Input::new(&OutPoint {
                txid: Txid::hash(b"some arbitrary bytes"),
                vout: 0x15,
            })],
            outputs: vec![],
        };
        let bytes = psbt.serialize();
        assert!(!bytes.is_empty());
        let decoded = Psbt::deserialize(&bytes).expect("failed to decode PSBT with 1 input");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn signer_checks_p2sh_p2wsh_valid() {
        let witness_script = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
        let redeem_script = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());

        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].redeem_script = Some(redeem_script);
        psbt.inputs[0].witness_script = Some(witness_script);

        assert_eq!(psbt.signer_checks(0), Ok(()));
    }

    #[test]
    fn signer_checks_p2sh_p2wsh_wrong_witness_script_rejected() {
        let real_witness_script = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
        let wrong_witness_script = Builder::new().push_opcode(opcodes::OP_FALSE).into_script();

        let redeem_script = ScriptBuf::new_p2wsh(&real_witness_script.wscript_hash());
        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());

        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].redeem_script = Some(redeem_script);
        psbt.inputs[0].witness_script = Some(wrong_witness_script);

        assert_eq!(psbt.signer_checks(0), Err(SignError::WitnessScriptMismatchShWsh));
    }

    #[test]
    fn signer_checks_p2wsh_valid() {
        // Native segwit: the witness script hash matches the scriptPubKey.
        let witness_script = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
        let script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());

        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].witness_script = Some(witness_script);

        assert_eq!(psbt.signer_checks(0), Ok(()));
    }

    #[test]
    fn signer_checks_p2wsh_wrong_witness_script_rejected() {
        // Native segwit: the witness script hash does not match the scriptPubKey.
        let real_witness_script = Builder::new().push_opcode(opcodes::OP_TRUE).into_script();
        let wrong_witness_script = Builder::new().push_opcode(opcodes::OP_FALSE).into_script();
        let script_pubkey = ScriptBuf::new_p2wsh(&real_witness_script.wscript_hash());

        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].witness_script = Some(wrong_witness_script);

        assert_eq!(psbt.signer_checks(0), Err(SignError::WitnessScriptMismatchWsh));
    }

    #[test]
    fn signer_checks_partial_sigs_sighash_mismatch_rejected() {
        // A partial sig whose sighash type disagrees with the input's declared sighash type.
        let pubkey = PublicKey::from_slice(&[2u8; 33]).unwrap();
        let script_pubkey = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap());
        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::ALL);
        let sig = ecdsa::Signature {
            signature: bitcoin::secp256k1::ecdsa::Signature::from_compact(&[1u8; 64]).unwrap(),
            sighash_type: EcdsaSighashType::None,
        };
        psbt.inputs[0].partial_sigs.insert(pubkey, sig);

        assert_eq!(psbt.signer_checks(0), Err(SignError::SighashMismatch));
    }

    #[test]
    fn signer_checks_non_witness_utxo_txid_mismatch_rejected() {
        // A non-witness UTXO whose txid does not match the input's previous txid.
        let funding_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() }],
        };

        // The input spends OutPoint::null() (all-zeros txid), which does not match the funding
        // transaction's txid.
        let mut psbt = single_input_psbt();
        psbt.inputs[0].spent_output_index = 0;
        psbt.inputs[0].non_witness_utxo = Some(funding_tx);

        assert_eq!(psbt.signer_checks(0), Err(SignError::NonWitnessUtxoTxidMismatch));
    }

    #[test]
    fn signer_checks_taproot_key_sig_sighash_mismatch_rejected() {
        // A taproot key sig whose sighash type disagrees with the input's declared sighash type.
        let xonly = XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let script_pubkey = ScriptBuf::new_p2tr(&Secp256k1::verification_only(), xonly, None);
        let mut psbt = single_input_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000), script_pubkey });
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::ALL);
        psbt.inputs[0].tap_key_sig = Some(taproot::Signature {
            signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&[1u8; 64]).unwrap(),
            sighash_type: TapSighashType::None,
        });

        assert_eq!(psbt.signer_checks(0), Err(SignError::SighashMismatch));
    }
    #[test]
    fn iter_funding_utxos_yields_correct_utxo() {
        let mut psbt = single_input_psbt();
        let tx_out = TxOut { value: Amount::from_sat(5_000), script_pubkey: ScriptBuf::new() };
        psbt.inputs[0].witness_utxo = Some(tx_out.clone());

        let results: Vec<_> = psbt.iter_funding_utxos().collect();
        assert_eq!(results.len(), 1, "should yield exactly one UTXO");
        let utxo = results[0].as_ref().expect("UTXO should be present");
        assert_eq!(**utxo, tx_out, "UTXO should match what was set");
    }

    #[test]
    fn iter_funding_utxos_errors_on_missing_utxo() {
        let psbt = single_input_psbt();
        let results: Vec<_> = psbt.iter_funding_utxos().collect();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err(), "missing UTXO should produce an error");
    }

    #[test]
    fn encode_decode_roundtrip_nonempty() {
        let psbt = valid_psbt();
        let bytes = psbt.serialize();
        let decoded = Psbt::deserialize(&bytes).expect("roundtrip decode failed");
        let reencoded = decoded.serialize();
        assert_eq!(bytes, reencoded);
    }

    #[test]
    fn decode_partial_magic_bytes() {
        let psbt = valid_psbt();
        let bytes = psbt.serialize();
        let mut decoder = PsbtV2Decoder::default();

        // Feed 2 bytes at a time — exercises the NeedsMore path in the Magic stage.
        let mut remaining = &bytes[..];
        loop {
            let chunk_size = 2.min(remaining.len());
            let mut chunk = &remaining[..chunk_size];
            let status = decoder.push_bytes(&mut chunk).unwrap();
            let consumed = chunk_size - chunk.len();
            remaining = &remaining[consumed..];
            if status.is_ready() {
                break;
            }
        }
        let decoded = decoder.end().unwrap();
        assert_eq!(decoded.serialize(), bytes);
    }

    #[test]
    fn read_limit_during_incremental_decode() {
        let psbt = valid_psbt();
        let bytes = psbt.serialize();
        let mut decoder = PsbtV2Decoder::default();
        let mut remaining = &bytes[..];

        // Initial read_limit should request at least one byte.
        assert!(decoder.read_limit() > 0);

        // After feeding half the magic bytes, still needs more.
        let mut chunk = &remaining[..2];
        let status = decoder.push_bytes(&mut chunk).unwrap();
        remaining = &remaining[2 - chunk.len()..];
        assert!(status.needs_more());
        assert!(decoder.read_limit() > 0);

        // After feeding the rest, the decoder should finish.
        chunk = remaining;
        let status = decoder.push_bytes(&mut chunk).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);

        let decoded = decoder.end().unwrap();
        assert_eq!(decoded.serialize(), bytes);
    }

    fn output_with_script() -> Output {
        Output::new(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from(vec![0xab; 4]),
        })
    }

    fn output_without_script() -> Output {
        Output::new(TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() })
    }

    #[test]
    fn constructor_accepts_output_with_script() {
        let constructor = Constructor::<Modifiable>::default()
            .output(output_with_script())
            .expect("output must be valid");
        assert_eq!(constructor.0.outputs.len(), 1);
        assert_eq!(constructor.0.global.output_count, 1);

        let constructor = Constructor::<OutputsOnlyModifiable>::default()
            .output(output_with_script())
            .expect("output must be valid");
        assert_eq!(constructor.0.outputs.len(), 1);
        assert_eq!(constructor.0.global.output_count, 1);
    }

    #[test]
    fn constructor_rejects_output_missing_script() {
        assert_eq!(
            Constructor::<Modifiable>::default().output(output_without_script()).err(),
            Some(output::ValidationError::MissingScriptPubkey)
        );
        assert_eq!(
            Constructor::<OutputsOnlyModifiable>::default().output(output_without_script()).err(),
            Some(output::ValidationError::MissingScriptPubkey)
        );
    }

    #[test]
    fn unique_id_is_stable_across_sequence_updates() {
        // BIP-370 requires unique identification to carry a sequence of zero because Updaters
        // and Combiners may change PSBT_IN_SEQUENCE. `Psbt::id` zeroes the sequence itself, so
        // the default applied by `Input::unsigned_tx_in` cannot affect the result.
        let baseline = valid_psbt();
        assert!(baseline.inputs[0].sequence.is_none());
        let expected = baseline.id().expect("lock time must be determinable");

        for sequence in [Sequence::ZERO, Sequence::ENABLE_LOCKTIME_NO_RBF, Sequence::MAX] {
            let mut psbt = valid_psbt();
            psbt.inputs[0].sequence = Some(sequence);
            assert_eq!(psbt.id().expect("lock time must be determinable"), expected);
        }
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn constructor_accepts_underived_silent_payment_output() {
        // BIP-375: the silent payment info stands in for the script until it is derived.
        let mut output = output_without_script();
        output.sp_v0_info = Some(vec![0; 66]);

        assert!(Constructor::<Modifiable>::default().output(output.clone()).is_ok());
        assert!(Constructor::<OutputsOnlyModifiable>::default().output(output).is_ok());
    }

    #[cfg(feature = "silent-payments")]
    #[test]
    fn constructor_rejects_silent_payment_label_without_info() {
        let mut output = output_with_script();
        output.sp_v0_label = Some(0);

        assert_eq!(
            Constructor::<Modifiable>::default().output(output).err(),
            Some(output::ValidationError::LabelWithoutInfo)
        );
    }

    /// BIP-375 represents an underived silent payment output by omitting `PSBT_OUT_SCRIPT`,
    /// so a PSBT that arrives without the field has to leave without it too. Writing it back
    /// empty is a PSBT other implementations reject.
    #[cfg(feature = "silent-payments")]
    #[test]
    fn underived_silent_payment_output_round_trips_without_out_script() {
        use ::bitcoin::hashes::Hash as _;

        use crate::consts::PSBT_OUT_SCRIPT;

        let mut output = output_without_script();
        output.sp_v0_info = Some(vec![0; 66]);

        let mut psbt = single_input_psbt();
        // An all-zeros txid and a zero output index are the "not set yet" sentinels, so a
        // null outpoint does not survive a decode.
        psbt.inputs[0] = Input::new(&OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 1 });
        psbt.outputs = vec![output];

        let encoded = psbt.serialize();
        let decoded = Psbt::deserialize(&encoded).expect("psbt must decode");

        assert!(decoded.outputs[0].script_pubkey.is_empty());
        assert!(
            !decoded.outputs[0].pairs().iter().any(|pair| pair.key.type_value == PSBT_OUT_SCRIPT),
            "underived silent payment output must not encode PSBT_OUT_SCRIPT"
        );
        assert_eq!(decoded.serialize(), encoded);
    }
}
