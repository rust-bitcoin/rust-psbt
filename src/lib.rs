// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of the Partially Signed Bitcoin Transaction Format as defined in [BIP-174] and
//! PSBT version 2 as defined in [BIP-370].
//!
//! # Serialization
//!
//! This crate provides two serialization paths, the canonical binary wire format as well as human
//! readable `serde` representation.
//!
//! The [`PsbtEncode`] and [`PsbtDecode`] traits produce and consume the canonical PSBT wire
//! format, a compact binary representation defined by the BIP specifications. This encoding is
//! deterministic and consistent, the same PSBT always produces the same bytes. This is the format
//! used on the wire between signers, coordinators, and hardware wallets. It uses a sans-I/O
//! encoder/decoder model (via [`bitcoin_consensus_encoding`]) that works in `no_std` environments
//! and avoids heap allocations where possible.
//!
//! When the `serde` feature is enabled, all PSBT types additionally implement
//! [`Serialize`](serde::Serialize) and [`Deserialize`](serde::Deserialize). This produces a
//! human-readable representation (e.g. JSON) that is not part of any BIP specification. Unlike
//! the wire format, this representation is not guaranteed to be deterministic, the output
//! format is controlled by the serde backend, not by this crate. It is intended for debugging,
//! logging, and readability, not for wire compatibility.
//!
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

#![no_std]
#![doc(test(attr(deny(unused))))]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(feature = "arbitrary")]
pub extern crate arbitrary;
pub extern crate bitcoin;
#[cfg(feature = "miniscript")]
pub extern crate miniscript;

mod consts;
mod encoding;
mod error;
mod map;
mod psbt;
mod roles;
mod sighash_type;
#[cfg(feature = "silent-payments")]
mod silent_payments;
mod v0;
mod version;

#[cfg(feature = "std")]
#[doc(inline)]
pub use crate::encoding::{decode_from_reader, encode_to_writer};
#[cfg(feature = "base64")]
#[doc(inline)]
pub use crate::psbt::ParsePsbtError;
#[cfg(feature = "miniscript")]
#[doc(inline)]
pub use crate::roles::{
    FinalizeError, FinalizeInputError, Finalizer, InputError, InterpreterCheckError,
    InterpreterCheckInputError,
};
#[cfg(feature = "silent-payments")]
#[doc(inline)]
pub use crate::silent_payments::{DleqProof, InvalidLengthError, SpV0Info};
#[doc(inline)]
pub use crate::{
    encoding::{
        decode_from_slice, decode_from_slice_unbounded, encode_to_hex, encode_to_vec,
        PrefixedSliceEncoder, PsbtDecode, PsbtEncode, SliceEncoder, VecDecoder,
    },
    error::{
        DeserializeError, DetermineLockTimeError, FeeError, FundingUtxoError,
        InconsistentKeySourcesError, IndexOutOfBoundsError, InputsNotModifiableError,
        NotUnsignedError, OutputsNotModifiableError, PartialSigsSighashTypeError,
        PsbtNotModifiableError, SignError,
    },
    map::{
        // We do not re-export any of the input/output/global error types, use form `input::DecodeError`.
        global::{self, Global},
        input::{self, Input, InputBuilder},
        output::{self, Output, OutputBuilder},
        Key,
        KeyDecoder,
        KeyEncoder,
        ProprietaryKey,
        ProprietaryKeyEncoder,
        ProprietaryType,
    },
    psbt::{
        combine, CombineError, OutputType, Psbt, PsbtV2Decoder, PsbtV2Encoder, SigningAlgorithm,
    },
    roles::{
        sign_all, sign_all_unchecked, sign_input, sign_input_unchecked, AllSignableInputs,
        Constructor, Creator, ExtractError, ExtractTxError, ExtractTxFeeRateError, Extractor,
        GetKey, GetKeyError, InputSigs, InputsOnlyModifiable, KeyRequest, Mod, Modifiable,
        OutputsOnlyModifiable, SignableInput, Signer, SigningErrors, SigningKeys, SigningSession,
        Updater,
    },
    sighash_type::{InvalidSighashTypeError, ParseSighashTypeError, PsbtSighashType},
    v0::{Degraded, PsbtV0, PsbtV0Decoder, PsbtV0Encoder},
    version::{UnsupportedVersionError, Version},
};

/// PSBT version 0 as defined in [BIP-174].
///
/// [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
pub const V0: Version = Version::ZERO;
/// PSBT version 2 as defined in [BIP-370].
///
/// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>
pub const V2: Version = Version::TWO;
