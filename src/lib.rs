// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of the Partially Signed Bitcoin Transaction Format as defined in [BIP-174] and
//! PSBT version 2 as defined in [BIP-370].
//!
//! # Supported BIPs
//!
//! | BIP | Description | Status |
//! |-----|-------------|--------|
//! | [BIP-127] | Proof of Reserves | Full |
//! | [BIP-174] | PSBT Version 0 | Serialization and Deserialization |
//! | [BIP-370] | PSBT Version 2 | Full |
//! | [BIP-371] | Taproot fields for PSBT | Full |
//! | [BIP-375] | Silent Payments in PSBT | Experimental (feature `silent-payments`) |
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
//! [BIP-127]: <https://github.com/bitcoin/bips/blob/master/bip-0127.mediawiki>
//! [BIP-174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>
//! [BIP-371]: <https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki>
//! [BIP-375]: <https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki>

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
#[cfg(feature = "musig")]
mod musig;
mod psbt;
mod roles;
mod sighash_type;
#[cfg(feature = "silent-payments")]
mod silent_payments;
mod tap_key_origin;
mod tx_modifiable_flags;
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
pub use crate::roles::{FinalizeError, Finalizer, InputError};
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
        IndexOutOfBoundsError, NotUnsignedError, SignError, SignatureSighashTypeError,
        SignatureSource,
    },
    map::{
        // We do not re-export any of the input/output/global error types, use form `input::DecodeError`.
        global::{self, Global},
        input::{self, Input, InputBuilder},
        output::{self, Output, OutputBuilder},
        Count,
        Key,
        KeyDecoder,
        KeyEncoder,
        ProprietaryKey,
        ProprietaryKeyEncoder,
        ProprietaryType,
        RequiredHeightLockTime,
        RequiredHeightLockTimeError,
        Vout,
    },
    psbt::{
        combine, CombineError, OutputType, Psbt, PsbtV2Decoder, PsbtV2Encoder, ResolvedPsbt,
        SigningAlgorithm,
    },
    roles::{
        sign_all, sign_all_unchecked, sign_input, sign_input_unchecked, AllSignableInputs,
        ConstructError, Constructor, Creator, ExtractError, Extractor, GetKey, GetKeyError,
        InputPatch, InputSigs, InputsOnlyModifiable, KeyRequest, Mod, Modifiable, OutputPatch,
        OutputsOnlyModifiable, SignableInput, Signer, SigningErrors, SigningKeys, SigningSession,
        Updater, UpdaterPatch,
    },
    sighash_type::{ParseSighashTypeError, PsbtSighashType},
    tx_modifiable_flags::TxModifiableFlags,
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
