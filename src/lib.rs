// SPDX-License-Identifier: CC0-1.0

//! Partially Signed Bitcoin Transactions.
//!
//! Implementation of the Partially Signed Bitcoin Transaction Format as defined in [BIP-174] and
//! PSBT version 2 as defined in [BIP-370].
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
#[cfg(feature = "silent-payments")]
mod dleq;
mod encoding;
mod error;
#[macro_use]
mod macros;
mod map;
mod psbt;
mod roles;
#[cfg(feature = "serde")]
mod serde_utils;
mod sighash_type;
#[cfg(feature = "silent-payments")]
mod silent_payments;
mod version;

#[cfg(feature = "silent-payments")]
#[doc(inline)]
pub use crate::dleq::{DleqProof, InvalidLengthError};
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
pub use crate::silent_payments::SpV0Info;
#[doc(inline)]
pub use crate::{
    encoding::{
        decode_from_slice, decode_from_slice_unbounded, encode_to_hex, encode_to_vec,
        ExactPrefixedSliceEncoder, ExactSliceEncoder, PrefixedSliceEncoder, PsbtDecode, PsbtEncode,
        SliceEncoder, VecDecoder,
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
    psbt::Degraded,
    psbt::{
        combine, CombineError, DecodeError, GetKey, GetKeyError, KeyRequest, OutputType, Psbt,
        PsbtV0, PsbtV0Encoder, PsbtV2Decoder, PsbtV2Encoder, SigningAlgorithm, SigningErrors,
        SigningKeys,
    },
    roles::{
        Constructor, Creator, ExtractError, ExtractTxError, ExtractTxFeeRateError, Extractor,
        InputsOnlyModifiable, Mod, Modifiable, OutputsOnlyModifiable, Signer, Updater,
    },
    sighash_type::{InvalidSighashTypeError, ParseSighashTypeError, PsbtSighashType},
    version::{UnsupportedVersionError, Version},
};

/// PSBT version 0 - the original PSBT version.
pub const V0: Version = Version::ZERO;
/// PSBT version 2 - the second PSBT version.
pub const V2: Version = Version::TWO;
