// SPDX-License-Identifier: CC0-1.0

use alloc::borrow::ToOwned;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use bitcoin::sighash::{self, EcdsaSighashType, NonStandardSighashTypeError, TapSighashType};

use crate::error::write_err;

const SIGHASH_ANYONECANPAY: u32 = 0x80;

/// A Signature hash type for the corresponding input.
///
/// As of taproot upgrade, the signature hash type can be either [`EcdsaSighashType`] or
/// [`TapSighashType`] but it is not possible to know directly which signature hash type the user is
/// dealing with. Therefore, the user is responsible for converting to/from [`PsbtSighashType`]
/// from/to the desired signature hash type they need.
///
/// # Examples
///
/// ```
/// use bitcoin::{EcdsaSighashType, TapSighashType};
/// use psbt_v2::PsbtSighashType;
///
/// let _ecdsa_sighash_all: PsbtSighashType = EcdsaSighashType::All.into();
/// let _tap_sighash_all: PsbtSighashType = TapSighashType::All.into();
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PsbtSighashType {
    pub(crate) inner: u32,
}

impl fmt::Display for PsbtSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.taproot_hash_ty() {
            Err(_) => write!(f, "{:#x}", self.inner),
            Ok(taproot_hash_ty) => fmt::Display::fmt(&taproot_hash_ty, f),
        }
    }
}

impl FromStr for PsbtSighashType {
    type Err = ParseSighashTypeError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We accept strings of form: "SIGHASH_ALL" etc.
        //
        // NB: some of Taproot sighash types are non-standard for pre-taproot
        // inputs. We also do not support SIGHASH_RESERVED in verbatim form
        // ("0xFF" string should be used instead).
        if let Ok(ty) = s.parse::<TapSighashType>() {
            return Ok(ty.into());
        }

        // We accept non-standard sighash values.
        if let Ok(inner) = u32::from_str_radix(s.trim_start_matches("0x"), 16) {
            return Ok(Self { inner });
        }

        Err(ParseSighashTypeError { unrecognized: s.to_owned() })
    }
}
impl From<EcdsaSighashType> for PsbtSighashType {
    fn from(ecdsa_hash_ty: EcdsaSighashType) -> Self { Self { inner: ecdsa_hash_ty as u32 } }
}

impl From<TapSighashType> for PsbtSighashType {
    fn from(taproot_hash_ty: TapSighashType) -> Self { Self { inner: taproot_hash_ty as u32 } }
}

impl PsbtSighashType {
    /// Ambiguous `ALL` sighash type, may refer to either [`EcdsaSighashType::All`]
    /// or [`TapSighashType::All`].
    ///
    /// This is equivalent to either `EcdsaSighashType::All.into()` or `TapSighashType::All.into()`.
    /// For sighash types other than `ALL` use the ECDSA or Taproot sighash type directly.
    ///
    /// # Examples
    ///
    /// ```
    /// use bitcoin::EcdsaSighashType;
    /// use bitcoin::TapSighashType;
    /// use psbt_v2::PsbtSighashType;
    /// let _ecdsa_sighash_anyone_can_pay: PsbtSighashType = EcdsaSighashType::AllPlusAnyoneCanPay.into();
    /// let _tap_sighash_anyone_can_pay: PsbtSighashType = TapSighashType::AllPlusAnyoneCanPay.into();
    /// ```
    pub const ALL: Self = Self { inner: 0x01 };

    /// Returns the [`EcdsaSighashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn ecdsa_hash_ty(self) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        EcdsaSighashType::from_standard(self.inner)
    }

    /// Returns the [`TapSighashType`] if the [`PsbtSighashType`] can be
    /// converted to one.
    pub fn taproot_hash_ty(self) -> Result<TapSighashType, InvalidSighashTypeError> {
        if self.inner > 0xffu32 {
            return Err(InvalidSighashTypeError::Invalid(self.inner));
        }

        let ty = TapSighashType::from_consensus_u8(self.inner as u8)?;
        Ok(ty)
    }

    /// Creates a [`PsbtSighashType`] from a raw `u32`.
    ///
    /// Allows construction of a non-standard or non-valid sighash flag
    /// ([`EcdsaSighashType`], [`TapSighashType`] respectively).
    pub fn from_u32(n: u32) -> Self { Self { inner: n } }

    /// Converts [`PsbtSighashType`] to a raw `u32` sighash flag.
    ///
    /// No guarantees are made as to the standardness or validity of the returned value.
    pub fn to_u32(self) -> u32 { self.inner }

    /// True if the `SIGHASH_ANYONECANPAY` flag is set.
    ///
    /// Unlike [`Self::is_none`] and [`Self::is_single`], which answer "is this a
    /// standard sighash of the given base type", this is a pure flag bit check and
    /// applies to any `u32` value.
    pub fn is_anyone_can_pay(self) -> bool { self.inner & SIGHASH_ANYONECANPAY != 0 }

    /// True for `SIGHASH_NONE`, with or without `SIGHASH_ANYONECANPAY`.
    ///
    /// Returns `false` for non-standard sighash values, which fail
    /// [`Self::ecdsa_hash_ty`] anyway.
    pub fn is_none(self) -> bool {
        self.ecdsa_hash_ty()
            .map(|ty| matches!(ty, EcdsaSighashType::None | EcdsaSighashType::NonePlusAnyoneCanPay))
            .unwrap_or(false)
    }

    /// True for `SIGHASH_SINGLE`, with or without `SIGHASH_ANYONECANPAY`.
    ///
    /// The ECDSA-standard and taproot-valid type sets coincide except for `0x00`
    /// (taproot `Default`), which is not single - so one conversion suffices.
    ///
    /// Returns `false` for non-standard sighash values, which fail
    /// [`Self::ecdsa_hash_ty`] anyway.
    pub fn is_single(self) -> bool {
        self.ecdsa_hash_ty().map(|ty| ty.is_single()).unwrap_or(false)
    }
}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseSighashTypeError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for ParseSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

// TODO: Remove this error after issue resolves.
// https://github.com/rust-bitcoin/rust-bitcoin/issues/2423
/// Integer is not a consensus valid sighash type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidSighashTypeError {
    /// The real invalid sighash type error.
    Bitcoin(sighash::InvalidSighashTypeError),
    /// Hack required because of non_exhaustive on the real error.
    Invalid(u32),
}

impl fmt::Display for InvalidSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Bitcoin(ref e) => write_err!(f, "bitcoin"; e),
            Self::Invalid(invalid) => write!(f, "invalid sighash type {}", invalid),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bitcoin(ref e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

impl From<sighash::InvalidSighashTypeError> for InvalidSighashTypeError {
    fn from(e: sighash::InvalidSighashTypeError) -> Self { Self::Bitcoin(e) }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;
    use crate::sighash_type::InvalidSighashTypeError;

    #[test]
    fn psbt_sighash_type_ecdsa() {
        for ecdsa in &[
            EcdsaSighashType::All,
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ] {
            let sighash = PsbtSighashType::from(*ecdsa);
            let s = format!("{}", sighash);
            let back = s.parse::<PsbtSighashType>().unwrap();
            assert_eq!(back, sighash);
            assert_eq!(back.ecdsa_hash_ty().unwrap(), *ecdsa);
        }
    }

    #[test]
    fn psbt_sighash_type_taproot() {
        for tap in &[
            TapSighashType::Default,
            TapSighashType::All,
            TapSighashType::None,
            TapSighashType::Single,
            TapSighashType::AllPlusAnyoneCanPay,
            TapSighashType::NonePlusAnyoneCanPay,
            TapSighashType::SinglePlusAnyoneCanPay,
        ] {
            let sighash = PsbtSighashType::from(*tap);
            let s = format!("{}", sighash);
            let back = s.parse::<PsbtSighashType>().unwrap();
            assert_eq!(back, sighash);
            assert_eq!(back.taproot_hash_ty().unwrap(), *tap);
        }
    }

    #[test]
    fn psbt_sighash_type_notstd() {
        let nonstd = 0xdddddddd;
        let sighash = PsbtSighashType { inner: nonstd };
        let s = format!("{}", sighash);
        let back = s.parse::<PsbtSighashType>().unwrap();

        assert_eq!(back, sighash);
        // TODO: Add this assertion once we remove InvalidSighashTypeError
        // assert_eq!(back.ecdsa_hash_ty(), Err(NonStandardSighashTypeError(nonstd)));
        assert_eq!(back.taproot_hash_ty(), Err(InvalidSighashTypeError::Invalid(nonstd)));
    }

    #[test]
    fn psbt_sighash_const_all() {
        use bitcoin::{EcdsaSighashType, TapSighashType};

        assert_eq!(PsbtSighashType::ALL.to_u32(), 0x01);
        assert_eq!(PsbtSighashType::ALL.ecdsa_hash_ty().unwrap(), EcdsaSighashType::All);
        assert_eq!(PsbtSighashType::ALL.taproot_hash_ty().unwrap(), TapSighashType::All);
    }

    #[test]
    fn psbt_sighash_type_to_u32_roundtrip() {
        assert_eq!(PsbtSighashType::from_u32(0xffff_ffff).to_u32(), 0xffff_ffff);
        assert_eq!(PsbtSighashType::from_u32(0x01).to_u32(), 0x01);
        assert_eq!(PsbtSighashType::from_u32(0x00).to_u32(), 0x00);
    }

    #[test]
    fn sighash_flag_methods() {
        assert!(PsbtSighashType::from(EcdsaSighashType::AllPlusAnyoneCanPay).is_anyone_can_pay());
        assert!(!PsbtSighashType::from(EcdsaSighashType::All).is_anyone_can_pay());

        assert!(PsbtSighashType::from(EcdsaSighashType::None).is_none());
        assert!(!PsbtSighashType::from(EcdsaSighashType::All).is_none());
        assert!(PsbtSighashType::from(EcdsaSighashType::NonePlusAnyoneCanPay).is_none());

        assert!(PsbtSighashType::from(EcdsaSighashType::Single).is_single());
        assert!(!PsbtSighashType::from(EcdsaSighashType::All).is_single());
        assert!(PsbtSighashType::from(EcdsaSighashType::SinglePlusAnyoneCanPay).is_single());

        // Non-standard values are never classified.
        let nonstandard = PsbtSighashType::from_u32(0x07);
        assert!(!nonstandard.is_none());
        assert!(!nonstandard.is_single());
    }

    #[test]
    fn psbt_sighash_taproot_boundary_0xff() {
        // 0xFF is the boundary between the two rejection layers.
        // (This test killed a `>` → `>=` mutation.)
        match PsbtSighashType::from_u32(0xff).taproot_hash_ty() {
            Err(InvalidSighashTypeError::Bitcoin(_)) => {}
            other => panic!("0xff must be rejected by consensus conversion, got {:?}", other),
        }

        // The other side of the boundary takes the range-check layer.
        match PsbtSighashType::from_u32(0x100).taproot_hash_ty() {
            Err(InvalidSighashTypeError::Invalid(0x100)) => {}
            other => panic!("0x100 must be rejected by the range check, got {:?}", other),
        }
    }
}
