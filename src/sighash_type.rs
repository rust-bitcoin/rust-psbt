// SPDX-License-Identifier: CC0-1.0

use alloc::borrow::ToOwned;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use bitcoin::sighash::{self, EcdsaSighashType, NonStandardSighashTypeError, TapSighashType};
use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decoder, DecoderStatus, UnexpectedEofError,
};

use crate::{PsbtDecode, PsbtEncode};

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

#[cfg(feature = "serde")]
impl serde::Serialize for PsbtSighashType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            self.inner.serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PsbtSighashType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = alloc::string::String::deserialize(deserializer)?;
            s.parse::<Self>().map_err(serde::de::Error::custom)
        } else {
            let inner = u32::deserialize(deserializer)?;
            Ok(Self { inner })
        }
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
    pub fn taproot_hash_ty(self) -> Result<TapSighashType, sighash::InvalidSighashTypeError> {
        let val =
            u8::try_from(self.inner).map_err(|_| sighash::InvalidSighashTypeError(self.inner))?;
        TapSighashType::from_consensus_u8(val)
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
        self.ecdsa_hash_ty().is_ok_and(|ty| {
            matches!(ty, EcdsaSighashType::None | EcdsaSighashType::NonePlusAnyoneCanPay)
        })
    }

    /// True for `SIGHASH_SINGLE`, with or without `SIGHASH_ANYONECANPAY`.
    ///
    /// The ECDSA-standard and taproot-valid type sets coincide except for `0x00`
    /// (taproot `Default`), which is not single - so one conversion suffices.
    ///
    /// Returns `false` for non-standard sighash values, which fail
    /// [`Self::ecdsa_hash_ty`] anyway.
    pub fn is_single(self) -> bool { self.ecdsa_hash_ty().is_ok_and(|ty| ty.is_single()) }
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

impl PsbtEncode for PsbtSighashType {
    type Encoder<'e>
        = ArrayEncoder<4>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        ArrayEncoder::without_length_prefix(self.to_u32().to_le_bytes())
    }
}

/// Decoder for a [`PsbtSighashType`] value (4 bytes, u32 LE).
#[derive(Debug, Default)]
pub struct SighashTypeDecoder {
    inner: ArrayDecoder<4>,
}

impl SighashTypeDecoder {
    /// Constructs a new [`SighashTypeDecoder`].
    pub const fn new() -> Self { Self { inner: ArrayDecoder::new() } }
}

impl Decoder for SighashTypeDecoder {
    type Output = PsbtSighashType;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let bytes = self.inner.end()?;
        Ok(PsbtSighashType { inner: u32::from_le_bytes(bytes) })
    }

    fn read_limit(&self) -> usize { self.inner.read_limit() }
}

impl PsbtDecode for PsbtSighashType {
    type Decoder = SighashTypeDecoder;
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

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
        assert_eq!(back.ecdsa_hash_ty(), Err(NonStandardSighashTypeError(nonstd)));
        assert_eq!(back.taproot_hash_ty(), Err(sighash::InvalidSighashTypeError(nonstd)));
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
    fn read_limit_lifecycle() {
        let mut decoder = SighashTypeDecoder::new();
        assert_eq!(decoder.read_limit(), 4);

        let mut bytes: &[u8] = &[0x01, 0x00, 0x00, 0x00];
        let status = decoder.push_bytes(&mut bytes).unwrap();
        assert!(status.is_ready());
        assert_eq!(decoder.read_limit(), 0);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip() {
        let cases = [
            PsbtSighashType::from(EcdsaSighashType::All),
            PsbtSighashType::from(EcdsaSighashType::None),
            PsbtSighashType::from(EcdsaSighashType::Single),
            PsbtSighashType::from(EcdsaSighashType::AllPlusAnyoneCanPay),
            PsbtSighashType::from(TapSighashType::Default),
            PsbtSighashType::from(TapSighashType::All),
            PsbtSighashType::from(TapSighashType::NonePlusAnyoneCanPay),
            // Non-standard values round-trip through hex fallback.
            PsbtSighashType::from_u32(0xdddddddd),
        ];

        for original in &cases {
            let json = serde_json::to_string(original).unwrap();
            let parsed: PsbtSighashType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *original, "roundtrip failed for {json}");
        }

        // Non-standard value serializes as a hex string.
        let nonstd = PsbtSighashType::from_u32(0xdddddddd);
        assert_eq!(serde_json::to_string(&nonstd).unwrap(), r#""0xdddddddd""#);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_invalid() {
        assert!(serde_json::from_str::<PsbtSighashType>(r#""NOT_A_SIGHASH""#).is_err());
        assert!(serde_json::from_str::<PsbtSighashType>("42").is_err());
    }
}
