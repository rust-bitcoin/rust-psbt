// SPDX-License-Identifier: CC0-1.0

//! Transaction modifiable flags (`PSBT_GLOBAL_TX_MODIFIABLE`).
//!
//! Defined in [BIP-370] (PSBT version 2), this single-byte bitfield communicates which
//! parts of a PSBT may still be modified by subsequent roles. The Creator sets the flags
//! to indicate whether inputs or outputs can still be added or removed, and each Signer
//! clears the relevant flags after signing so the PSBT accurately reflects the remaining
//! degrees of freedom.
//!
//! [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, Decoder, DecoderStatus, UnexpectedEofError,
};

use crate::encoding::{PsbtDecode, PsbtEncode};
use crate::PsbtSighashType;

/// Set to 1 if inputs may be added or removed (bit 0).
const INPUTS_MODIFIABLE: u8 = 0x01;
/// Set to 1 if outputs may be added or removed (bit 1).
const OUTPUTS_MODIFIABLE: u8 = 0x01 << 1;
/// Set to 1 if the transaction includes a `SIGHASH_SINGLE` signature whose
/// input/output pairing must be preserved. The Constructor must iterate inputs
/// to determine whether and how to add or remove an input (bit 2).
const SIGHASH_SINGLE: u8 = 0x01 << 2;
/// Both inputs and outputs may be added or removed (bits 0 and 1).
///
/// Equivalent to `INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE` i.e., `0x01 | 0x02 == 0x03`.
const INPUTS_AND_OUTPUTS_MODIFIABLE: u8 = 0x03;

/// A bitfield for various transaction modification flags (BIP-370).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct TxModifiableFlags(pub u8);

impl TxModifiableFlags {
    /// All flags cleared.
    pub const fn new() -> Self { Self(0x00) }

    /// Constructs flags with only the inputs modifiable bit set.
    pub const fn with_inputs_modifiable() -> Self { Self(INPUTS_MODIFIABLE) }

    /// Constructs flags with only the outputs modifiable bit set.
    pub const fn with_outputs_modifiable() -> Self { Self(OUTPUTS_MODIFIABLE) }

    /// Constructs flags with both inputs and outputs modifiable bits set.
    pub const fn with_all_modifiable() -> Self { Self(INPUTS_AND_OUTPUTS_MODIFIABLE) }

    /// Returns `true` if no flags are set.
    pub fn is_empty(self) -> bool { self.0 == 0 }

    /// Set the inputs modifiable flag.
    pub fn set_inputs_modifiable(&mut self) { self.0 |= INPUTS_MODIFIABLE; }

    /// Set the outputs modifiable flag.
    pub fn set_outputs_modifiable(&mut self) { self.0 |= OUTPUTS_MODIFIABLE; }

    /// Set the has SIGHASH_SINGLE flag.
    pub fn set_sighash_single(&mut self) { self.0 |= SIGHASH_SINGLE; }

    /// Clear the inputs modifiable flag.
    pub fn clear_inputs_modifiable(&mut self) { self.0 &= !INPUTS_MODIFIABLE; }

    /// Clear the outputs modifiable flag.
    pub fn clear_outputs_modifiable(&mut self) { self.0 &= !OUTPUTS_MODIFIABLE; }

    /// Clear the has SIGHASH_SINGLE flag.
    pub fn clear_sighash_single(&mut self) { self.0 &= !SIGHASH_SINGLE; }

    /// Returns `true` if the inputs modifiable flag is set.
    pub fn is_inputs_modifiable(self) -> bool { self.0 & INPUTS_MODIFIABLE > 0 }

    /// Returns `true` if the outputs modifiable flag is set.
    pub fn is_outputs_modifiable(self) -> bool { self.0 & OUTPUTS_MODIFIABLE > 0 }

    /// Returns `true` if the has SIGHASH_SINGLE flag is set.
    pub fn has_sighash_single(self) -> bool { self.0 & SIGHASH_SINGLE > 0 }

    /// Apply [BIP-370] rules, update flags based on the sighash type used for signing.
    ///
    /// [BIP-370]: <https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki>
    pub fn apply_sighash(&mut self, sighash_type: PsbtSighashType) {
        if !sighash_type.is_anyone_can_pay() {
            self.clear_inputs_modifiable();
        }
        if !sighash_type.is_none() {
            self.clear_outputs_modifiable();
        }
        if sighash_type.is_single() {
            self.set_sighash_single();
        }
    }

    /// Merges the flags of two PSBTs being combined.
    ///
    /// All bits are ANDed (a part stays modifiable only if both PSBTs say so)
    /// except the SIGHASH_SINGLE bit, which is ORed (set if either PSBT has it).
    pub fn combine(&mut self, other: Self) {
        let sighash_single = self.has_sighash_single() || other.has_sighash_single();
        self.0 &= other.0;
        if sighash_single {
            self.set_sighash_single();
        }
    }
}

impl fmt::Display for TxModifiableFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // If any reserved bits are set, fall back to hex to avoid losing information.
        const KNOWN_MASK: u8 = 0x07; // INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE | SIGHASH_SINGLE
        if self.0 & !KNOWN_MASK != 0 {
            return write!(f, "{:#x}", self.0);
        }

        let mut first = true;
        let mut write_flag = |name: &str| {
            if !first {
                f.write_str("|")?;
            }
            first = false;
            f.write_str(name)
        };
        if self.is_inputs_modifiable() {
            write_flag("INPUTS_MODIFIABLE")?;
        }
        if self.is_outputs_modifiable() {
            write_flag("OUTPUTS_MODIFIABLE")?;
        }
        if self.has_sighash_single() {
            write_flag("SIGHASH_SINGLE")?;
        }
        if first {
            f.write_str("NONE")?;
        }
        Ok(())
    }
}

/// Error returned when parsing a [`TxModifiableFlags`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTxModifiableFlagsError(String);

impl fmt::Display for ParseTxModifiableFlagsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse TxModifiableFlags: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseTxModifiableFlagsError {}

impl FromStr for TxModifiableFlags {
    type Err = ParseTxModifiableFlagsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept hex format: "0x03"
        if let Some(hex) = s.strip_prefix("0x") {
            return u8::from_str_radix(hex, 16)
                .map(TxModifiableFlags)
                .map_err(|_| ParseTxModifiableFlagsError(s.into()));
        }
        if s.eq_ignore_ascii_case("NONE") {
            return Ok(Self(0));
        }
        let mut flags = 0u8;
        for part in s.split('|') {
            let part = part.trim();
            match part {
                "INPUTS_MODIFIABLE" => flags |= INPUTS_MODIFIABLE,
                "OUTPUTS_MODIFIABLE" => flags |= OUTPUTS_MODIFIABLE,
                "SIGHASH_SINGLE" => flags |= SIGHASH_SINGLE,
                _ => return Err(ParseTxModifiableFlagsError(s.into())),
            }
        }
        Ok(Self(flags))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TxModifiableFlags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            self.0.serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for TxModifiableFlags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = alloc::string::String::deserialize(deserializer)?;
            s.parse::<Self>().map_err(serde::de::Error::custom)
        } else {
            let inner = u8::deserialize(deserializer)?;
            Ok(Self(inner))
        }
    }
}

impl From<u8> for TxModifiableFlags {
    fn from(byte: u8) -> Self { Self(byte) }
}

impl PsbtEncode for TxModifiableFlags {
    type Encoder<'e>
        = TxModifiableFlagsEncoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> {
        TxModifiableFlagsEncoder::new(ArrayEncoder::without_length_prefix([self.0]))
    }
}

bitcoin_consensus_encoding::encoder_newtype_exact! {
    /// Encoder for a single-byte modifiable-flags value.
    pub struct TxModifiableFlagsEncoder<'e>(ArrayEncoder<1>);
}

/// Decoder for the single-byte modifiable-flags value.
#[derive(Debug, Default)]
pub struct TxModifiableFlagsDecoder(ArrayDecoder<1>);

impl Decoder for TxModifiableFlagsDecoder {
    type Output = TxModifiableFlags;
    type Error = UnexpectedEofError;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let [byte] = self.0.end()?;
        Ok(TxModifiableFlags(byte))
    }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl PsbtDecode for TxModifiableFlags {
    type Decoder = TxModifiableFlagsDecoder;
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use bitcoin::sighash::EcdsaSighashType;

    use super::*;

    #[test]
    fn new_is_empty() {
        assert_eq!(TxModifiableFlags::new().0, 0x00);
        assert!(TxModifiableFlags::new().is_empty());
        assert_eq!(TxModifiableFlags::default().0, 0x00);
    }

    #[test]
    fn with_inputs_modifiable() {
        let f = TxModifiableFlags::with_inputs_modifiable();
        assert!(f.is_inputs_modifiable());
        assert!(!f.is_outputs_modifiable());
        assert!(!f.has_sighash_single());
        assert!(!f.is_empty());
    }

    #[test]
    fn with_outputs_modifiable() {
        let f = TxModifiableFlags::with_outputs_modifiable();
        assert!(!f.is_inputs_modifiable());
        assert!(f.is_outputs_modifiable());
        assert!(!f.has_sighash_single());
    }

    #[test]
    fn with_all_modifiable() {
        let f = TxModifiableFlags::with_all_modifiable();
        assert!(f.is_inputs_modifiable());
        assert!(f.is_outputs_modifiable());
        assert!(!f.has_sighash_single());
    }

    #[test]
    fn combine() {
        // (self, other) -> expected. Modifiable bits are ANDed, SIGHASH_SINGLE is
        // ORed, undefined bits are ANDed (cleared unless set in both).
        let cases = [
            // AND clears bits absent from other; OR keeps SIGHASH_SINGLE from one side.
            (INPUTS_MODIFIABLE | SIGHASH_SINGLE, 0x00, SIGHASH_SINGLE),
            // AND keeps bits set in both.
            (INPUTS_MODIFIABLE, INPUTS_MODIFIABLE, INPUTS_MODIFIABLE),
            // SIGHASH_SINGLE set in both stays set (OR, not XOR).
            (SIGHASH_SINGLE, SIGHASH_SINGLE, SIGHASH_SINGLE),
            // Undefined bits are ANDed, not kept from self.
            (0b1000_0001, 0x01, 0x01),
        ];
        for (a, b, expected) in cases {
            let mut flags = TxModifiableFlags(a);
            flags.combine(TxModifiableFlags(b));
            assert_eq!(flags.0, expected);
        }
    }

    #[test]
    fn set_and_clear_inputs() {
        let mut f = TxModifiableFlags::new();
        f.set_inputs_modifiable();
        assert!(f.is_inputs_modifiable());
        f.clear_inputs_modifiable();
        assert!(!f.is_inputs_modifiable());
    }

    #[test]
    fn set_inputs_modifiable_is_idempotent() {
        // Setting a flag that is already set must be a no-op (| not ^).
        let mut f = TxModifiableFlags(INPUTS_MODIFIABLE);
        f.set_inputs_modifiable();
        assert!(f.is_inputs_modifiable());
    }

    #[test]
    fn set_and_clear_outputs() {
        let mut f = TxModifiableFlags::new();
        f.set_outputs_modifiable();
        assert!(f.is_outputs_modifiable());
        f.clear_outputs_modifiable();
        assert!(!f.is_outputs_modifiable());
    }

    #[test]
    fn set_and_clear_sighash_single() {
        let mut f = TxModifiableFlags::new();
        f.set_sighash_single();
        assert!(f.has_sighash_single());
        f.clear_sighash_single();
        assert!(!f.has_sighash_single());
    }

    #[test]
    fn multiple_flags_independent() {
        let mut f = TxModifiableFlags::new();
        f.set_inputs_modifiable();
        f.set_outputs_modifiable();
        f.set_sighash_single();
        assert!(f.is_inputs_modifiable());
        assert!(f.is_outputs_modifiable());
        assert!(f.has_sighash_single());

        f.clear_inputs_modifiable();
        assert!(!f.is_inputs_modifiable());
        assert!(f.is_outputs_modifiable());
        assert!(f.has_sighash_single());

        f.clear_sighash_single();
        assert!(!f.has_sighash_single());
        assert!(f.is_outputs_modifiable());
    }

    #[test]
    fn from_u8_roundtrip() {
        for byte in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff] {
            let f = TxModifiableFlags::from(byte);
            assert_eq!(f.0, byte);
        }
    }

    #[test]
    fn display_empty() {
        assert_eq!(TxModifiableFlags::new().to_string(), "NONE");
    }

    #[test]
    fn display_inputs_only() {
        assert_eq!(TxModifiableFlags::with_inputs_modifiable().to_string(), "INPUTS_MODIFIABLE");
    }

    #[test]
    fn display_multiple() {
        let f = TxModifiableFlags::with_all_modifiable();
        let s = f.to_string();
        assert!(s.contains("INPUTS_MODIFIABLE"));
        assert!(s.contains("OUTPUTS_MODIFIABLE"));
    }

    #[test]
    fn display_unknown_bits_falls_back_to_hex() {
        // Bits 3-7 are not known flags; Display should use hex to preserve them.
        let f = TxModifiableFlags(0x88);
        assert_eq!(f.to_string(), "0x88");
    }

    #[test]
    fn from_str_none() {
        let f: TxModifiableFlags = "NONE".parse().unwrap();
        assert_eq!(f, TxModifiableFlags(0x00));
    }

    #[test]
    fn from_str_single_flag() {
        let f: TxModifiableFlags = "INPUTS_MODIFIABLE".parse().unwrap();
        assert_eq!(f, TxModifiableFlags(INPUTS_MODIFIABLE));
    }

    #[test]
    fn from_str_multiple_flags() {
        let f: TxModifiableFlags = "INPUTS_MODIFIABLE|OUTPUTS_MODIFIABLE".parse().unwrap();
        assert_eq!(f, TxModifiableFlags(INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE));
    }

    #[test]
    fn from_str_hex() {
        let f: TxModifiableFlags = "0xff".parse().unwrap();
        assert_eq!(f, TxModifiableFlags(0xff));
    }

    #[test]
    fn from_str_invalid() {
        assert!("NOT_A_FLAG".parse::<TxModifiableFlags>().is_err());
    }

    #[test]
    fn from_str_roundtrip() {
        let cases = [
            TxModifiableFlags(0x00),
            TxModifiableFlags::with_inputs_modifiable(),
            TxModifiableFlags::with_outputs_modifiable(),
            TxModifiableFlags::with_all_modifiable(),
            TxModifiableFlags(INPUTS_MODIFIABLE | SIGHASH_SINGLE),
            TxModifiableFlags(OUTPUTS_MODIFIABLE | SIGHASH_SINGLE),
            // Unknown bits round-trip through hex fallback.
            TxModifiableFlags(0x88),
        ];
        for original in &cases {
            let s = original.to_string();
            let parsed: TxModifiableFlags = s.parse().unwrap();
            assert_eq!(parsed, *original, "roundtrip failed for {s:?}");
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_rejects_invalid() {
        assert!(serde_json::from_str::<TxModifiableFlags>(r#""NOT_A_FLAG""#).is_err());
        assert!(serde_json::from_str::<TxModifiableFlags>("42").is_err());
    }

    #[test]
    fn apply_sighash_all_clears_both() {
        let mut f = TxModifiableFlags::with_all_modifiable();
        f.apply_sighash(PsbtSighashType::from(EcdsaSighashType::All));
        assert!(!f.is_inputs_modifiable());
        assert!(!f.is_outputs_modifiable());
        assert!(!f.has_sighash_single());
    }

    #[test]
    fn apply_sighash_acp_preserves_inputs() {
        let mut f = TxModifiableFlags::with_inputs_modifiable();
        f.apply_sighash(PsbtSighashType::from(EcdsaSighashType::AllPlusAnyoneCanPay));
        assert!(f.is_inputs_modifiable());
    }

    #[test]
    fn apply_sighash_none_preserves_outputs() {
        let mut f = TxModifiableFlags::with_outputs_modifiable();
        f.apply_sighash(PsbtSighashType::from(EcdsaSighashType::None));
        assert!(f.is_outputs_modifiable());
    }

    #[test]
    fn apply_sighash_none_acp_preserves_outputs() {
        let mut f = TxModifiableFlags::with_outputs_modifiable();
        f.apply_sighash(PsbtSighashType::from(EcdsaSighashType::NonePlusAnyoneCanPay));
        assert!(f.is_outputs_modifiable());
    }

    #[test]
    fn apply_sighash_single_sets_flag() {
        let mut f = TxModifiableFlags::new();
        f.apply_sighash(PsbtSighashType::from(EcdsaSighashType::Single));
        assert!(f.has_sighash_single());
        assert!(!f.is_inputs_modifiable());
        assert!(!f.is_outputs_modifiable());
    }

    #[test]
    fn apply_sighash_single_acp_sets_flag() {
        let mut f = TxModifiableFlags::new();
        f.apply_sighash(PsbtSighashType::from(EcdsaSighashType::SinglePlusAnyoneCanPay));
        assert!(f.has_sighash_single());
    }

    #[test]
    fn encode_decode_roundtrip() {
        use crate::encoding::{decode_from_slice, encode_to_vec};

        let original = TxModifiableFlags::with_all_modifiable();
        let encoded = encode_to_vec(&original);
        let decoded: TxModifiableFlags = decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, original);
    }
}
