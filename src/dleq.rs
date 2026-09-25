// SPDX-License-Identifier: CC0-1.0

//! BIP-375: Support for silent payments in PSBTs.
//!
//! This module provides type-safe wrapper for BIP-374 dleq proof field.

#[cfg(feature = "serde")]
use alloc::format;
use alloc::vec::Vec;
use core::fmt;

/// A 64-byte DLEQ proof (BIP-374).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DleqProof(pub [u8; 64]);

#[cfg(feature = "serde")]
impl serde::Serialize for DleqProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&bitcoin::hex::DisplayHex::to_lower_hex_string(&self.0[..]))
        } else {
            serializer.serialize_bytes(&self.0[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DleqProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct HexVisitor;
            impl serde::de::Visitor<'_> for HexVisitor {
                type Value = DleqProof;

                fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    f.write_str("a 64-byte hex string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    use bitcoin::hex::FromHex;
                    let vec = Vec::<u8>::from_hex(s).map_err(E::custom)?;
                    DleqProof::try_from(vec).map_err(|e| {
                        E::custom(format!("expected {} bytes, got {}", e.expected, e.got))
                    })
                }
            }
            deserializer.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;
            impl serde::de::Visitor<'_> for BytesVisitor {
                type Value = DleqProof;

                fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    f.write_str("64 bytes")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    DleqProof::try_from(v).map_err(|e| {
                        E::custom(format!("expected {} bytes, got {}", e.expected, e.got))
                    })
                }
            }
            deserializer.deserialize_bytes(BytesVisitor)
        }
    }
}

impl DleqProof {
    /// Returns the inner 64-byte array.
    pub fn as_bytes(&self) -> &[u8; 64] { &self.0 }
}

impl From<[u8; 64]> for DleqProof {
    fn from(bytes: [u8; 64]) -> Self { Self(bytes) }
}

impl AsRef<[u8]> for DleqProof {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl TryFrom<&[u8]> for DleqProof {
    type Error = InvalidLengthError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 64]>::try_from(slice)
            .map(DleqProof)
            .map_err(|_| InvalidLengthError { got: slice.len(), expected: 64 })
    }
}

impl TryFrom<Vec<u8>> for DleqProof {
    type Error = InvalidLengthError;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> { Self::try_from(v.as_slice()) }
}

/// Error returned when a byte array has an invalid length for a dleq proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLengthError {
    /// The length that was provided.
    pub got: usize,
    /// The expected length.
    pub expected: usize,
}

impl fmt::Display for InvalidLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid length for BIP-375 type: got {}, expected {}", self.got, self.expected)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLengthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_ref_returns_correct_slice() {
        let bytes = [0xAB; 64];
        let proof = DleqProof(bytes);
        let slice: &[u8] = proof.as_ref();
        assert_eq!(slice.len(), 64);
        assert_eq!(slice, &bytes);
    }
}
