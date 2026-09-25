// SPDX-License-Identifier: CC0-1.0

//! PSBT serialization.
//!
//! Traits to serialize PSBT values to and from raw bytes
//! according to the BIP-174 specification.

use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use core::fmt;

use bitcoin::bip32::{ChildNumber, Fingerprint, KeySource};
use bitcoin::consensus::{self, Decodable};
use bitcoin::hashes::{self, hash160, ripemd160, sha256, sha256d, Hash};
use bitcoin::key::PublicKey;
use bitcoin::secp256k1::{self, XOnlyPublicKey};
use bitcoin::taproot::{
    ControlBlock, LeafVersion, TapLeafHash, TapNodeHash, TapTree, TaprootBuilder,
};
use bitcoin::{
    absolute, ecdsa, taproot, transaction, Amount, ScriptBuf, Sequence, Transaction, TxOut, Txid,
    VarInt, Witness,
};

#[cfg(feature = "silent-payments")]
use crate::dleq;
use crate::error::write_err;
use crate::sighash_type::PsbtSighashType;
use crate::version;

/// A trait for deserializing a value from raw data in PSBT key-value maps.
pub(crate) trait Deserialize: Sized {
    /// Deserializes a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

// Strictly speaking these do not need the prefix because the v0 versions are
// unused but we want to leave thoes in the code so the the files are close as
// possible to the original from bitcoin/miniscript repos.
v2_impl_psbt_de_serialize!(absolute::LockTime);
v2_impl_psbt_de_serialize!(Amount);
v2_impl_psbt_de_serialize!(Transaction);
v2_impl_psbt_de_serialize!(transaction::Version);
v2_impl_psbt_de_serialize!(TxOut);
v2_impl_psbt_de_serialize!(Witness);
v2_impl_psbt_de_serialize!(VarInt);
v2_impl_psbt_hash_de_serialize!(ripemd160::Hash);
v2_impl_psbt_hash_de_serialize!(sha256::Hash);
v2_impl_psbt_hash_de_serialize!(TapLeafHash);
v2_impl_psbt_hash_de_serialize!(TapNodeHash);
v2_impl_psbt_hash_de_serialize!(Txid);
v2_impl_psbt_hash_de_serialize!(hash160::Hash);
v2_impl_psbt_hash_de_serialize!(sha256d::Hash);

// taproot
v2_impl_psbt_de_serialize!(Vec<TapLeafHash>);

impl Deserialize for ScriptBuf {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> { Ok(Self::from(bytes.to_vec())) }
}

impl Deserialize for PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_slice(bytes).map_err(Error::InvalidPublicKey)
    }
}

impl Deserialize for secp256k1::PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_slice(bytes).map_err(Error::InvalidSecp256k1PublicKey)
    }
}

impl Deserialize for ecdsa::Signature {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        // NB: Since BIP-174 says "the signature as would be pushed to the stack from
        // a scriptSig or witness" we should ideally use a consensus deserialization and do
        // not error on a non-standard values. However,
        //
        // 1) the current implementation of from_u32_consensus(`flag`) does not preserve
        // the sighash byte `flag` mapping all unknown values to EcdsaSighashType::All or
        // EcdsaSighashType::AllPlusAnyOneCanPay. Therefore, break the invariant
        // EcdsaSig::from_slice(&sl[..]).to_vec = sl.
        //
        // 2) This would cause to have invalid signatures because the sighash message
        // also has a field sighash_u32 (See BIP141). For example, when signing with non-standard
        // 0x05, the sighash message would have the last field as 0x05u32 while, the verification
        // would check the signature assuming sighash_u32 as `0x01`.
        Self::from_slice(bytes).map_err(|e| match e {
            ecdsa::Error::EmptySignature => Error::InvalidEcdsaSignature(e),
            ecdsa::Error::SighashType(err) => Error::NonStandardSighashType(err.0),
            ecdsa::Error::Secp256k1(..) => Error::InvalidEcdsaSignature(e),
            ecdsa::Error::Hex(..) => unreachable!("decoding from slice, not hex"),
            _ => panic!("TODO: Handle non_exhaustive error"),
        })
    }
}

impl Deserialize for KeySource {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::NotEnoughData);
        }

        let fprint: Fingerprint = bytes[0..4].try_into().expect("4 is the fingerprint length");
        let mut dpath: Vec<ChildNumber> = Default::default();

        let mut d = &bytes[4..];
        while !d.is_empty() {
            {
                let index = u32::consensus_decode(&mut d)?;
                dpath.push(index.into())
            }
        }

        Ok((fprint, dpath.into()))
    }
}

impl Deserialize for u32 {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let val: Self = consensus::deserialize(bytes)?;
        Ok(val)
    }
}

impl Deserialize for Sequence {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let n: Self = consensus::deserialize(bytes)?;
        Ok(n)
    }
}

impl Deserialize for absolute::Height {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let n: u32 = consensus::deserialize(bytes)?;
        let lock = Self::from_consensus(n)?;
        Ok(lock)
    }
}

impl Deserialize for absolute::Time {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let n: u32 = consensus::deserialize(bytes)?;
        let lock = Self::from_consensus(n)?;
        Ok(lock)
    }
}

// partial sigs
impl Deserialize for Vec<u8> {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> { Ok(bytes.to_vec()) }
}

impl Deserialize for PsbtSighashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let raw: u32 = consensus::deserialize(bytes)?;
        Ok(Self { inner: raw })
    }
}

// Taproot related ser/deser
impl Deserialize for XOnlyPublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_slice(bytes).map_err(|_| Error::InvalidXOnlyPublicKey)
    }
}

impl Deserialize for taproot::Signature {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_slice(bytes).map_err(|e| match e {
            taproot::SigFromSliceError::SighashType(err) => Error::NonStandardSighashType(err.0),
            taproot::SigFromSliceError::InvalidSignatureSize(_) =>
                Error::InvalidTaprootSignature(e),
            taproot::SigFromSliceError::Secp256k1(..) => Error::InvalidTaprootSignature(e),
            _ => panic!("TODO: Handle non_exhaustive error"),
        })
    }
}

impl Deserialize for (XOnlyPublicKey, TapLeafHash) {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 32 {
            return Err(Error::NotEnoughData);
        }
        let a: XOnlyPublicKey = Deserialize::deserialize(&bytes[..32])?;
        let b: TapLeafHash = Deserialize::deserialize(&bytes[32..])?;
        Ok((a, b))
    }
}

impl Deserialize for ControlBlock {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes).map_err(|_| Error::InvalidControlBlock)
    }
}

impl Deserialize for (ScriptBuf, LeafVersion) {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::NotEnoughData);
        }
        // The last byte is LeafVersion.
        let script = ScriptBuf::deserialize(&bytes[..bytes.len() - 1])?;
        let leaf_ver = LeafVersion::from_consensus(bytes[bytes.len() - 1])
            .map_err(|_| Error::InvalidLeafVersion)?;
        Ok((script, leaf_ver))
    }
}

impl Deserialize for (Vec<TapLeafHash>, KeySource) {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let (leafhash_vec, consumed) = consensus::deserialize_partial::<Vec<TapLeafHash>>(bytes)?;
        let key_source = KeySource::deserialize(&bytes[consumed..])?;
        Ok((leafhash_vec, key_source))
    }
}

impl Deserialize for TapTree {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut builder = TaprootBuilder::new();
        let mut bytes_iter = bytes.iter();
        while let Some(depth) = bytes_iter.next() {
            let version = bytes_iter.next().ok_or(Error::Taproot("invalid Taproot Builder"))?;
            let (script, consumed) =
                consensus::deserialize_partial::<ScriptBuf>(bytes_iter.as_slice())?;
            if consumed > 0 {
                bytes_iter.nth(consumed - 1);
            }
            let leaf_version =
                LeafVersion::from_consensus(*version).map_err(|_| Error::InvalidLeafVersion)?;
            builder = builder
                .add_leaf_with_ver(*depth, script, leaf_version)
                .map_err(|_| Error::Taproot("Tree not in DFS order"))?;
        }
        Self::try_from(builder).map_err(Error::TapTree)
    }
}

// Helper function to compute key source len

// TODO: This error is still too general but splitting it up is
// non-trivial because it is returned by the Deserialize trait.
/// Ways that deserializing a PSBT might fail.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Not enough data to deserialize object.
    NotEnoughData,
    /// Non-proprietary key type found when proprietary key was expected
    InvalidProprietaryKey,
    /// Signals that there are no more key-value pairs in a key-value map.
    NoMorePairs,
    /// Unable to parse as a standard sighash type.
    NonStandardSighashType(u32),
    /// Invalid hash when parsing slice.
    InvalidHash(hashes::FromSliceError),
    /// Serialization error in bitcoin consensus-encoded structures
    ConsensusEncoding(consensus::encode::Error),
    /// Parsing error indicating invalid public keys
    InvalidPublicKey(bitcoin::key::FromSliceError),
    /// Parsing error indicating invalid secp256k1 public keys
    InvalidSecp256k1PublicKey(secp256k1::Error),
    /// Parsing error indicating invalid xonly public keys
    InvalidXOnlyPublicKey,
    /// Parsing error indicating invalid ECDSA signatures
    InvalidEcdsaSignature(bitcoin::ecdsa::Error),
    /// Parsing error indicating invalid taproot signatures
    InvalidTaprootSignature(bitcoin::taproot::SigFromSliceError),
    /// Parsing error indicating invalid control block
    InvalidControlBlock,
    /// Parsing error indicating invalid leaf version
    InvalidLeafVersion,
    /// Parsing error indicating a taproot error
    Taproot(&'static str),
    /// Taproot tree deserialization error
    TapTree(taproot::IncompleteBuilderError),
    /// Error related to PSBT version
    /// PSBT data is not consumed entirely
    PartialDataConsumption,
    /// Couldn't converting parsed u32 to a lock time.
    LockTime(absolute::ConversionError),
    /// Unsupported PSBT version.
    UnsupportedVersion(version::UnsupportedVersionError),
    /// Invalid scan key for BIP-375 silent payments (expected 33 bytes).
    InvalidScanKey {
        /// The length that was provided.
        got: usize,
        /// The expected length.
        expected: usize,
    },
    /// Invalid ECDH share for BIP-375 silent payments (expected 33 bytes).
    InvalidEcdhShare {
        /// The length that was provided.
        got: usize,
        /// The expected length.
        expected: usize,
    },
    /// Invalid DLEQ proof for BIP-375 silent payments (expected 64 bytes).
    #[cfg(feature = "silent-payments")]
    InvalidDleqProof(dleq::InvalidLengthError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotEnoughData => f.write_str("not enough data to deserialize object"),
            Self::InvalidProprietaryKey =>
                write!(f, "non-proprietary key type found when proprietary key was expected"),
            Self::NoMorePairs => f.write_str("no more key-value pairs for this psbt map"),
            Self::NonStandardSighashType(ref sht) =>
                write!(f, "non-standard sighash type: {}", sht),
            Self::InvalidHash(ref e) => write_err!(f, "invalid hash when parsing slice"; e),
            Self::ConsensusEncoding(ref e) => write_err!(f, "bitcoin consensus encoding error"; e),
            Self::InvalidPublicKey(ref e) => write_err!(f, "invalid public key"; e),
            Self::InvalidSecp256k1PublicKey(ref e) =>
                write_err!(f, "invalid secp256k1 public key"; e),
            Self::InvalidXOnlyPublicKey => f.write_str("invalid xonly public key"),
            Self::InvalidEcdsaSignature(ref e) => write_err!(f, "invalid ECDSA signature"; e),
            Self::InvalidTaprootSignature(ref e) => write_err!(f, "invalid taproot signature"; e),
            Self::InvalidControlBlock => f.write_str("invalid control block"),
            Self::InvalidLeafVersion => f.write_str("invalid leaf version"),
            Self::Taproot(s) => write!(f, "taproot error -  {}", s),
            Self::TapTree(ref e) => write_err!(f, "taproot tree error"; e),
            Self::PartialDataConsumption =>
                f.write_str("data not consumed entirely when explicitly deserializing"),
            Self::LockTime(ref e) => write_err!(f, "parsed locktime invalid"; e),
            Self::UnsupportedVersion(ref e) => write_err!(f, "unsupported version"; e),
            Self::InvalidScanKey { got, expected } => {
                write!(f, "invalid scan key: got {} bytes, expected {}", got, expected)
            }
            Self::InvalidEcdhShare { got, expected } => {
                write!(f, "invalid ECDH share: got {} bytes, expected {}", got, expected)
            }
            #[cfg(feature = "silent-payments")]
            Self::InvalidDleqProof(e) => {
                write!(f, "invalid DLEQ proof: got {} bytes, expected {}", e.got, e.expected)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidHash(ref e) => Some(e),
            Self::ConsensusEncoding(ref e) => Some(e),
            Self::LockTime(ref e) => Some(e),
            Self::UnsupportedVersion(ref e) => Some(e),
            Self::NotEnoughData
            | Self::InvalidProprietaryKey
            | Self::NoMorePairs
            | Self::NonStandardSighashType(_)
            | Self::InvalidPublicKey(_)
            | Self::InvalidSecp256k1PublicKey(_)
            | Self::InvalidXOnlyPublicKey
            | Self::InvalidEcdsaSignature(_)
            | Self::InvalidTaprootSignature(_)
            | Self::InvalidControlBlock
            | Self::InvalidLeafVersion
            | Self::Taproot(_)
            | Self::TapTree(_)
            | Self::PartialDataConsumption
            | Self::InvalidScanKey { .. }
            | Self::InvalidEcdhShare { .. } => None,
            #[cfg(feature = "silent-payments")]
            Self::InvalidDleqProof { .. } => None,
        }
    }
}

impl From<hashes::FromSliceError> for Error {
    fn from(e: hashes::FromSliceError) -> Self { Self::InvalidHash(e) }
}

impl From<consensus::encode::Error> for Error {
    fn from(e: consensus::encode::Error) -> Self { Self::ConsensusEncoding(e) }
}

impl From<absolute::ConversionError> for Error {
    fn from(e: absolute::ConversionError) -> Self { Self::LockTime(e) }
}

impl From<version::UnsupportedVersionError> for Error {
    fn from(e: version::UnsupportedVersionError) -> Self { Self::UnsupportedVersion(e) }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use core::convert::TryFrom;

    use super::*;

    // Composes tree matching a given depth map, filled with dumb script leaves,
    // each of which consists of a single push-int op code, with int value
    // increased for each consecutive leaf.
    pub fn compose_taproot_builder<'map>(
        opcode: u8,
        depth_map: impl IntoIterator<Item = &'map u8>,
    ) -> TaprootBuilder {
        let mut val = opcode;
        let mut builder = TaprootBuilder::new();
        for depth in depth_map {
            let script = ScriptBuf::from_hex(&format!("{:02x}", val)).unwrap();
            builder = builder.add_leaf(*depth, script).unwrap();
            let (new_val, _) = val.overflowing_add(1);
            val = new_val;
        }
        builder
    }

    #[test]
    fn taptree_hidden() {
        let mut builder = compose_taproot_builder(0x51, &[2, 2, 2]);
        builder = builder
            .add_leaf_with_ver(
                3,
                ScriptBuf::from_hex("b9").unwrap(),
                LeafVersion::from_consensus(0xC2).unwrap(),
            )
            .unwrap();
        builder = builder.add_hidden_node(3, TapNodeHash::all_zeros()).unwrap();
        assert!(TapTree::try_from(builder).is_err());
    }

    #[test]
    fn taptree_roundtrip() {
        let mut builder = compose_taproot_builder(0x51, &[2, 2, 2, 3]);
        builder = builder
            .add_leaf_with_ver(
                3,
                ScriptBuf::from_hex("b9").unwrap(),
                LeafVersion::from_consensus(0xC2).unwrap(),
            )
            .unwrap();
        let tree = TapTree::try_from(builder).unwrap();
        let tree_prime = TapTree::deserialize(&crate::encoding::encode_to_vec(&tree)).unwrap();
        assert_eq!(tree, tree_prime);
    }

    #[test]
    fn can_deserialize_non_standard_psbt_sighash_type() {
        let non_standard_sighash = [222u8, 0u8, 0u8, 0u8]; // 32 byte value.
        let sighash = PsbtSighashType::deserialize(&non_standard_sighash);
        assert!(sighash.is_ok())
    }

    #[test]
    fn deserialize_xonly_public_key_len() {
        assert!(XOnlyPublicKey::deserialize(&[1; 31]).is_err());
        assert!(XOnlyPublicKey::deserialize(&[1; 33]).is_err());
    }
}
