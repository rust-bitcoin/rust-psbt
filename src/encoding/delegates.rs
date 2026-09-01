// SPDX-License-Identifier: CC0-1.0

//! Delegates to consensus encoders for PSBT types.
//!
//! This module contains [`PsbtEncode`] implementations for types
//! that have no PSBT-specific encoding logic and can delegate directly to their
//! consensus [`bitcoin_consensus_encoding::Encode`] implementations.

use bitcoin::locktime::absolute;
use bitcoin::{transaction, OutPoint, Sequence, Transaction, TxOut, Witness};
use bitcoin_consensus_encoding::{CompactSizeEncoder, Decode, Encode};

use super::{KeyValueEncoder, PsbtDecode, PsbtEncode, ValueDecoder};

/// Marker trait for types that delegate consensus encoding and decoding to PSBT.
///
/// Types implementing this trait have no PSBT-specific codec logic and can
/// delegate directly to their consensus implementations via the blanket
/// [`PsbtEncode`] and [`PsbtDecode`] implementations.
trait PsbtDelegate: Encode + Decode {}

/// Blanket [`PsbtEncode`] implementation for types that delegate to consensus encoding.
impl<T: PsbtDelegate> PsbtEncode for T {
    type Encoder<'e>
        = <T as Encode>::Encoder<'e>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { self.encoder() }
}

/// Blanket [`PsbtDecode`] implementation for types that delegate to consensus decoding.
impl<T: PsbtDelegate> PsbtDecode for T {
    type Decoder = <T as Decode>::Decoder;
}

/// [`absolute::LockTime`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for absolute::LockTime {}
pub(crate) type FallbackLockTimeKeyValueEncoder<'e> =
    KeyValueEncoder<CompactSizeEncoder, <absolute::LockTime as PsbtEncode>::Encoder<'e>>;
pub(crate) type FallbackLockTimeValueDecoder =
    ValueDecoder<<absolute::LockTime as PsbtDecode>::Decoder>;

/// [`Sequence`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for Sequence {}

/// [`transaction::Version`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for transaction::Version {}
pub(crate) type TxVersionKeyValueEncoder<'e> =
    KeyValueEncoder<CompactSizeEncoder, <transaction::Version as PsbtEncode>::Encoder<'e>>;
pub(crate) type TxVersionValueDecoder = ValueDecoder<<transaction::Version as PsbtDecode>::Decoder>;

/// [`OutPoint`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for OutPoint {}

/// [`Transaction`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for Transaction {}

/// [`TxOut`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for TxOut {}

/// [`Witness`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for Witness {}
