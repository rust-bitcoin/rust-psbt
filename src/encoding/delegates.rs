// SPDX-License-Identifier: CC0-1.0

//! Delegates to consensus encoders for PSBT types.
//!
//! This module contains PSBT codec implementations for types that have no PSBT-specific encoding
//! logic and can delegate directly to their consensus implementations.

use bitcoin::locktime::absolute;
use bitcoin::{transaction, Amount, OutPoint, Sequence, Transaction, TxOut, Witness};
use bitcoin_consensus_encoding::{Decode, Encode};

use super::{PsbtDecode, PsbtEncode};

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
/// [`Amount`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for Amount {}
/// [`Sequence`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for Sequence {}
/// [`transaction::Version`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for transaction::Version {}
/// [`OutPoint`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for OutPoint {}
/// [`Transaction`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for Transaction {}
/// [`TxOut`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for TxOut {}
/// [`Witness`] uses its consensus encoding and decoding for PSBT.
impl PsbtDelegate for Witness {}
