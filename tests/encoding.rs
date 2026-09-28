// SPDX-License-Identifier: CC0-1.0

//! Integration tests for PSBT encoding.

use bitcoin::locktime::absolute;
use bitcoin::{transaction, Sequence};
use bitcoin_consensus_encoding::{Decoder, DecoderStatus};
#[cfg(feature = "std")]
use psbt_v2::encode_to_writer;
use psbt_v2::{
    decode_from_slice, encode_to_hex, encode_to_vec, PrefixedSliceEncoder, PsbtDecode, PsbtEncode,
    VecDecoder, Version,
};

/// A type with a length-prefixed vector field.
struct Sequences(Vec<Sequence>);

impl PsbtEncode for Sequences {
    type Encoder<'e>
        = PrefixedSliceEncoder<'e, Sequence>
    where
        Self: 'e;

    fn psbt_encoder(&self) -> Self::Encoder<'_> { PrefixedSliceEncoder::new(&self.0) }
}

struct SequencesDecoder(VecDecoder<Sequence>);

impl Default for SequencesDecoder {
    fn default() -> Self { Self(VecDecoder::new()) }
}

impl Decoder for SequencesDecoder {
    type Output = Sequences;
    type Error = <VecDecoder<Sequence> as Decoder>::Error;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<DecoderStatus, Self::Error> {
        self.0.push_bytes(bytes)
    }

    fn end(self) -> Result<Sequences, Self::Error> { self.0.end().map(Sequences) }

    fn read_limit(&self) -> usize { self.0.read_limit() }
}

impl PsbtDecode for Sequences {
    type Decoder = SequencesDecoder;
}

#[test]
fn version_encode_to_vec() {
    let version = Version::TWO;
    let bytes = encode_to_vec(&version);
    assert_eq!(bytes, vec![0x02, 0x00, 0x00, 0x00]);
}

#[test]
fn version_encode_to_hex() {
    let version = Version::ZERO;
    let hex = encode_to_hex(&version, bitcoin_consensus_encoding::hex::Case::Lower);
    assert_eq!(hex, "00000000");
}

#[cfg(feature = "std")]
#[test]
fn version_encode_to_writer() {
    use std::io::Cursor;

    let version = Version::TWO;
    let mut buf = vec![];
    let mut cursor = Cursor::new(&mut buf);
    encode_to_writer(&mut cursor, &version).expect("write failed");
    assert_eq!(buf, vec![0x02, 0x00, 0x00, 0x00]);
}

#[test]
fn sequence_encode_to_vec() {
    let seq = Sequence::ZERO;
    let bytes = encode_to_vec(&seq);
    assert_eq!(bytes, vec![0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn sequence_encode_to_hex() {
    let seq = Sequence::MAX;
    let hex = encode_to_hex(&seq, bitcoin_consensus_encoding::hex::Case::Lower);
    assert_eq!(hex, "ffffffff");
}

#[cfg(feature = "std")]
#[test]
fn sequence_encode_to_writer() {
    use std::io::Cursor;

    let seq = Sequence::ZERO;
    let mut buf = vec![];
    let mut cursor = Cursor::new(&mut buf);
    encode_to_writer(&mut cursor, &seq).expect("write failed");
    assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn sequences_encode_to_vec() {
    let seqs = Sequences(vec![Sequence::ZERO, Sequence::MAX]);
    let bytes = encode_to_vec(&seqs);
    assert_eq!(bytes, vec![0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]);
}

#[test]
fn sequences_encode_empty() {
    let bytes = encode_to_vec(&Sequences(Vec::new()));
    assert_eq!(bytes, vec![0x00]);
}

#[test]
fn sequences_decode_from_slice() {
    let bytes = [0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff];
    let seqs: Sequences = decode_from_slice(&bytes).expect("decode failed");
    assert_eq!(seqs.0, vec![Sequence::ZERO, Sequence::MAX]);
}

#[test]
fn sequences_decode_empty() {
    let bytes = [0x00];
    let seqs: Sequences = decode_from_slice(&bytes).expect("decode failed");
    assert!(seqs.0.is_empty());
}

#[test]
fn sequences_decode_truncated() {
    // Prefix claims two elements but only one is present.
    let bytes = [0x02, 0x00, 0x00, 0x00, 0x00];
    let res = decode_from_slice::<Sequences>(&bytes);
    assert!(res.is_err());
}

#[test]
fn sequences_roundtrip() {
    let seqs = Sequences(vec![Sequence::ZERO, Sequence::MAX, Sequence::ZERO]);
    let bytes = encode_to_vec(&seqs);
    let decoded: Sequences = decode_from_slice(&bytes).expect("decode failed");
    assert_eq!(decoded.0, seqs.0);
}

#[test]
fn vec_decoder_read_limit_lifecycle() {
    let mut decoder = VecDecoder::<Sequence>::new();
    assert!(decoder.read_limit() > 0);

    // One-element vector of a 4-byte sequence.
    let mut bytes: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x00];
    let status = decoder.push_bytes(&mut bytes).unwrap();
    assert!(status.is_ready());
    assert_eq!(decoder.read_limit(), 0);
}

#[test]
fn tx_version_roundtrip() {
    let version = transaction::Version::TWO;
    let bytes = encode_to_vec(&version);
    assert_eq!(decode_from_slice::<transaction::Version>(&bytes).unwrap(), version);
}

#[test]
fn lock_time_roundtrip() {
    let lock_time = absolute::LockTime::from_height(700_000).unwrap();
    let bytes = encode_to_vec(&lock_time);
    assert_eq!(decode_from_slice::<absolute::LockTime>(&bytes).unwrap(), lock_time);
}
