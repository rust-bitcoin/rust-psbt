// SPDX-License-Identifier: CC0-1.0

//! Decode a PSBT from hex and print its JSON representation. First attempts v2 decoding, falls back
//! to v0 if necessary. Check out the test vectors under tests/ for some example hex blobs.
//!
//! ```sh
//! # BIP-174 create vector (empty PSBT with 2 inputs, 2 outputs)
//! cargo run --example psbt2json --features serde -- \
//!   70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000
//! ```

use std::{env, process};

use psbt_v2::bitcoin::hex::FromHex;
use psbt_v2::{Psbt, PsbtV0};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: psbt2json <psbt-hex>");
        process::exit(1);
    }

    let bytes = Vec::from_hex(&args[1]).unwrap_or_else(|e| {
        eprintln!("Invalid hex: {e}");
        process::exit(1);
    });

    let psbt = Psbt::deserialize(&bytes).unwrap_or_else(|_| {
        let v0 = PsbtV0::deserialize(&bytes).unwrap_or_else(|e| {
            eprintln!("Failed to decode PSBT: {e}");
            process::exit(1);
        });
        eprintln!("Decoded as v0 PSBT (BIP-174)");
        v0.into_psbt()
    });

    println!("{}", serde_json::to_string_pretty(&psbt).expect("PSBT serialization is infallible"));
}
