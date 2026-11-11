//! Measures the cost of grinding ECDSA nonces for shorter signatures.
//!
//! Each extra byte saved needs about 8 more zero bits in R or S, so the number of signing attempts
//! grows about 256 times per byte:
//!
//! | DER bytes | Grinding        | Expected attempts |
//! |-----------|-----------------|-------------------|
//! | 71        | none            | 1                 |
//! | 70        | low-R (default) | 2                 |
//! | 69        | 2 bytes         | 256               |
//! | 68        | 3 bytes         | 44,000            |
//! | 67        | 4 bytes         | 8,400,000         |
//!
//! This program times each level with the same secp256k1 calls the Signer uses and prints the time
//! per signature, the cost relative to a plain signature and the longest DER signature seen.
//!
//! ```sh
//! cargo run --release --example grinding_bench
//! cargo run --release --example grinding_bench -- 4
//! ```
//!
//! Level 4 is only measured when asked for, as it takes minutes per signature.
//!
//! Results on an Intel Core i5-13420H:
//!
//! ```text
//! $ cargo run --release --example grinding_bench -- 4
//! grinding            sigs   time per sig     attempts  max DER
//! none               20000        42.9 us           1x       71
//! low-R (default)    20000        86.6 us           2x       70
//! 2 bytes              500        10.4 ms         243x       69
//! 3 bytes               10         1.59 s       37013x       68
//! 4 bytes               10        3.6 min     5018754x       67
//! ```
//!
//! A single 4-byte signature can take anywhere from seconds to many minutes, so the 4-byte time is
//! the mean of 10 signatures. Saving one more byte is not worth that wait, which is why the Signer
//! stops at 3 bytes.

use std::time::Instant;

use psbt_v2::bitcoin::secp256k1::{ecdsa, Message, Secp256k1, SecretKey, SignOnly};

/// A grinding level which defines what it is called, how many signatures to time and how to sign.
struct Level {
    label: &'static str,
    signatures: u32,
    sign: fn(&Secp256k1<SignOnly>, &Message, &SecretKey) -> ecdsa::Signature,
}

fn main() {
    let with_4_bytes = match std::env::args().nth(1).as_deref() {
        None => false,
        Some("4") => true,
        Some(arg) => panic!("unknown argument {arg:?}, pass 4 to also measure 4 bytes"),
    };

    let mut levels = vec![
        Level { label: "none", signatures: 20_000, sign: |secp, msg, sk| secp.sign_ecdsa(msg, sk) },
        Level {
            label: "low-R (default)",
            signatures: 20_000,
            sign: |secp, msg, sk| secp.sign_ecdsa_low_r(msg, sk),
        },
        Level {
            label: "2 bytes",
            signatures: 500,
            sign: |secp, msg, sk| secp.sign_ecdsa_grind_r(msg, sk, 2),
        },
        Level {
            label: "3 bytes",
            signatures: 10,
            sign: |secp, msg, sk| secp.sign_ecdsa_grind_r(msg, sk, 3),
        },
    ];
    if with_4_bytes {
        levels.push(Level {
            label: "4 bytes",
            signatures: 10,
            sign: |secp, msg, sk| secp.sign_ecdsa_grind_r(msg, sk, 4),
        });
    }

    let secp = Secp256k1::signing_only();
    let sk = SecretKey::from_slice(&[7u8; 32]).expect("valid secret key");

    println!(
        "{:<16} {:>7} {:>14} {:>12} {:>8}",
        "grinding", "sigs", "time per sig", "attempts", "max DER"
    );
    let mut plain = None;
    for level in levels {
        let messages = messages(level.signatures);
        let start = Instant::now();
        let max_der = messages
            .iter()
            .map(|msg| (level.sign)(&secp, msg, &sk).serialize_der().len())
            .max()
            .expect("at least one signature");
        let per_sig = start.elapsed().as_secs_f64() / f64::from(level.signatures);
        let plain = *plain.get_or_insert(per_sig);
        println!(
            "{:<16} {:>7} {:>14} {:>11.0}x {:>8}",
            level.label,
            level.signatures,
            format_duration(per_sig),
            per_sig / plain,
            max_der
        );
    }
}

/// `count` distinct messages, so every signature grinds from a different starting nonce.
fn messages(count: u32) -> Vec<Message> {
    (0..count)
        .map(|i| {
            let mut digest = [0u8; 32];
            digest[..4].copy_from_slice(&i.to_le_bytes());
            digest[31] = 1;
            Message::from_digest(digest)
        })
        .collect()
}

fn format_duration(secs: f64) -> String {
    match secs {
        s if s < 1e-3 => format!("{:.1} us", s * 1e6),
        s if s < 1.0 => format!("{:.1} ms", s * 1e3),
        s if s < 60.0 => format!("{:.2} s", s),
        s => format!("{:.1} min", s / 60.0),
    }
}
