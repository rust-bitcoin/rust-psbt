// SPDX-License-Identifier: CC0-1.0

//! Guards against quadratic retained allocation when a session creates the complete set of
//! signable inputs for a Taproot PSBT (see the signer role for the fixed behavior).

#![cfg(feature = "std")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use psbt_v2::bitcoin::hashes::Hash;
use psbt_v2::bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use psbt_v2::bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
use psbt_v2::{Global, Input, Output, Psbt, Signer};

thread_local! {
    // Cumulative requested bytes for only the thread running the operation.
    static ALLOCATED: Cell<Option<usize>> = const { Cell::new(None) };
}

struct CountingAllocator;

fn count(bytes: usize) {
    let _ = ALLOCATED.try_with(|counter| {
        if let Some(total) = counter.get() {
            counter.set(Some(total.saturating_add(bytes)));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count(size);
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn strict_validation_allocations(input_count: u32) -> usize {
    let script = ScriptBuf::new_p2tr(
        &Secp256k1::verification_only(),
        XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        None,
    );
    let inputs = (0..input_count)
        .map(|index| {
            let mut input =
                Input::new(&OutPoint { txid: Txid::from_byte_array([3u8; 32]), vout: index });
            input.witness_utxo =
                Some(TxOut { value: Amount::from_sat(1_000), script_pubkey: script.clone() });
            input
        })
        .collect();
    let psbt = Psbt {
        global: Global { input_count: input_count as usize, output_count: 1, ..Global::default() },
        inputs,
        outputs: vec![Output::new(TxOut { value: Amount::from_sat(500), script_pubkey: script })],
    };

    // The request has matching counts and ordinary serialized input maps.
    // Exclude fixture construction and decoding from the allocation measurement.
    let decoded = Psbt::deserialize(&psbt.serialize()).unwrap();
    let mut signer = Signer::new(decoded).unwrap();
    ALLOCATED.with(|counter| counter.set(Some(0)));
    let (len, allocated) = signer.session(|session| {
        let checked = session.signable_inputs();
        std::hint::black_box(&checked);
        let allocated = ALLOCATED.with(|counter| counter.replace(None).unwrap());
        (checked.map(|inputs| inputs.len()), allocated)
    });
    assert_eq!(len.unwrap(), input_count as usize);
    allocated
}

#[test]
fn strict_taproot_validation_has_linear_allocation_growth() {
    let small = strict_validation_allocations(128);
    let large = strict_validation_allocations(512);
    assert!(small > 0);

    // Four times as many fixed-size input maps get an eight-fold allowance.
    // Retaining a complete cloned prevout vector in every signable input would
    // grow allocation approximately sixteen-fold instead.
    assert!(
        large <= small * 8,
        "quadratic prevout allocation: 128 inputs = {small} bytes; 512 inputs = {large} bytes",
    );
}
