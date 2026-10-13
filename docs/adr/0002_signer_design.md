# Signer Design Decisions

* Status: in-progress
* Date: 2026-10-12

Living record of the new `Signer` design decisions; sections are appended as they are
made.

## Verification should not be void, it must produce evidence

Following *Parse, don't validate*[^1]: a check that returns `Ok(())` lets the caller
discard the proof and forces the next consumer to re-derive what was just checked.
Verification instead returns a value whose type is the proof: a `SignableInput` is
created only by `verify` (untrusted data) or `assume_checked` (caller-attested data),
and the signing methods accept nothing else, so checked data is exactly what gets
signed. The same rule applies to bounds checks: `checked_input` returns the checked
`&Input`, not `()`.

Staging every fallible check at creation leaves signing infallible: `get_input_sigs`
has no error type, and `apply` fails only on an out-of-bounds index, which requires a
signature batch produced against a different `Psbt`.

## One Session, One Readable `Psbt`, One Writable Sighash Cache

Every signature in a session must commit to the transaction the sighash cache was
built from, so `Signer` owns the `Psbt` and builds the `SighashCache` at construction,
failing upfront if the lock time cannot be determined. Writing signatures needs
`&mut Psbt`, which conflicts with live evidence, so signing runs in two phases:

```rust
let mut signer = Signer::new(psbt)?;
let sigs = {
    let mut session = signer.session();      // lends Psbt + cache
    let inputs = session.signable_inputs()?; // verify every input
    session.get_all(&inputs, &keys, &secp)   // signatures, detached
};                                           // session dropped, Psbt unfrozen
let psbt = signer.apply(sigs)?;              // writes, clears TX_MODIFIABLE
```

A `SignableInput` carries `&'a Psbt`, so the borrow checker forbids mutating the
`Psbt` while any is alive. The evidence snapshots everything the sighash commits to -
prevout, script code, sighash type, taproot spent outputs - so remaining live reads
are shape-only (key lookup). `SigningSession` holds `&'a Psbt` and
`&'a mut SighashCache` under one lifetime, letting the cache be reused while the
`Psbt` stays frozen.

## Two Verification Paths, One Explicit Trust Boundary

A PSBT alone cannot prove the amount of a witness-only non-P2TR input, and signing an
unattested amount enables the fee-inflation attack[^2]. Strict creation (`verify`)
therefore requires the full funding transaction for those inputs; P2TR is exempt
because the BIP-341 sighash commits to amount and scriptPubKey.

Callers who verified funding data against their own UTXO set use the trusted path
(`assume_checked`), which skips only the caller-attested checks - `UnverifiableUtxo`
and the script/signature consistency checks; structural checks still run via the
shared `check_data`. The trust level is chosen by which method is called, never by a
flag; the trusted funding accessor stays crate-private, and the test vectors mirror
the split with `strict_sign` / `trusted_sign` tasks.

## Roles Own Workflow, `Psbt` Owns Data

A signing API directly on `Psbt` couples the data structure with the signing
workflow. By removing `Psbt::sign` and signing through `Signer`, that coupling
is broke.

[^1]: Alexis King, "Parse, don't validate", 2019. <https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/>
[^2]: Bitcoin Optech Newsletter #101, "Fee overpayment attack on multi-input segwit transactions". <https://bitcoinops.org/en/newsletters/2020/06/10/#fee-overpayment-attack-on-multi-input-segwit-transactions>
