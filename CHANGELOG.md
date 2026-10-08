# Changelog

## [Unreleased]

- Fix `Psbt::deserialize` rejecting PSBTv2 outputs whose `PSBT_OUT_SCRIPT` value is empty (BIP-370 requires the key's
  presence, not a non-empty scriptPubKey). Remove `output::ValidationError::MissingScriptPubkey`; missing
  `PSBT_OUT_SCRIPT` is now detected during decoding via `output::DecodeError::MissingScriptPubkey`.

- Handle multi-byte `keytype`s [#94](https://github.com/rust-bitcoin/rust-psbt/pull/94).
- Bump miniscript to `v13.0.0`.
- Insource psbt related changes from `miniscript@13.0.0` [#163](https://git.rust-bitcoin.org/rust-bitcoin/rust-psbt/pulls/163): 
    - Fix: skip re-finalizing PSBT inputs that already have `final_script_sig` or `final_script_witness` which could
    cause a failure if re-finalized [rust-miniscript#960](https://github.com/rust-bitcoin/rust-miniscript/pull/960).
    - Replace `descriptor::ConversionError` by `descriptor::NonDefiniteKeyError`. The `Error` variant in the return
    type of the `update_with_descriptor_unchecked` methods from `PsbtInputExt` and `PsbtOutputExt` is
    `descriptor::NonDefiniteKeyError` from now on.
    - Remove `PartialOrd, Ord, Hash, Clone, Copy` derivations from `OutputUpdateError` and `UtxoUpdateError`.
    - `PsbtInputSatisfier` no longer exposes the `psbt` and `index` fields publicly. Now the accessors are the methods
    `psbt` for the inner PSBT and `psbt_input` for the input the `PsbtInputSatisfier` is applied on.
    - Update `miniscript::Satisfier.lookup_tap_key_spend_sig` impl for `v0::miniscript::PsbtInputSatisfier` and
    `v2::miniscript::InputSatisfier`. Now `lookup_tap_key_spend_sig` takes a public key as parameter.
    - Make `Translator.pk` impl for `KeySourceLookUp` infallible. The output is still wrapped in a `Result`, unwrapping
    it will always return the successful variant. 
- Bump miniscript to `v13.1.0`.
- Insource psbt related changes from `miniscript@13.1.0` [#180](https://git.rust-bitcoin.org/rust-bitcoin/rust-psbt/pulls/180): 
    - Create `PlanExt` public trait and implement `update_psbt_input` copying the code from `miniscript::plan::Plan.update_psbt_input`.
- `Psbt.signer_checks` related changes [#186](https://git.rust-bitcoin.org/rust-bitcoin/rust-psbt/pulls/186):
    - Fix malformed `P2SH-P2WSH` checks.
    - Remove `SignerChecksError`.
    - Add new `SignError` variants:
        - `NonWitnessSig`.
        - `NonWitnessUtxoTxidMismatch`.
        - `WitnessAndNonWitnessUtxo`.
        - `RedeemScriptMismatch`.
        - `MissingTxOut`.
        - `WitnessScriptMismatchWsh`.
        - `WitnessScriptMismatchShWsh`.
        - `SigHashMismatch`.
    - Added `index: usize` parameter to `signer_checks` method. Now it can be executed on individual inputs.
    - Change `signer_checks` error return type from `SignerChecksError` to `SignError`.
    - Execute `Psbt.signer_checks` before any `Psbt.sign` operation. The `Psbt.sign` call can now fail with the new `SignError` variants.

## [0.3.0] - 2026-03-24

The 0.3.0 version is the last major release for `bitcoin v0.32.x`. Only security patches will be added to the v0.3.x branch.

- Bump MSRV to Rust `v1.74.0`.
- Upgrade dependencies and copied implementations.
  - `bitcoin v0.32.8`
  - `miniscript v12.3.5`
- Simplify feature flags.
  - Consolidate miniscript into a single `miniscript` feature
  - Rename `rand-std` to `rand`
  - Remove the `no-std` feature (use `default-features = false` instead).
- Add `silent-payments` feature.

## [0.2.0] - 2024-08-22

- Bump MSRV to Rust `v1.63.0` [#27](https://github.com/tcharding/rust-psbt/pull/27)
- Upgrade dependencies [#26](https://github.com/tcharding/rust-psbt/pull/26)
   - `bitcoin v0.32.0`
   - `miniscript 12.2.0`

## [0.1.1] - 2024-02-08

Add various combinations of the three bips as keywords.

## [0.1.0] - 2024-02-08

The initial non-beta release!

Includes some fixes required to enable porting `bdk` to use the `v0` module.

## [0.1.0-beta.1] - 2024-02-08

- Re-import all the PSBT v0 code from `rust-bitcoin` and `rust-miniscript`[#23](https://github.com/tcharding/rust-psbt/pull/23)
- Add initial basic integration testing against Bitcoin Core [#21](https://github.com/tcharding/rust-psbt/pull/21)
  and [#22](https://github.com/tcharding/rust-psbt/pull/22)

## [0.1.0-beta.0]- 2024-02-02

The initial beta release. The aim of this release is to make the new PSBT v2 API available for beta
testing. Currently we expose the v0 API pretty much as it is in `rust-bitcoin` and `rust-miniscript`.

Enjoy!

[Unreleased]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.3.0...HEAD
[0.3.0]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.2.0...psbt-v2-0.3.0
[0.2.0]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.1.1...psbt-v2-0.2.0
[0.1.1]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.1.0...psbt-v2-0.1.1
[0.1.0]: https://github.com/rust-bitcoin/rust-psbt/compare/0.1.0-beta.1...psbt-v2-0.1.0
[0.1.0-beta.1]: https://github.com/rust-bitcoin/rust-psbt/compare/0.1.0-beta.0...0.1.0-beta.1
[0.1.0-beta.0]: https://github.com/rust-bitcoin/rust-psbt/releases/tag/0.1.0-beta.0
