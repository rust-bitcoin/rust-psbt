# Changelog

## [Unreleased]

## 0.4.0 - Unreleased

The 0.4.0 release is a near-complete rewrite of the crate. The role-based
v2 API is now the primary interface, the v0 module has been reduced to
serialization-only, and the old serialization module is replaced by the new
sans-I/O encoding.

The MSRV remains at 1.74.0, but the main `bitcoin` and `miniscript` dependencies
have been upgraded. `bitcoin` went from `0.32.8` to `0.32.102` and enabled the
new `encoding` feature. `miniscript` went from `12.3.5` to `13.2.0`.

### V2 Roles are the Primary API

The `Psbt` type at the crate root is now a v2 PSBT. The v0 module is private and
reduced to codec-only: deserialize v0 bytes with `PsbtV0Decoder`, manipulate as
v2, and serialize back to v0 with `PsbtV0Encoder` (with a `Degraded` marker for
the lossy v2 to v0 direction). See the [deprecation ADR] for rationale.

The roles are now the primary interface to build a PSBT. There are five
always-available roles: `Creator` starts a blank PSBT, `Constructor` fills
in the inputs and outputs, `Updater` can changes some data in the inputs and
outputs, `Signer` produces and adds signatures (see the [signer ADR]), and
`Extractor` pulls out the final signed transaction. A sixth role, `Finalizer`,
completes the signature data into final scripts and is available under the
`miniscript` feature.

[deprecation ADR]: docs/adr/0001_deprecate_v0_api.md
[signer ADR]: docs/adr/0002_signer_design.md

### Encoding

A new sans-I/O, `no_std` compatible encoding system replaces the
old serialization via the `bitcoin_consensus_encoding` crate. The
`PsbtEncode`/`PsbtDecode` traits produce and consume the canonical PSBT wire
format.

`Psbt` exposes inherent convenience methods, `deserialize(bytes)` and
`serialize()`, for the common cases. For callers who need to drive I/O
themselves (synchronous, asynchronous, or embedded) the `PsbtV2Decoder`
and `PsbtV2Encoder` types implement the `bitcoin_consensus_encoding` sans-I/O
`Decoder`/`Encoder` interfaces.

### Release Candidates

#### [0.4.0-rc.1] - 2026-11-20

- The initial release candidate for 0.4.0.

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

## [0.1.0-beta.0] - 2024-02-02

The initial beta release. The aim of this release is to make the new PSBT v2 API available for beta
testing. Currently we expose the v0 API pretty much as it is in `rust-bitcoin` and `rust-miniscript`.

Enjoy!

[Unreleased]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.4.0-rc.1...HEAD
[0.4.0-rc.1]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.3.0...psbt-v2-0.4.0-rc.1
[0.3.0]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.2.0...psbt-v2-0.3.0
[0.2.0]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.1.1...psbt-v2-0.2.0
[0.1.1]: https://github.com/rust-bitcoin/rust-psbt/compare/psbt-v2-0.1.0...psbt-v2-0.1.1
[0.1.0]: https://github.com/rust-bitcoin/rust-psbt/compare/0.1.0-beta.1...psbt-v2-0.1.0
[0.1.0-beta.1]: https://github.com/rust-bitcoin/rust-psbt/compare/0.1.0-beta.0...0.1.0-beta.1
[0.1.0-beta.0]: https://github.com/rust-bitcoin/rust-psbt/releases/tag/0.1.0-beta.0
