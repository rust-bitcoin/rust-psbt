# Contributing

- [Architecture Decisions](#architecture-decisions)
- [Development Workflow](#development-workflow)
- [Policies](#policies)

We have a dedicated developer channel on IRC, #bitcoin-rust@libera.chat where you may get helpful advice if you have questions.

## Architecture Decisions

Important architectural decisions are documented as Architecture Decision Records (ADRs) in the [`docs/adr/`](docs/adr/) directory. These records explain the rationale behind major design choices and are essential reading for contributors looking to understand the project direction.

- [ADR-0001: Deprecating the V0 API](docs/adr/0001_deprecate_v0_api.md) - Plans for transitioning away from the v0 module to establish v2 as the primary API.
- [ADR-0002: Signer Design Decisions](docs/adr/0002_signer_design.md) - Design decisions for the PSBT signing interface.

## Development Workflow

We use [`cargo-rbmt`][rbmt] for managing toolchains, lockfiles, and common development tasks.

```bash
cargo rbmt test
cargo rbmt lint
cargo rbmt fmt
```

Some helpful [cargo aliases](.cargo/config.toml) follow the comma-prefix convention.

```bash
cargo ,mutants -- -- -Z unstable-options --fail-fast
```

### Integration Tests with Bitcoin Core

The `bitcoind-tests/` package contains integration tests that run against real Bitcoin Core instances. A separate package is used so that bitcoind version flags don't pollute the rust-psbt crate. The package has its own lockfile so that it doesn't affect dependency version resolution.

```bash
cargo rbmt integration
```

## Policies

We follow [rust-bitcoin] policies unless otherwise stated here.

### stacked attributes

Use stacked attributes over `#[cfg(all(...))]` when a simple conjunction applies to the same item.

Good:
```rust
#[cfg(feature = "alloc")]
#[cfg(feature = "hex")]
```
Bad:
```rust
#[cfg(all(feature = "alloc", feature = "hex"))]
```

[rust-bitcoin]: <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/CONTRIBUTING.md>
[rbmt]: <https://crates.io/crates/cargo-rbmt>
