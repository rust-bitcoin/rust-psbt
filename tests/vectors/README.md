# Test Vectors

The test vectors live in `tests/data/*.json` as plain data. The runner in
`tests/vectors/mod.rs` reads them and dispatches each case to the appropriate
handler based on its `task` field. Keeping the two separate means you can edit
vectors without touching Rust, cases run in parallel, and a broken case is easy
to pin down.

Each spec (`bip174`, `bip370`, `bip371`, `bip375`) has a corresponding
`tests/<spec>.rs` file with one `#[test]` per case, grouped into modules
(`invalid`, `valid`, `workflow`, `determine_lock_time`) by task type.

## How the runner works

The JSON file is loaded once. Each entry in `cases` becomes its own `#[test]`,
so `cargo test` output maps one line per vector. Each `#[test]` calls the spec
function with the case's *description* as a lookup key.

```rust
#[test]
fn missing_outputs() {
    bip174("Invalid: missing outputs in PSBT");
}
```

The runner finds the case with a matching `description` field, validates it,
and dispatches to the handler for its `task` type.

Because each vector is its own `#[test]`, isolating a broken case is as simple
as running `cargo test` with its name. The namespace grouping also lets you
target a whole category in one go:

```sh
# Run a single case
cargo test --all-features --test bip174 missing_outputs

# Run every invalid case
cargo test --all-features --test bip174 invalid
```

## Looking things up with `jq`

Find a case by a word in its description:
```sh
jq '[.cases | to_entries[] | select(.value.description | test("<substr>"; "i")) | .key]' tests/data/bip174.json
```

Find a case by its expected PSBT hex:
```sh
jq '[.cases | to_entries[] | select(.value.expected.hex == "<hex>") | .key]' tests/data/bip174.json
```

List all case descriptions grouped by task type:
```sh
jq '[.cases[] | {task: .supplementary.task, desc: .description}] | group_by(.task) | map({(.[0].task): [.[].desc]}) | add' tests/data/bip174.json
```

## Adding a new test vector

Only add cases when the upstream BIP vectors gain a new one.

1. Append an entry to `cases` in the appropriate `tests/data/<spec>.json`:
   - `description` — start with `Valid:`, `Invalid:`, or `Workflow` so it
     matches the module grouping convention.
   - `supplementary.task` — pick the handler that should run.
   - The fields that handler reads. The authoritative list is the `Supplementary`
     struct in `tests/vectors/mod.rs`; only set what your case actually uses.
   - `expected.hex` — the resulting PSBT. Omit for `fail_*` tasks. For
     `extract`, put the expected transaction hex in `supplementary.tx` instead.

2. Add a `#[test]` shim in the corresponding `tests/<spec>.rs` under the
   right module (match by task type: `fail_deserialize`/`fail_sign` go in
   `invalid`, `deserialize` goes in `valid`, etc.):
   ```rust
   #[test]
   fn my_new_case() {
       bip174("Valid: my new case description");
   }
   ```
   The string must exactly match the `description` field in the JSON.

3. If your case needs data the runner doesn't yet understand, add a field to
   `Supplementary` and extend the relevant handler.
