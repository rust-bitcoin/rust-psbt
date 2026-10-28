# Test Vectors

The test vectors live in `tests/data/*.json` as plain data. The runner in
`tests/vectors/mod.rs` reads them and dispatches each case to the appropriate
handler based on its task type, the single key under the case's `task` object.
Keeping the two separate means you can edit vectors without touching Rust, cases
run in parallel, and a broken case is easy to pin down.

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
and dispatches to the handler for its task type (the key under the case's
`task` object).

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

Find a case by its expected PSBT base64 (the `expected` field of a task payload):
```sh
jq '[.cases | to_entries[] | select(any(.value.task[]; has("expected") and .expected.base64 == "<base64>")) | .key]' tests/data/bip174.json
```

List all case descriptions grouped by task type:
```sh
jq '[.cases[] | {task: (.task | keys[0]), desc: .description}] | group_by(.task) | map({(.[0].task): [.[].desc]}) | add' tests/data/bip174.json
```

## Adding a new test vector

Only add cases when the upstream BIP vectors gain a new one.

1. Append an entry to `cases` in the appropriate `tests/data/<spec>.json`:
   - `description`: start with `Valid:`, `Invalid:`, or `Workflow` so it
     matches the module grouping convention.
   - `task`: an object with a single key naming the handler that should run,
     e.g. `"task": { "deserialize": { "psbts": [...] } }`. The payload schema
     is determined by that key; the authoritative list is the `Task` enum in
     `tests/vectors/mod.rs`.
   - Input PSBTs live in the task payload. Validation/parse tasks
     (`deserialize`, `fail_deserialize`, `determine_lock_time`, `combine`, etc.)
     use an array `psbts`, while single-input tasks (`fail_sign`,
     `fail_strict_sign`, `strict_sign`, `trusted_sign`, `update`, `finalize`,
     `extract`) use a single `psbt` object.
   - Result-producing tasks (`create`, `update`, `strict_sign`, `trusted_sign`,
     `combine`, `finalize`) put the expected PSBT in the task payload as
     `"expected": { "base64": "..." }`. For `extract`, the expected
     transaction hex goes in `task.extract.tx`.

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
   the relevant `Task` variant and extend its handler.
