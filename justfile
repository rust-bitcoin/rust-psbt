set quiet := true

alias ulf := update-lock-files
alias m := mutants

export RBMT_LOG_LEVEL := env("RBMT_LOG_LEVEL", "progress")

project := file_name(justfile_directory())
rbmt_version := `grep "^rbmt.version" Cargo.toml | cut -d'"' -f2`

_default:
  @just --list

# Install workspace tools including rbmt
[group('rbmt')]
tools:
  echo "{{project}} dev tools [cargo-rbmt@{{rbmt_version}}]"
  cargo install --quiet --locked cargo-rbmt@{{rbmt_version}}
  cargo rbmt toolchains
  cargo rbmt tools

# Run rbmt with given args
[group('rbmt')]
rbmt *args: tools
  cargo rbmt {{args}}

# Update rbmt managed lockfiles
[group('rbmt')]
update-lock-files: (rbmt "lock --lockfiles minimal,maximum")

# Check docs
[group('ci')]
docs: (rbmt "docs --lockfile maximum")

# Format workspace
[group('ci')]
fmt: (rbmt "fmt")

# Lint workspace
[group('ci')]
lint: (rbmt "lint --lockfile maximum")

# Test package on minimal dependency versions
[group('ci')]
test: (rbmt "test --lockfile minimal")

# Check prerelease
[group('ci')]
prerelease: (rbmt "prerelease --force")

# Bitcoin Core integration tests
[group('ci')]
integration: (rbmt "integration")

# Check mutants, filter by given git ref baseline or file glob
[group('ci')]
mutants baseline="" file="": tools
  cargo +$(cargo rbmt toolchains --nightly) mutants \
    {{ if baseline == "" { "" } else { "--in-diff <(git diff " + baseline + ")" } }} \
    {{ if file == "" { "" } else { "--file " + file } }} \
    -- -- -Z unstable-options --fail-fast
