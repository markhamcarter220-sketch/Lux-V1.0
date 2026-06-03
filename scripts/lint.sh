#!/usr/bin/env bash
# Full lint pass — must be green before any PR is merged.
set -euo pipefail

echo "==> rustfmt check"
cargo fmt --all -- --check

echo "==> clippy (all targets, all features, deny warnings)"
cargo clippy --all-targets --all-features -- -D warnings \
  -D clippy::pedantic \
  -D clippy::cargo \
  -D clippy::nursery \
  -A clippy::module_name_repetitions

echo "==> cargo deny"
cargo deny check

echo "lint: PASSED"
