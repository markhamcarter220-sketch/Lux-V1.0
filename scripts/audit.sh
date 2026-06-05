#!/usr/bin/env bash
# Supply-chain and advisory audit.  Run before every release cut.
set -euo pipefail

echo "==> cargo audit (deny all advisories)"
cargo audit --deny warnings

echo "==> cargo deny (license + bans)"
cargo deny check advisories licenses bans sources

echo "==> check for unsafe_code in source tree"
# Filter out:
#   1. Comment lines mentioning unsafe
#   2. Outer #[allow(unsafe_code)] attribute
#   3. Inner #![allow(unsafe_code)] attribute (Python FFI module — reviewed)
#   4. deny(unsafe_code) lint gate in lib.rs (this denies unsafe, not allows it)
if grep -rn "unsafe" src/ --include="*.rs" \
    | grep -v "//.*unsafe" \
    | grep -v "#!\?\[allow(unsafe_code)\]" \
    | grep -v "deny(unsafe_code)"; then
  echo "ERROR: unsafe code detected in src/ — review required"
  exit 1
fi

echo "audit: PASSED"
