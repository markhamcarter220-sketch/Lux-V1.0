#!/usr/bin/env bash
# Supply-chain and advisory audit.  Run before every release cut.
set -euo pipefail

echo "==> cargo audit (deny all advisories)"
cargo audit --deny warnings

echo "==> cargo deny (license + bans)"
cargo deny check advisories licenses bans sources

echo "==> check for unsafe_code in source tree"
if grep -rn "unsafe" src/ --include="*.rs" | grep -v "//.*unsafe" | grep -v "#\[allow(unsafe_code)\]"; then
  echo "ERROR: unsafe code detected in src/ — review required"
  exit 1
fi

echo "audit: PASSED"
