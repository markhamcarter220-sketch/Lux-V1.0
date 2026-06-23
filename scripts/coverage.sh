#!/usr/bin/env bash
# Generate LLVM coverage report and enforce the 100% security-path threshold.
# Requires: cargo-llvm-cov  (cargo install cargo-llvm-cov)
set -euo pipefail

echo "==> building with instrumentation"
cargo llvm-cov --all-features --workspace \
  --lcov --output-path lcov.info

echo "==> generating HTML report"
cargo llvm-cov report --html --output-dir coverage/

echo "==> enforcing security-path coverage threshold"
# Line coverage for the four I1-I4 enforcement points (CLAUDE.md, README.md).
# `cargo llvm-cov report --json` only reports src/*.rs files, never the
# tests/*.rs drivers that exercise them -- filtering on a tests/ path here
# always matched zero files and made this check vacuously fail every run.
SECURITY_COV=$(cargo llvm-cov report --json 2>/dev/null \
  | python3 -c "
import json, sys
paths = ('src/auth/policy.rs', 'src/auth/capability.rs',
         'src/metabolism/ledger.rs', 'src/topology/graph.rs')
data = json.load(sys.stdin)
files = [f for f in data['data'][0]['files']
         if f['filename'].endswith(paths)]
missing = set(paths) - {p for f in files for p in paths if f['filename'].endswith(p)}
if missing:
    sys.exit(f'enforcement-point file(s) not found in report: {sorted(missing)}')
total = sum(f['summary']['lines']['count'] for f in files)
covered = sum(f['summary']['lines']['covered'] for f in files)
print(f'{covered}/{total}')
pct = covered / total * 100 if total else 0
sys.exit(0 if pct == 100.0 else 1)
")
echo "security path coverage: ${SECURITY_COV}"
echo "coverage: PASSED"
