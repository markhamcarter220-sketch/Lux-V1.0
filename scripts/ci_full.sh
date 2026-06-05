#!/usr/bin/env bash
# Orchestrates the complete CI gate in the correct order.
# Mirrors the GitHub Actions pipeline for local pre-push validation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "  Lux Kernel — Full CI Gate"
echo "========================================"

echo ""
echo "--- Phase 1: Format & Lint ---"
bash "${SCRIPT_DIR}/lint.sh"

echo ""
echo "--- Phase 2: Supply-Chain Audit ---"
bash "${SCRIPT_DIR}/audit.sh"
cargo deny check

echo ""
echo "--- Phase 3: Unit & Integration Tests ---"
cargo test --all-features --workspace

echo ""
echo "--- Phase 4: Security Path Tests ---"
cargo test --test invariant_enforcement --test privilege_escalation -- --nocapture

echo ""
echo "--- Phase 5: Coverage Threshold ---"
bash "${SCRIPT_DIR}/coverage.sh"

echo ""
echo "========================================"
echo "  ALL GATES PASSED"
echo "========================================"
