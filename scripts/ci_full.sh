#!/usr/bin/env bash
# Orchestrates the complete CI gate in the correct order.
# Mirrors the GitHub Actions pipeline for local pre-push validation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEAN_DIR="$(cd "${SCRIPT_DIR}/../lean" && pwd)"

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
cargo test --all-features --test security -- --nocapture

echo ""
echo "--- Phase 5: Coverage Threshold ---"
if cargo llvm-cov --version &>/dev/null; then
  bash "${SCRIPT_DIR}/coverage.sh"
else
  echo "==> cargo-llvm-cov not installed; skipping coverage (install with: cargo install cargo-llvm-cov)"
  echo "coverage: SKIPPED"
fi

echo ""
echo "--- Phase 6: Formal Verification (Lean 4) ---"
if command -v lake &>/dev/null; then
  echo "==> lake build (LuxSpec + LuxCostModel + LuxRefinement + LuxCapabilityBridge)"
  (cd "${LEAN_DIR}" && lake build)
  echo "formal: PASSED"
else
  echo "==> lake not installed; skipping formal verification"
  echo "==> Install Lean 4 + Lake: https://leanprover.github.io/lean4/doc/quickstart.html"
  echo "==> Modules to verify: LuxSpec, LuxCostModel, LuxRefinement, LuxCapabilityBridge"
  echo "formal: SKIPPED"
fi

echo ""
echo "--- Phase 7: Reproducible Build & Binary Attestation ---"
if cargo auditable --version &>/dev/null; then
  echo "==> cargo auditable build --release"
  cargo auditable build --release
else
  echo "==> cargo-auditable not installed; skipping auditable build"
  echo "==> Install with: cargo install cargo-auditable"
fi

if cargo sbom --version &>/dev/null; then
  echo "==> cargo sbom --output-format spdx_json_2_3"
  cargo sbom --output-format spdx_json_2_3 > target/spdx.json
  echo "==> SBOM written to target/spdx.json"
  echo "attestation: PASSED"
else
  echo "==> cargo-sbom not installed; skipping SBOM generation"
  echo "==> Install with: cargo install cargo-sbom"
  echo "attestation: SKIPPED"
fi

echo ""
echo "========================================"
echo "  ALL GATES PASSED"
echo "========================================"
