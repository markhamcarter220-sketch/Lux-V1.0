#!/usr/bin/env bash
# build_lux.sh — Build and install the lux_kernel PyO3 extension.
#
# What this does:
#   1. Installs maturin (PyO3's build tool) into the current Python environment.
#   2. Runs `maturin develop --features python` from the project root.
#      This compiles lux_kernel with the `python` feature (std + PyO3) and
#      installs the resulting .so extension into the active Python environment.
#   3. Verifies the import succeeds.
#
# Run from any directory:
#   bash hiring-audit/build_lux.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "[build_lux] Project root: $PROJECT_ROOT"
echo "[build_lux] Installing maturin..."
pip install --quiet "maturin>=1.0,<2.0" --break-system-packages 2>/dev/null \
  || pip install --quiet "maturin>=1.0,<2.0"

echo "[build_lux] Building lux_kernel extension (features=python)..."
cd "$PROJECT_ROOT"
maturin develop --features python --release

echo "[build_lux] Verifying import..."
python3 -c "
import lux_kernel
print('[build_lux] lux_kernel imported successfully.')
log = lux_kernel.PyAuditLog()
gate = lux_kernel.PyPolicyGate(
    approved_features=['years_experience','education_level','technical_skills',
                       'communication_score','problem_solving','fit_score'],
    blocked_attrs=['age','gender','race','ethnicity','sex'],
)
print('[build_lux] PyAuditLog:', repr(log))
print('[build_lux] PyPolicyGate:', repr(gate))
print('[build_lux] Build verified OK.')
"
