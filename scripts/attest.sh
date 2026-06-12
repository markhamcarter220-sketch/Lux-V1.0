#!/usr/bin/env bash
# Builds the lux_kernel binary with embedded dependency metadata,
# generates an SPDX 2.3 SBOM, and prints a summary of hashes for
# supply-chain verification.
set -euo pipefail

echo "========================================"
echo "  Lux Kernel — Build Attestation"
echo "========================================"

echo ""
echo "==> Building with cargo auditable (embeds RUSTSEC audit data into ELF .note section)..."
cargo auditable build --release

echo ""
echo "==> Generating SPDX 2.3 SBOM..."
cargo sbom --output-format spdx_json_2_3 > target/spdx.json
echo "    SBOM written to target/spdx.json"

echo ""
echo "==> Computing binary hash..."
BINARY_SHA=$(sha256sum target/release/lux_kernel 2>/dev/null || echo "binary not found (library crate)")

echo ""
echo "==> Saving Cargo.lock manifest hash..."
sha256sum Cargo.lock > target/Cargo.lock.sha256
LOCK_SHA=$(cat target/Cargo.lock.sha256)

echo ""
echo "========================================"
echo "  Attestation Summary"
echo "========================================"
echo "  Binary SHA-256  : ${BINARY_SHA}"
echo "  Cargo.lock SHA-256: ${LOCK_SHA}"
echo "  SBOM location   : $(pwd)/target/spdx.json"
echo "========================================"
