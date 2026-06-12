# Build Attestation and Reproducible Builds

This document describes the supply-chain evidence chain for Lux Kernel release
binaries, the tools that generate it, and the exact commands an auditor should
run to verify each link.

---

## Chain of Evidence Overview

```
Cargo.lock  ──┐
              ├──► cargo-deny  ──► policy enforcement (license, advisory, registry)
              │
              ├──► cargo-auditable ──► ELF .note.cargo (dependency snapshot in binary)
              │
              └──► cargo-sbom ──────► target/spdx.json (SPDX 2.3 SBOM)
```

Every release binary should be traceable from source to binary through this
chain without requiring the original source tree.

---

## Tool Descriptions

### `cargo-auditable`

`cargo-auditable` embeds a compressed JSON snapshot of the complete dependency
tree directly into the compiled ELF binary, in a dedicated `.note.cargo` section
(RUSTSEC auditable format).

- **What it captures**: crate name, version, source (crates.io / git / path),
  and the feature flags active at build time, for every transitive dependency.
- **Why it matters**: `cargo audit bin <binary>` can check a shipped binary for
  known RUSTSEC advisories without access to the source tree or `Cargo.lock`.
- **Format**: zlib-compressed JSON inside an ELF note, readable by
  `rust-audit-info <binary>`.
- **Build command**: `cargo auditable build --release`
- **Install**: `cargo install cargo-auditable`

### `cargo-sbom`

`cargo-sbom` generates a Software Bill of Materials from the resolved dependency
graph.  Lux uses the SPDX 2.3 JSON format (`--output-format spdx_json_2_3`).

- **What it captures**: all transitive dependencies with SPDX package identifiers,
  checksums (sha256 of the `.crate` tarball from crates.io), declared licenses,
  and a document-level creation timestamp.
- **Why it matters**: SPDX is the industry-standard interchange format for
  supply-chain tooling, licence compliance, and vulnerability databases (OSV,
  NVD).
- **Output file**: `target/spdx.json`
- **Build command**: `cargo sbom --output-format spdx_json_2_3 > target/spdx.json`
- **Install**: `cargo install cargo-sbom`

### `Cargo.lock`

`Cargo.lock` is checked into the repository (version 3 format) and pins every
transitive dependency to an exact version and source checksum.  It is the
authoritative source-of-truth for the dependency graph at any given commit.

- Pinning prevents "version drift" between developer and CI builds.
- `Cargo.lock.sha256` (written by `scripts/attest.sh`) ties the lock file
  to a specific hash so auditors can confirm the lock file has not changed
  between the build and review.

### `cargo-deny`

`deny.toml` configures `cargo deny check` to enforce:

- **advisories**: rejects crates with open RUSTSEC advisories.
- **licenses**: allowlist of approved SPDX license identifiers; unlicensed or
  non-allowlisted crates fail the gate.
- **sources**: only crates.io and local path/git sources from known repositories
  are permitted; unknown registries are denied.
- **bans**: duplicate crate versions policy.

`cargo-deny` runs in Phase 2 of `scripts/ci_full.sh` on every CI invocation.

---

## Verification Steps for Auditors

Run these four commands against a release binary and the accompanying
`target/spdx.json` and `Cargo.lock`:

### Step 1 — Verify the lock file has not changed

```bash
sha256sum --check target/Cargo.lock.sha256
```

Expected: `Cargo.lock: OK`

If this fails, the `Cargo.lock` used at build time differs from the one in the
working tree, meaning the dependency graph may have silently changed.

### Step 2 — Audit the binary for RUSTSEC advisories

```bash
# Install: cargo install cargo-audit
cargo audit bin target/release/lux_kernel
```

This reads the `.note.cargo` section embedded by `cargo-auditable` and checks
every dependency against the RUSTSEC advisory database.  A clean run produces
no findings.

### Step 3 — Inspect the embedded dependency snapshot

```bash
# Install: cargo install rust-audit-info
rust-audit-info target/release/lux_kernel
```

This pretty-prints the JSON dependency tree from the ELF note section.  Compare
the output against `Cargo.lock` to confirm they describe the same graph.

### Step 4 — Validate the SPDX SBOM

```bash
# Install: pip install spdx-tools
pyspdxtools validate target/spdx.json
```

A valid SBOM produces `The document is valid.`  Cross-reference the package list
against `Cargo.lock` to confirm all transitive dependencies are present.

---

## CI Integration

`scripts/ci_full.sh` Phase 7 runs both tools automatically:

1. `cargo auditable build --release` — builds the auditable binary.
2. `cargo sbom --output-format spdx_json_2_3 > target/spdx.json` — writes the SBOM.

Both steps are skipped with a clear message if the tools are not installed,
matching the skip-pattern used for `cargo-llvm-cov` (Phase 5) and `lake` (Phase 6).

For convenience, `scripts/attest.sh` runs the full attestation pipeline and
prints a summary block with the binary SHA-256, Cargo.lock SHA-256, and SBOM
path.

---

## Known Gaps

The following supply-chain hardening items are **not yet implemented**.
They represent the gap between current state and a fully attested release:

| Gap | Description | Suggested remedy |
|-----|-------------|------------------|
| **No sigstore/cosign signing** | The binary and SBOM are hashed but not cryptographically signed by an identity | Integrate `cosign sign-blob` in CI with OIDC keyless signing |
| **SBOM is unsigned** | `target/spdx.json` has no detached signature; an attacker with CI write access could substitute it | Sign with `cosign sign-blob` or GPG; publish signature alongside the SBOM |
| **TPM attestation is NullTpm in default build** | `tpm` feature is off by default; builds use `NullTpm` which provides no hardware root of trust | Enable `--features tpm` with a real TPM 2.0 driver in hardened deployments |
| **No Sigstore Rekor transparency log entry** | Build provenance is not published to a public transparency log | Use `slsa-github-generator` or `cosign attest` to upload to Rekor |
| **No SLSA provenance document** | The build does not produce a SLSA v1.0 provenance attestation | Add a `slsa-verifier` step once a GitHub Actions pipeline exists |
| **Reproducibility not verified** | Builds have deterministic flags (`lto=fat`, `codegen-units=1`) but bit-for-bit reproducibility has not been confirmed across independent build environments | Run `reprotest` or compare SHA-256 from two independent CI environments |

These gaps should be resolved before the external security audit described in
`CLAUDE.md`.
