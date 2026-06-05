# Lux Kernel — Tier Boundaries

This document defines the precise boundary between each maturity tier, explains
what "complete" means for each tier, and describes the verification evidence
that earns each designation.

---

## Summary Table

| Tier | Label | Status | Evidence |
|------|-------|--------|----------|
| 1 | Core security invariants | **Production-ready** | 63 adversarial tests + TLA+ formal verification |
| 2 | Cryptography, audit, revocation | **Complete** | 18 security tests + 247 total tests passing |
| 2.5 | Compliance reference implementations | **Complete** | 3 domain demos with bias test reports |
| 3 | Hardware integrations (HSM, TPM, WASM, consensus) | **Roadmap** | Interfaces defined; production drivers not yet integrated |

---

## Tier 1 — Production-Ready

**Definition:** The four kernel invariants are mechanically enforced, formally
verified, and adversarially tested. Code in this tier can be used in production
as the enforcement layer beneath systems where fail-closed behaviour is required.

**What "production-ready" means here:**
- Every denied operation returns an explicit typed `Error` — no panics, no silent
  failures, no `unwrap()` in the enforcement path.
- The invariants cannot be bypassed by presenting invalid inputs — every
  non-nominal input is rejected, not defaulted.
- 100% of the security-path tests pass with zero failures.
- TLC model checking across 322,560 distinct states found no counterexample to
  any of the four security theorems.

**What it does NOT mean:**
- It does not mean a third-party security firm has reviewed the code.
- It does not mean the boot manifest delivery channel is cryptographically
  authenticated (that is Tier 2/3).
- It does not mean the implementation is hardened against side-channel attacks.

### Tier 1 Items and Their Evidence

| Item | Implementation | Evidence |
|------|---------------|----------|
| Core error taxonomy | `src/error.rs` | All `Error` variants have a corresponding denial classification; no catch-all |
| Capability token model | `src/auth/capability.rs` | `Capability` fields are `pub(crate)` — no external construction |
| Policy enforcement point | `src/auth/policy.rs` | `Policy::check` fails closed; 12 adversarial tests (inv2) |
| Resource ledger | `src/metabolism/ledger.rs` | `checked_sub` only; 12 adversarial tests (inv3) |
| Topology graph | `src/topology/graph.rs` | Deny-by-default; 12 adversarial tests (inv4) |
| Work queue | `src/scheduler/queue.rs` | Bounded capacity; `enqueue` returns `Err` at capacity |
| Boot manifest framework | `src/boot/` | All inputs return `Ok` or `Err(ManifestInvalid)` |
| Security-path test coverage | `tests/security/` | 18 tests; 100% pass required |
| Adversarial test suite | `tests/adversarial/` | 63 attacks, 0 successful escalations |
| TLA+ formal verification | `tla/` | 322,560 states, 6 invariants, 0 violations |

---

## Tier 2 — Complete

**Definition:** Cryptographic boot manifest verification, capability revocation,
and a tamper-evident audit log are integrated into the kernel. The boot path
is end-to-end authenticated with Ed25519 signatures.

**What "complete" means here:**
- `ManifestDecoder::decode` verifies the Ed25519 signature with `verify_strict`
  (cofactor-clearing, the secure variant) **before** parsing any CBOR content.
- `AuditLog` maintains a SHA-256 hash chain across all appended events;
  `verify_chain()` detects any mutation.
- Capability revocation uses epoch-based generation numbers; a rotated generation
  immediately invalidates all tokens from the previous generation.
- 247 tests pass across unit, integration, property, security, and adversarial
  suites.

**What it does NOT mean:**
- It does not mean the private signing key is protected by hardware (that is
  Tier 3 — HSM integration).
- It does not mean the TPM has attested the boot manifest hash chain.
- The `SoftwareHsm` in `src/hsm/mock.rs` is a software implementation; a
  production deployment would replace it with a hardware-backed driver.

### Tier 2 Items and Their Evidence

| Item | Implementation | Key Test |
|------|---------------|----------|
| CBOR manifest decoder | `src/boot/decode.rs` | 12 adversarial decode tests |
| Ed25519 verification | `src/hsm/mock.rs:88` (`verify_strict`) | `signature_verification` test module |
| Revocation ledger | `src/auth/revocation.rs` | `revocation` integration tests |
| Append-only audit log | `src/audit/log.rs` | `audit_log` integration tests (SHA-256 chain) |
| Property tests | `tests/properties/` | 17 proptest invariant proofs |

---

## Tier 2.5 — Complete

**Definition:** Three compliance reference implementations demonstrate Lux
applied to regulated AI decision-making domains. Each produces a policy-gated
pipeline, a tamper-evident audit log, and a statistical bias report.

**What "complete" means here:**
- Each pipeline runs end-to-end and produces deterministic output.
- Protected attributes are excluded at the policy gate, not filtered in
  pre-processing.
- Chi-squared independence tests confirm statistical independence of outcomes
  from protected attributes at α = 0.05 in all three domains.
- PyO3 bindings connect the Python domain layer to the Rust kernel for
  `hiring-audit/`.

**Intended use:** Reference implementation and integration demonstration.
These are NOT production-grade compliance tools — they are proofs of concept
showing the architectural pattern.

### Tier 2.5 Items

| Item | Location | Key Result |
|------|----------|-----------|
| EU AI Act hiring demo | `hiring-audit/` | race p=0.597, gender p=0.751 |
| Fair lending demo | `lending-audit/` | 5 protected attrs, all p > 0.05 |
| Recidivism governance demo | `recidivism-demo/` | race p=0.916, 1.4-pt gap vs. COMPAS 17-pt |

---

## Tier 3 — Roadmap

**Definition:** Hardware integrations and advanced features that require either
hardware peripherals, nightly Rust features, or additional infrastructure that
is not yet production-integrated.

**What "roadmap" means here:**
- The interfaces and abstractions are defined and tested with software mocks.
- No production hardware driver is wired into the kernel.
- The features are not suitable for production deployment in their current form.

### Tier 3 Items

| Item | Current State | What's Missing |
|------|--------------|----------------|
| HSM-backed capability minting | `SoftwareHsm` mock only | Real PKCS#11 or vendor HSM driver |
| TPM-anchored boot attestation | `SoftwareTpm` / `NullTpm` mocks only | Real TPM 2.0 driver (tpm2-tss or equivalent) |
| Formal cost model | Manual analysis only | Mechanized proof (Lean/Isabelle) |
| WASM execution substrate | `WasmShim` struct defined | Wasmtime/Cranelift integration |
| Distributed topology consensus | `MockTransport` only | Real network transport (QUIC/TLS) |

**Note on scaffolded code:** The source tree contains code for all Tier 3
items (`src/hsm/`, `src/tpm/`, `src/wasm/`, `src/consensus/`). This code
compiles, is tested with mocks, and defines the integration interfaces. It
is not a complete production implementation — it is the abstraction layer
that a production driver would implement against.

---

## Migration Path

A deployment that starts at Tier 1 and wants to reach Tier 3:

```
Tier 1 (now)
  → Use BootCredentials with SoftwareHsm
  → Manifest signed with software key
  → AuditLog in process memory only

Tier 2 (now, same codebase)
  → Full Ed25519 verification already wired
  → Audit log with SHA-256 hash chain
  → Revocation via epoch rotation

Tier 2 → Tier 3 (hardware integration)
  → Replace SoftwareHsm with a PKCS#11-backed HsmProvider implementation
  → Replace SoftwareTpm with a tpm2-tss-backed TpmProvider implementation
  → Wire WasmShim to a real WASM runtime
  → Replace MockTransport with a TLS/QUIC transport implementation
  → No changes to kernel core — only the provider implementations change
```

---

## Verification Checklist

Before claiming any tier is "complete" for a deployment:

### Tier 1 Checklist
- [ ] `cargo test --all-features` passes with 0 failures
- [ ] `cargo test --test adversarial` — 63/63 attacks blocked
- [ ] `cargo test --test security` — 18/18 invariant tests pass
- [ ] `cargo clippy --all-features -- -D warnings` — 0 warnings
- [ ] TLC model check completes with no violations

### Tier 2 Checklist
- [ ] All Tier 1 items above
- [ ] `cargo audit` — 0 vulnerabilities
- [ ] `cargo deny check` — passes license, ban, and advisory checks
- [ ] Manifest signature path reviewed: `verify_strict` is the only verify call
- [ ] `AuditLog::verify_chain()` returns `true` after a full pipeline run

### Tier 3 Checklist (per integration)
- [ ] All Tier 1 and Tier 2 items above
- [ ] Real hardware driver implements the trait (`HsmProvider`, `TpmProvider`, etc.)
- [ ] Integration test suite run against real hardware, not only mocks
- [ ] Independent security review of the hardware integration layer
