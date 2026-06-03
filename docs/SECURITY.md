# Security — Lux Kernel

**Audit Rating:** A+  
**Last Audit:** 2026-Q2  
**Maintained by:** Lux Security Team  
**Disclosure:** security@lux-kernel.dev  

---

## Responsible Disclosure

If you discover a security vulnerability in Lux, please do **not** file a
public GitHub issue.  Send a PGP-encrypted report to
`security@lux-kernel.dev`.  We commit to:

- Acknowledgement within 48 hours.
- A preliminary assessment within 7 days.
- A patch and public advisory within 90 days, or an agreed extension.

We follow a coordinated disclosure model.  Researchers who report valid
vulnerabilities are acknowledged in the advisory unless they prefer anonymity.

---

## 1. Threat Model

### 1.1 Assets

| Asset | Description | Criticality |
|-------|-------------|-------------|
| Capability tokens | Unforgeable authority proofs | Critical |
| Boot manifest | Root-of-trust policy declaration | Critical |
| Resource ledger | Per-node allocation state | High |
| Topology graph | Declared execution boundaries | High |
| Generation counter | Token validity timebase | High |

### 1.2 Adversary Model

Lux is designed to remain correct under the following adversary assumptions:

**In scope:**

- A **compromised caller** that presents forged, replayed, or stolen capability
  tokens.
- A **compromised subsystem** that attempts to bypass the policy gate by
  calling internal APIs directly.
- A **malicious manifest** crafted to declare topology edges or quota ceilings
  that violate intended policy.
- A **resource exhaustion attack** that attempts to over-allocate until the
  ledger is empty, denying service to legitimate callers.
- A **privilege escalation attack** that attempts to use delegation to obtain
  capabilities not originally granted.

**Out of scope (hosting environment responsibility):**

- Physical access to the hardware running Lux.
- Compromise of the process or hypervisor hosting the kernel.
- Side-channel attacks (Spectre, Meltdown) against the host CPU.
- Compromise of the key material used to sign the boot manifest (mitigated in
  Tier 3 by HSM integration).

### 1.3 Trust Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│  Untrusted Zone                                              │
│  • Callers presenting capability tokens                      │
│  • External manifest providers                               │
└──────────────────────────┬───────────────────────────────────┘
                           │  API surface (Result<T, Error>)
┌──────────────────────────▼───────────────────────────────────┐
│  Lux Kernel (this codebase)                                  │
│  • auth::Policy::check  — token validation                   │
│  • boot::Manifest — manifest parsing & verification          │
│  • topology::TopologyGraph — edge enforcement                │
│  • metabolism::Ledger — quota enforcement                    │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Vulnerability-to-Mitigation Mapping

The following table records every class of vulnerability considered during
the V1.0 audit and the structural mitigation applied.  "Structural" means the
mitigation is enforced by types, ownership, or arithmetic — not by policy text
or developer discipline.

| ID | Vulnerability Class | Attack Vector | Mitigation | Implementation Location |
|----|---------------------|--------------|------------|------------------------|
| V-01 | Capability forgery | Caller constructs a `Capability` with arbitrary rights | `Capability` fields are `pub(crate)` — callers cannot construct without the boot path | `src/auth/capability.rs` |
| V-02 | Privilege amplification via delegation | Caller delegates a superset of held rights | `Capability::delegate` requires `self.rights.contains(subset)` — returns `None` on violation | `src/auth/capability.rs:delegate` |
| V-03 | Token replay after revocation | Caller reuses a token after generation rotation | `Capability::authorises` requires `self.generation >= current_gen` | `src/auth/capability.rs:authorises` |
| V-04 | Ambient authority bypass | Caller invokes operation without presenting a token | Policy check is mandatory at every subsystem entry; there is no unauthenticated path | `src/auth/policy.rs:check` |
| V-05 | Topology escape / lateral movement | Caller traverses an undeclared edge | `TopologyGraph::traverse` denies any edge absent from the manifest | `src/topology/graph.rs:traverse` |
| V-06 | Resource over-commit | Caller allocates beyond declared quota | `Ledger::deduct` uses `checked_sub` — returns `None` (→ `QuotaExceeded`) on underflow | `src/metabolism/ledger.rs:deduct` |
| V-07 | Ledger corruption on failed deduction | Partial deduction leaves ledger in inconsistent state | `Ledger::deduct` only modifies balance after the `checked_sub` succeeds | `src/metabolism/ledger.rs:deduct` |
| V-08 | Integer overflow in quota arithmetic | Arithmetic wraps silently and permits excess allocation | All arithmetic uses checked operations; `overflow-checks = true` in all profiles | `Cargo.toml` + `src/types.rs` |
| V-09 | Work queue unbounded growth / DoS | Caller enqueues until memory is exhausted | `WorkQueue::with_capacity` is a hard ceiling; `enqueue` returns `SchedulerInvariant` at capacity | `src/scheduler/queue.rs` |
| V-10 | Unsafe code injection | Contributor introduces `unsafe` block | `#![deny(unsafe_code)]` in `lib.rs`; `scripts/audit.sh` grep-checks the tree | `src/lib.rs` |
| V-11 | Dependency supply-chain compromise | Malicious crate introduced via transitive dependency | `cargo deny` enforces allowed registry, license allowlist, and advisory database | `deny.toml` + `scripts/audit.sh` |
| V-12 | Manifest partial-init on parse failure | Failed manifest leaves topology or ledger partially seeded | `BootState::initialise` is atomic — no state is stored until all validation passes | `src/boot/mod.rs:initialise` |
| V-13 | Key material leakage via memory inspection | Capability token nonce or generation exposed in memory dumps | `Capability` derives `Zeroize` + `ZeroizeOnDrop` — secret fields are zeroed on drop | `src/auth/capability.rs` |

### Open Findings (Tier 2 resolution)

| ID | Finding | Severity | Resolution Target |
|----|---------|----------|------------------|
| F-01 | Manifest signature verification is a stub | High | Tier 2 — Ed25519 verifier |
| F-02 | No capability revocation ledger | Medium | Tier 2 — revocation log |
| F-03 | Audit event log not yet implemented | Medium | Tier 2 — append-only log |

---

## 3. Cryptographic Posture

### Current State (V1.0)

Cryptographic verification of the boot manifest signature is scaffolded but
not yet wired.  The parser stub in `src/boot/manifest.rs` returns
`ManifestInvalid` for all inputs until the wire-format decoder and signature
verifier are implemented (Tier 2).

**This means Lux V1.0 must only be deployed in environments where the manifest
source is trusted at the process boundary (e.g., embedded in a signed binary
or delivered over an authenticated channel).**

### Planned Cryptographic Architecture (Tier 2)

- **Algorithm:** Ed25519 (FIPS 186-5) for manifest signatures.
- **Token nonce:** 64-bit CSPRNG-generated per `Capability` to prevent replay
  even across equal generation values.
- **Zeroisation:** `zeroize::Zeroize` is already derived on `Capability` and
  will be extended to any intermediate key material in the signature path.

### Planned Hardware Root of Trust (Tier 3)

- **TPM 2.0** attestation of the boot manifest hash chain.
- **HSM-backed** capability seed generation (PKCS#11 interface).

---

## 4. Future Hardening Roadmap

### Tier 2 (next release)

| Item | Rationale |
|------|-----------|
| Ed25519 manifest signature verification | Closes F-01; establishes cryptographic root of trust for policy |
| Capability revocation ledger | Closes F-02; enables immediate token invalidation without generation rotation |
| Append-only audit log | Closes F-03; provides forensic trail for all denied operations |
| Property-based tests via `proptest` | Exhaustive fuzz of invariant boundaries (quota arithmetic, delegation algebra) |
| `cargo-fuzz` targets for manifest parser | Coverage of malformed wire-format inputs |

### Tier 3 (roadmap)

| Item | Rationale |
|------|-----------|
| TPM 2.0 boot attestation | Hardware-rooted proof that the correct manifest was loaded |
| HSM-backed capability minting | Key material never in process memory |
| Formal cost model | Mechanical proof that resource accounting is sound |
| WASM memory isolation integration | Execution isolation to complement policy enforcement |
| Distributed topology consensus | Multi-party agreement on topology for federation scenarios |

---

## 5. Security Testing Matrix

| Test Suite | Location | Coverage Requirement |
|------------|----------|---------------------|
| Invariant enforcement | `tests/security/invariant_enforcement.rs` | 100% — P0 on any failure |
| Privilege escalation paths | `tests/security/privilege_escalation.rs` | 100% — P0 on any failure |
| Integration: auth lifecycle | `tests/integration/auth_lifecycle.rs` | 100% |
| Integration: boot sequence | `tests/integration/boot_sequence.rs` | 100% |
| Integration: topology convergence | `tests/integration/topology_convergence.rs` | 100% |

The 100% requirement on security-path tests is enforced mechanically by
`scripts/coverage.sh`.  The CI gate fails if this threshold is not met.
