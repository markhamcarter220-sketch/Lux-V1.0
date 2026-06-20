# Security — Lux Kernel

**Audit Status:** No third-party audit complete. OSTIF engagement initiated 2026-Q2.  
**Internal review only:** TLA+ model checking (bounded) + 63-vector adversarial suite.  
**Maintained by:** Lux Project Contributors  
**Disclosure:** see Responsible Disclosure below

---

## Responsible Disclosure

**Status: Planned disclosure process — not yet operational.** There is no
confirmed monitored inbox or published PGP key for the address below as of
this writing. Treat the timeline that follows as the *intended* process, not
an SLA the project can currently honor.

If you discover a security vulnerability in Lux, please do **not** file a
public GitHub issue. Once this process is live, reports will go to a
PGP-encrypted channel at `security@lux-kernel.dev`. The target timeline,
once operational, is:

- Acknowledgement within 48 hours.
- A preliminary assessment within 7 days.
- A patch and public advisory within 90 days, or an agreed extension.

Until operational status is confirmed (a published PGP key and a
demonstrated response), any report to this address should be treated as
best-effort. We intend to follow a coordinated disclosure model once live;
researchers who report valid vulnerabilities will be acknowledged in the
advisory unless they prefer anonymity.

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
| V-03 | Token replay after revocation | Caller reuses a token after generation rotation | `Capability::authorises` requires `self.generation == current_gen` — rotation invalidates all prior-generation tokens; there is no forward validity | `src/auth/capability.rs:authorises` |
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

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| F-01 | Manifest signature verification | High | **Resolved** — genuine Ed25519 `verify_strict` (not a stub) at `src/hsm/mock.rs:94`, called via `HsmProvider::verify` from `src/boot/decode.rs:88`; see naming caveat in §3 |
| F-02 | No capability revocation ledger | Medium | **Resolved** — `src/auth/revocation.rs` |
| F-03 | Audit event log not yet implemented | Medium | **Resolved** — `src/audit/log.rs` |

---

## 3. Cryptographic Posture

### Current State (V1.0)

Ed25519 manifest signature verification is **fully wired** as of Tier 2.
The decoder at `src/boot/decode.rs:88` calls `HsmProvider::verify` **before**
any CBOR parsing — a manifest with an invalid signature is rejected without
inspecting its contents (fail-closed). The default production implementation
of `HsmProvider::verify` is `SoftwareHsm::verify` (`src/hsm/mock.rs:91-98`),
which performs a genuine `VerifyingKey::verify_strict` (cofactor-safe) check
via `ed25519-dalek` — real cryptographic verification, not a stub.

**Naming caveat:** the module is named `mock.rs` because it is a *software*
(non-hardware) implementation, not because verification is faked. The name
reads as a stub to a reader skimming file paths; renaming it (e.g. to
`software.rs`) is recommended but is a code change outside the scope of this
documentation pass.

### Cryptographic Architecture (Tier 2 — Implemented)

- **Algorithm:** Ed25519 (FIPS 186-5) — `verify_strict` (cofactor-safe variant) at `src/hsm/mock.rs:94`.
- **Wire format:** 64-byte signature prepended to CBOR payload; verified before parse.
- **Token nonce:** 64-bit per `Capability`; replay is detected and denied by `Policy::check`.
- **Zeroisation:** `zeroize::Zeroize` is derived on `Capability`; secret fields are zeroed on drop.

### Planned Hardware Root of Trust (Tier 3)

- **TPM 2.0** attestation of the boot manifest hash chain.
- **HSM-backed** capability seed generation (PKCS#11 interface).

---

## 4. Future Hardening Roadmap

### Tier 2 (next release)

Ed25519 manifest signature verification, the capability revocation ledger,
and the audit log (F-01, F-02, F-03) have already shipped in V1.0 and are no
longer pending — see §2 Open Findings. They are removed from this table.

| Item | Rationale |
|------|-----------|
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
| Signature verification (5 cases) | `tests/security.rs::signature_verification` | Passes — all 5 cases verified |

The 100% requirement on security-path tests is enforced mechanically by
`scripts/coverage.sh`.  The CI gate fails if this threshold is not met.

---

## 6. Integrator Assumptions

### What Lux Guarantees

| Guarantee | Enforcement |
|-----------|-------------|
| Capability checks are fail-closed | `auth::Policy::check` returns `Err` on any non-success path |
| Audit log is append-only and tamper-evident | SHA-256 hash chain; `AuditLog::verify_chain()` detects any mutation |
| Topology is bounded to the boot manifest | `TopologyGraph::traverse` denies edges absent from the manifest |
| Resource deductions are atomic | `Ledger::deduct` uses `checked_sub`; balance only changes on success |
| No ambient authority | Every subsystem entry requires a presented capability token |

### What Lux Does Not Guarantee

| Non-guarantee | Integrator Responsibility |
|---------------|--------------------------|
| Physical security of the host machine | Isolate the host; Lux cannot protect against physical access |
| Integrity of the boot manifest delivery channel | Use HSM/TPM attestation (Tier 3) or deliver over an authenticated channel |
| Network transport security between distributed nodes | Use TLS or equivalent; Lux consensus protocol authenticates proposals but does not encrypt |
| Correctness of the workload running above the kernel | Lux enforces *that* capabilities are checked, not *what* the workload does with them |
| Monotonic or trusted wall-clock time | The caller supplies `timestamp` to `AuditLog::append`; Lux stores it verbatim |

### Hosting Environment Responsibilities

1. **Manifest delivery:** The boot manifest must arrive over an authenticated channel or be embedded in a signed binary. An adversary who can substitute the manifest controls the entire policy.
2. **Process isolation:** The process running Lux must be isolated from other processes. Lux provides no defence against an attacker with arbitrary code execution in the same process.
3. **Clock source:** Audit timestamps supplied by the caller should be monotonic. Lux does not validate or interpret timestamps — they are stored for auditability.
4. **Key material lifecycle:** Private keys used to sign boot manifests must be rotated and revoked per the organisation's key management policy. Lux does not manage key lifecycle.
