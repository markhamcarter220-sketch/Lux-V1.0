# Lux Kernel — Third-Party Security Audit Roadmap

**Status:** Vendor selection in progress  
**Target audit window:** Q3 2026  
**Last updated:** 2026-Q2

---

## Why This Document Exists

Lux makes strong security claims. Those claims are backed by:

1. Formal verification (TLA+, 322,560 states, 0 violations)
2. Adversarial tests (63 named attack vectors, 0 successful escalations)
3. Static analysis (`cargo clippy --all-features -- -D warnings`, 0 warnings)
4. Supply-chain audit (`cargo audit`, `cargo deny check`, 0 vulnerabilities)

What none of those provide is an independent human expert reviewing the design
and implementation for logic errors, protocol weaknesses, and implementation
subtleties that automated tools miss.

This document is a public commitment to:
- **When** the audit will happen
- **What** will be in scope
- **How** findings will be disclosed
- **Who** the intended auditors are

---

## Timeline

| Milestone | Target | Status |
|-----------|--------|--------|
| Internal security review complete | Q2 2026 | **Done** |
| Formal verification complete | Q2 2026 | **Done** |
| Codebase stabilised (no major API changes) | Q2 2026 | **Done** |
| Audit vendor shortlist (3 candidates) | Q3 2026 | In progress |
| Vendor selected and SOW signed | Q3 2026 | Planned |
| Audit execution | Q3 2026 | Planned |
| Draft report received | Q3/Q4 2026 | Planned |
| Remediation window | Q4 2026 | Planned |
| Final report published | Q4 2026 | Planned |

---

## Audit Scope

### In Scope

| Area | Rationale |
|------|-----------|
| `src/auth/` — capability lifecycle, policy gate, revocation | Core of the capability model |
| `src/boot/` — manifest decoder, Ed25519 verification | Root-of-trust bootstrap path |
| `src/audit/` — append-only audit log, SHA-256 hash chain | Tamper-evidence claims |
| `src/topology/` — graph enforcement | Topology-bounded invariant |
| `src/metabolism/` — resource ledger | Arithmetic safety claims |
| `src/error.rs` — denial taxonomy | Fail-closed error handling |
| `src/hsm/` — HSM provider interface and software mock | Cryptographic boundary |
| `deny.toml`, `Cargo.toml` — dependency policy | Supply-chain posture |
| Four security invariants (I1–I4) as stated in `README.md` | Core security contract |
| TLA+ specification against implementation correspondence | Formal model accuracy |

### Out of Scope (this engagement)

| Area | Reason |
|------|--------|
| `src/python/` — PyO3 bindings | Python C extension boundary; separate engagement |
| `src/wasm/`, `src/consensus/`, `src/tpm/` — Tier 3 stubs | Not production-integrated |
| `hiring-audit/`, `lending-audit/`, `recidivism-demo/` | Reference implementations only |
| `tla/` — TLA+ specification itself | Separate formal methods review |
| Operating system or hypervisor beneath Lux | Hosting environment responsibility |
| Network transport between distributed nodes | Not yet production-integrated |

---

## Auditor Selection Criteria

Candidates must satisfy all of the following:

1. **Rust expertise** — at least one team member with demonstrated experience
   auditing safe-Rust codebases. `unsafe`-focused CVEs are not the risk here;
   logic and protocol errors are.

2. **Formal methods familiarity** — ability to review the TLA+ specification
   and assess whether the formal model accurately captures the implementation.

3. **Cryptographic competence** — Ed25519 verification subtleties (cofactor
   contributions, `verify` vs. `verify_strict`), hash-chain integrity, and
   capability token design.

4. **No conflicts of interest** — no financial or professional relationship
   with the Lux project or its contributors.

5. **Public track record** — at least three published security audit reports
   in the systems/infrastructure space.

Preferred: experience auditing `no_std` embedded Rust, capability-based
security systems, or governance/policy enforcement infrastructure.

---

## What We Are Asking the Auditor to Look For

Beyond standard vulnerability classes, we have specific questions:

1. **Capability model completeness:** Is there any path through which a caller
   can acquire authority they were not explicitly granted? Any ambient authority
   that bypasses `Policy::check`?

2. **Manifest bootstrap integrity:** Is `verify_strict` the right call? Are
   there any TOCTOU issues in the manifest decode → boot path?

3. **Audit log tamper resistance:** Does the SHA-256 hash chain construction
   in `src/audit/log.rs` meet its tamper-evidence claim? Can a partial-update
   attack leave `verify_chain()` returning `true` after mutation?

4. **Revocation soundness:** Can a revoked token ever pass `Policy::check`
   after revocation, under any ordering of concurrent calls?

5. **Arithmetic safety:** Are there any integer overflow, underflow, or
   wrap-around paths in resource accounting that `checked_sub` does not cover?

6. **TLA+ correspondence:** Does the TLA+ model in `tla/LuxKernel.tla`
   accurately capture the implementation's state transitions? Are there
   implementation behaviours not represented in the model?

---

## Remediation Process

When the audit report is received:

| Finding Severity | SLA |
|-----------------|-----|
| Critical (CVSS ≥ 9.0) | 7 days to patch; immediate advisory |
| High (CVSS 7.0–8.9) | 30 days to patch |
| Medium (CVSS 4.0–6.9) | 90 days to patch |
| Low / Informational | Next scheduled release |

All findings, regardless of severity, will be tracked in a public GitHub issue
tagged `audit-finding`. The fix will be accompanied by a regression test.

Disputed findings will be documented with the project's response and the
auditor's reply. No finding will be silently closed.

---

## Report Disclosure

The final audit report will be published in full at:

```
docs/audits/AUDIT_REPORT_Q4_2026.pdf
```

The report will include:
- Auditor name and firm
- Scope and methodology
- All findings with severity ratings
- Project responses to each finding
- Remediation status at time of publication

**We will not redact findings.** A governance kernel that hides its audit
findings undermines its own purpose. If the auditor finds a critical
vulnerability, the vulnerability will be disclosed alongside the patch,
following coordinated disclosure with a reasonable embargo for downstream
users to update.

---

## Transparency Commitments

This project commits to:

1. **Not claiming "audited" status** until the final report is published and
   all Critical and High findings are resolved.

2. **Not removing the `[ ] Third-party security audit` open item** from
   `README.md` until the conditions in (1) are met.

3. **Publishing the full report**, not a summary or executive overview.

4. **Disclosing all findings**, not only those the project agrees with.

5. **Updating this document** if the timeline slips, with an explanation.

---

## FAQ

**Q: Why Q3 2026 and not sooner?**

The codebase needs to be stable before an audit is worthwhile. A moving target
is an inefficient use of audit time and budget. Q2 2026 was used to complete
Tier 2 (cryptography, audit log, revocation) and close all known internal
findings. Q3 is the first point at which the scope is stable.

**Q: Why not use an automated audit tool instead?**

We already do: `cargo audit`, `cargo deny`, `cargo clippy --all-features -- -D warnings`,
and `cargo fuzz`. These catch supply-chain vulnerabilities, dependency issues,
logic errors that Rust's type system expresses, and input-handling panics.
They do not catch design-level issues, protocol weaknesses, or implementation
logic errors that are syntactically correct but semantically wrong.

**Q: What if the audit finds something serious?**

Then we fix it, disclose it, and thank the auditor. A security kernel that
cannot withstand scrutiny should not exist. The point of the audit is to find
problems, not to confirm that none exist.

**Q: Will the Tier 3 items (HSM, TPM, WASM, consensus) be audited?**

Not in this engagement. They are not production-integrated. A separate audit
engagement will cover each Tier 3 integration as it matures.

**Q: How can I follow the audit progress?**

Watch the GitHub repository. The vendor selection, SOW signing, and report
publication will each be announced as a tagged release or GitHub Discussions
post. This document will be updated at each milestone.
