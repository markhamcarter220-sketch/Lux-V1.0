# Lux Kernel

**A fail-closed, capability-authenticated governance microkernel.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Rust 1.78+](https://img.shields.io/badge/rust-1.78%2B-orange)](https://www.rust-lang.org)
[![no_std](https://img.shields.io/badge/no__std-yes-blue)](#)

---

## What Is Lux?

Lux is a governance microkernel written in safe Rust, designed to be the
authoritative enforcement layer beneath distributed infrastructure systems.

Where conventional runtimes trust their callers and validate at the edges, Lux
inverts that assumption: **every operation requires a proof of authority**,
every resource allocation is charged against an immutable quota, and every
routing decision is bounded by a statically-declared topology.  There is no
"trusted internal path" — the kernel's own subsystems are subject to the same
capability checks as external callers.

The design is deliberately minimal.  Lux does not schedule processes, manage
memory pages, or drive hardware.  It enforces **policy** — the rules that
govern what may happen, when, between whom, and at what resource cost — and
delegates everything else to the systems built on top of it.

### Why Does Lux Exist?

Modern infrastructure governance is implemented as a patchwork of advisory
controls: API gateway rate limits that can be bypassed at the network layer,
RBAC systems that trust the identity claims they receive, and resource quotas
enforced by processes that share address space with the workloads they police.

Lux exists because **advisory controls fail under adversarial conditions**.
A kernel that cannot be argued out of a decision — that denies ambiguous
requests by construction rather than by policy document — is a fundamentally
different security primitive.

---

## Security Invariants

These four invariants are non-negotiable.  Every line of code in this
repository is a proof that they hold.  A change that violates any of them
is a P0 regression, regardless of its other merits.

| # | Invariant | Enforcement Point |
|---|-----------|-------------------|
| 1 | **Fail-Closed** — ambiguity and error states produce denial, never access | `auth::policy::Policy::check` |
| 2 | **Capability-Gated** — no operation proceeds without a valid, scoped, time-bounded token | `auth::capability::Capability::authorises` |
| 3 | **Accountable Resources** — every allocation is charged; over-quota requests are hard-rejected | `metabolism::ledger::Ledger::deduct` |
| 4 | **Topology-Bounded** — execution is confined to the boot-manifest graph; undeclared edges are denied | `topology::graph::OperationalGraph::traverse` |

**Audit-completeness (I1 extension):** Any otherwise-permitted operation that
cannot be written to the audit log is denied rather than silently permitted.
Three enforcement gates (`Policy::check`, `OperationalGraph::traverse`,
`QuotaEnforcer::deduct`) return `Error::AuditFull` when the log is saturated
and the operation would have succeeded.  Pre-existing denials are returned
unchanged — audit saturation never masks a legitimate rejection.
**Availability tradeoff:** a saturated audit log denies new operations until
`rotate_generation()` or a log drain is called.  This is a deliberate
fail-closed design choice.

All four invariants are verified by the adversarial test suite (66 attacks,
zero successful privilege escalations — see `tests/adversarial/`) and
formally verified by TLC model checking across 322,560 distinct states
(see [Formal Verification](#formal-verification) below).

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a full derivation of
each invariant from first principles, and [`docs/SECURITY.md`](docs/SECURITY.md)
for the threat model. Note: Third-party security audit is not yet complete (see [Project Maturity](#project-maturity)).

---

## Formal Verification

**Note on terminology:** This project has two independent formal verification
layers, at different stages of completion. **TLA+/TLC** (below) exhaustively
model-checks the four invariants over a bounded state space and is re-run to
produce the numbers quoted here — this layer is genuinely machine-checked.
**Lean 4** (`lean/`) contains *written* proof terms for the four core
modules (`LuxSpec.lean`, `LuxCostModel.lean`, `LuxRefinement.lean`,
`LuxCapabilityBridge.lean`); mechanical verification via `lake build` has
NOT been completed in this session and has not been independently witnessed
since. Source inspection (grep, not a build) finds no `sorry` token in those
four files. A fifth file, `lean/Refinement.lean`, layers system-level I1–I4
obligations on top of that proof tree; the same inspection finds 2 of its 9
theorems contain literal `sorry` placeholders (the I3 obligations) — see
[Project Maturity](#project-maturity) and `docs/REFINEMENT_GAPS.md`. Neither
layer subsumes the other: TLA+/TLC checks system behaviour across a bounded
model; Lean's proof terms target properties of the ledger/capability model
in unbounded arithmetic and do not yet model the full topology/typestate
layer (I4). Status becomes "verified" only when `lake build` passes with
zero `sorry` and zero errors, witnessed directly.

The four core security theorems are formally verified using
**TLA+ (Temporal Logic of Actions)** with the **TLC model checker**.
TLC exhaustively enumerates every reachable state and checks that all
invariants hold.  A counterexample would produce a concrete violation trace.

```
TLC2 Version 2026.05.26.235334
Model: MC.tla with MC.cfg
Bound: 2 principals, 2 nodes, 2 rights, MaxNonce=2, MaxEpoch=1, MaxCaps=3

States generated : 2,638,225
Distinct states  : 322,560
States on queue  : 0  (exhaustive -- no states left)
Search depth     : 11
Time             : 8 seconds

Invariants checked:
  TypeOK                  PASS
  NonEscalation           PASS
  RevocationSoundness     PASS
  ResourceAtomicity       PASS
  TopologyBoundedness     PASS
  AllSecurityInvariantsHold PASS

Result: No error has been found.
```

**Theorems proved** (inductive proofs documented in
[`docs/FORMAL_VERIFICATION.md`](docs/FORMAL_VERIFICATION.md)):

| Theorem | Formal statement | Maps to invariant |
|---|---|---|
| NonEscalation | `∀ cap ∈ issuedCaps: cap.rights ⊆ cap.rootRights` | I2 — Capability-Gated |
| RevocationSoundness | `∀ cap: cap.nonce ∈ revokedNonces → ¬IsValidCap(cap)` | I1 — Fail-Closed |
| ResourceAtomicity | `∀ p ∈ Principals: balances[p] ≥ 0` | I3 — Accountable Resources |
| TopologyBoundedness | `executedTraversals ⊆ BootEdges` | I4 — Topology-Bounded |

The model bounds are sufficient: each theorem has an inductive proof that
holds for arbitrary parameter values.  TLC confirms the base case and each
inductive step within the bounded model.

**Run the model check:**

```sh
cd tla
java -XX:+UseParallelGC -jar tla2tools.jar MC.tla -config MC.cfg -workers 4
# Expected: Model checking completed. No error has been found.
```

---

## Project Maturity

See [`TIER_BOUNDARIES.md`](TIER_BOUNDARIES.md) for detailed explanation of maturity levels.
See [`AUDIT_ROADMAP.md`](AUDIT_ROADMAP.md) for third-party audit timeline and criteria.

```
Tier 1 — PRODUCTION-READY (core security enforced, tested, verified)
[x] Core error taxonomy (HALT/FAILURE denial classification, exhaustive variants)
[x] Capability token model (object-capability, no ambient authority)
[x] Policy enforcement point (fail-closed gate)
[x] Resource ledger (checked arithmetic, no silent overflow)
[x] Topology graph (static, manifest-derived, deny-by-default)
[x] Work queue (bounded capacity, priority-ordered)
[x] Boot manifest validation framework
[x] 100% security-path test pass rate
[x] Adversarial test suite (66 attacks, 0 escalations) — tests/adversarial/
[x] TLA+ formal verification (322,560 states, 0 violations) — tla/

Tier 2 — COMPLETE (cryptography, audit, revocation integrated)
[x] Wire-format manifest decoder (CBOR) — src/boot/decode.rs
[x] Cryptographic manifest signature (Ed25519) — src/boot/credentials.rs
[x] Capability revocation ledger (O(1) via epoch) — src/auth/revocation.rs
[x] Audit event log (append-only, hash-chained) — src/audit/
[x] Formal property tests (proptest) — tests/properties/

Tier 2.5 — COMPLETE (compliance demonstrations)
[x] EU AI Act reference implementation (hiring-audit/)
[x] Fair lending reference implementation (ECOA/FHA) — lending-audit/
[x] Criminal justice governance demonstration — recidivism-demo/

Tier 3 — IN PROGRESS (3/5 complete; 2 pending hardware deployment)
[x] WASM execution substrate — Wasmtime-backed executor, 3 host functions, 12 integration tests (src/wasm/, tests/wasm_executor.rs)
[x] Distributed topology consensus — full Raft state machine, 21 unit tests + integration tests (src/consensus/, tests/raft.rs)
[~] HSM-backed capability minting — SoftwareKeyStore + YubiHSM/PKCS#11 stubs (src/hsm/);
    3 HSM/RevocationLedger state-disagreement integration tests (tests/hsm_state_disagreement.rs)
    Pending: real YubiHSM or PKCS#11 hardware deployment
[~] TPM-anchored boot attestation — BootAttestation + TssTpm stub (src/tpm/, tests/tpm.rs)
    Pending: physical TPM chip + TSS stack
[~] Formal proofs — Lean 4 four-file core suite (lean/) is WRITTEN. Mechanical
    verification via `lake build` has NOT been completed in this session and
    has not been independently witnessed since. Proof terms are drafted but
    not machine-checked here.
    LuxSpec.lean: abstract ideal-system specification (I2 + I3)
    LuxCostModel.lean: concrete model of src/metabolism/ledger.rs (7 ledger theorems)
    LuxRefinement.lean: refinement proofs — concreteDeductSpec, delegate_non_amplification
    LuxCapabilityBridge.lean: u32 bitfield ↔ Finset Right isomorphism (bitsContainsIffSubset)
    See docs/FORMAL_COST_MODEL.md and docs/FORMAL_VERIFICATION.md §6 for theorem index.
    A fifth file, lean/Refinement.lean, layers 9 system-level I1–I4 obligations
    above this proof tree. Source inspection (not a build) confirms exactly 2
    literal `sorry` placeholders, both I3 (`accountableResources_soleDeductionPath`,
    `accountableResources_ceilingBound`). Status becomes "verified" only when
    `lake build` passes with zero `sorry` and zero errors, witnessed directly.
    See docs/REFINEMENT_GAPS.md for the per-theorem breakdown and caveats.

AUDIT & VERIFICATION STATUS:
[x] Internal security review (Lux Project Contributors)
[x] TLA+ formal model verification (322,560 states exhaustively checked)
[x] Adversarial test suite (66 named attack vectors, 0 successful escalations)
[ ] Third-party security audit — PLANNED (vendor selection in progress)
    Target: Q3 2026. See AUDIT_ROADMAP.md for timeline.
```

---

## Compliance Applications

Lux has been applied to three regulated decision-making domains as reference
implementations.  Each demonstrates the same three-layer proof pattern:
architectural exclusion (policy gate), tamper-evident audit, and statistical
validation.

### EU AI Act — Employment Screening (`hiring-audit/`)

**Problem:** EU AI Act Article 9 requires high-risk AI systems (including
automated hiring tools) to be subject to human oversight and produce auditable
records of decisions.

**What Lux provides:** A fail-closed policy gate blocks all protected
attributes (`age`, `gender`, `race`) from reaching the model, enforced at the
API level before inference.  A SHA-256 hash-chained audit log records every
decision.  Chi-squared independence tests confirm race (p = 0.597) and gender
(p = 0.751) are statistically independent of hiring outcomes at α = 0.05.

**Regulatory context:** EU AI Act (2024/1689), Articles 9–12 (risk management,
data governance, technical documentation, human oversight).

### Fair Lending — Credit Decisions (`lending-audit/`)

**Problem:** ECOA (15 U.S.C. § 1691) disparate-impact claims do not require
discriminatory intent — adverse outcomes for a protected class are sufficient
for liability, even in automated systems.

**What Lux provides:** Policy gate blocks five protected attributes
(`age`, `gender`, `race`, `marital_status`, `disability`) plus any
alias-named proxies.  All five pass chi-squared independence at α = 0.05
(p-values: 0.877, 0.910, 0.591, 0.331, 0.833).  Gender and disability —
highest priority under active CFPB enforcement — pass the 4/5ths disparate
impact rule.  200 decisions logged, chain verified, zero policy violations.

**Regulatory context:** ECOA (15 U.S.C. § 1691), FHA (42 U.S.C. § 3605),
CFPB supervisory examination criteria.

### Criminal Justice Risk Assessment (`recidivism-demo/`)

**Problem:** COMPAS (Correctional Offender Management Profiling for
Alternative Sanctions) was found by ProPublica (2016, n = 7,214) to produce
a Black defendant false-positive rate of 44.9% versus 23.5% for white
defendants (chi-squared p < 0.001).  The primary cause: `prior_drug_convictions`,
a racial proxy not labelled as a protected attribute.

**What Lux provides:** The policy gate explicitly blocks
`prior_drug_convictions` by name as a known racial proxy, in addition to
`race`, `gender`, `ethnicity`, `national_origin`, and `disability`.  On
150 synthetic defendants, race (p = 0.916) and gender (p = 0.617) are
statistically independent of risk assessments.  RISK_HIGH classification
rate by race: Black 62.0%, White 60.6% — a 1.4-point gap, versus COMPAS's
own RISK_HIGH classification-rate gap of 17 points (Black 51.4%, White
34.0%; a different metric from the 44.9%/23.5% false-positive rates cited
above).

**Regulatory context:** 14th Amendment Equal Protection Clause;
*Washington v. Davis*, 426 U.S. 229 (1976); *State v. Loomis*, 881 N.W.2d
749 (Wis. 2016).

---

## Quick Start

### Prerequisites

- Rust 1.78 or later (`rustup update stable`)
- `cargo-audit` (`cargo install cargo-audit`)
- `cargo-deny` (`cargo install cargo-deny`)
- `cargo-llvm-cov` (`cargo install cargo-llvm-cov`) — for coverage

### Build

```sh
git clone https://github.com/markhamcarter220-sketch/lux-v1.0.git
cd lux-v1.0
cargo build --release
```

### Test

```sh
# All tests (318 total: 39 unit + 66 adversarial + 16 HSM + 3 HSM-disagreement
# + 107 integration + 17 property + 21 raft + 19 security + 18 TPM + 12 WASM)
cargo test --all-features

# Security invariant tests only
cargo test --test security -- --nocapture

# Adversarial suite (66 attacks)
cargo test --test adversarial -- --nocapture
```

### Formal Verification

```sh
cd tla
java -XX:+UseParallelGC -jar tla2tools.jar MC.tla -config MC.cfg -workers 4
```

### Full CI Gate (mirrors the pipeline)

`scripts/ci_full.sh` exists and orchestrates the full local CI gate in order
(format & lint, supply-chain audit, unit & integration tests, security path
tests, coverage threshold, Lean build, reproducible build & binary
attestation). There is no GitHub Actions workflow under `.github/workflows/`
yet — this script is the CI gate, run locally/manually until it is wired
into a hosted workflow:

```sh
./scripts/ci_full.sh
```

Individual phases can also be run standalone:

```sh
./scripts/lint.sh        # cargo fmt --check + cargo clippy -D warnings
./scripts/audit.sh       # cargo deny check + cargo audit
cargo test --all-features
cargo test --test security -- --nocapture
./scripts/coverage.sh    # cargo-llvm-cov threshold check
./scripts/attest.sh      # reproducible build + binary attestation
```

### As a Dependency

```toml
[dependencies]
lux_kernel = { git = "https://github.com/markhamcarter220-sketch/lux-v1.0", tag = "v1.0.0" }
```

---

## Repository Layout

```
lux-v1.0/
├── src/
│   ├── lib.rs              # Crate root — four invariants
│   ├── error.rs            # Denial taxonomy + HALT/FAILURE classification
│   ├── types.rs            # Shared primitive types
│   ├── audit/              # Append-only, hash-chained event log
│   ├── auth/               # Capability lifecycle, policy gate, revocation
│   ├── boot/               # CBOR manifest decoder, Ed25519 verification
│   ├── metabolism/         # Resource ledger and quota enforcement
│   ├── scheduler/          # Bounded priority work queue
│   └── topology/           # Directed execution graph enforcement
├── tests/
│   ├── adversarial/        # 66 attack vectors, 0 successful escalations
│   ├── integration/        # Cross-subsystem integration tests
│   ├── properties/         # Proptest invariant proofs
│   └── security/           # Invariant regression tests (100% pass required)
├── tla/
│   ├── LuxKernel.tla       # Parametric TLA+ specification (6 actions, 4 invariants)
│   ├── MC.tla              # Model-checking wrapper with concrete constants
│   └── MC.cfg              # TLC configuration
├── hiring-audit/           # EU AI Act reference implementation
│   ├── *.py                # Pipeline: data generation, model, policy gate, audit
│   ├── output/             # Generated decisions, audit log, bias report
│   └── docs/               # PROOF_STATEMENT.md, REFERENCE_IMPLEMENTATION.md, ONE_PAGER.md
├── lending-audit/          # ECOA/FHA reference implementation
│   ├── *.py                # Pipeline: 200 applicants, RandomForest, 5 protected attrs
│   ├── output/             # Generated decisions, audit log, bias report
│   └── docs/               # PROOF_STATEMENT.md, ONE_PAGER.md
├── recidivism-demo/        # Criminal justice governance demonstration
│   ├── *.py                # Pipeline: 150 defendants, LogisticRegression, proxy blocking
│   ├── output/             # Generated decisions, audit log, fairness report
│   └── docs/               # demo_proof_statement.md
├── lean/
│   ├── LuxSpec.lean            # Abstract ideal-system specification (I2 + I3)
│   ├── LuxCostModel.lean       # Concrete model of ledger.rs — 7 ledger invariants (I3)
│   ├── LuxRefinement.lean      # Refinement proofs (spec ← concrete model)
│   ├── LuxCapabilityBridge.lean# u32 bitfield ↔ Finset Right isomorphism (I2 bridge)
│   ├── Refinement.lean         # I1–I4 system-level invariant obligations (2 of 9 theorems have `sorry`)
│   ├── FunctionSpecs.lean      # Entry point for the FunctionSpecs/ tree (signature + pre/post only, no proofs)
│   ├── FunctionSpecs/          # Per-module function specs for all 247 production functions in src/
│   └── lakefile.lean           # Lake build file (6 lean_lib targets — see lean/lakefile.lean)
├── docs/
│   ├── ARCHITECTURE.md         # Conceptual model → implementation bridge
│   ├── ADVERSARIAL_TESTING.md  # 66-attack test methodology
│   ├── FORMAL_VERIFICATION.md  # TLC results and inductive proof sketches
│   ├── FORMAL_COST_MODEL.md    # Lean 4 theorems and TLA+ relationship
│   ├── SECURITY.md             # Threat model and audit findings
│   └── adr/                    # Architecture Decision Records (0001–0005)
├── benches/                # Criterion throughput benchmarks
├── scripts/
│   ├── lint.sh             # cargo fmt --check + clippy -D warnings + cargo deny
│   ├── audit.sh            # cargo audit + cargo deny (advisories/licenses/bans)
│   ├── coverage.sh         # cargo-llvm-cov + 100% security-path threshold check
│   ├── attest.sh           # auditable build + SPDX SBOM + binary/lockfile hashes
│   └── ci_full.sh          # orchestrates all of the above, in order
├── Cargo.toml
├── deny.toml               # cargo-deny policy
├── rustfmt.toml
└── clippy.toml
```

Note: there is no GitHub Actions workflow under `.github/workflows/` yet —
`scripts/ci_full.sh` is the CI gate today; see
[Full CI Gate](#full-ci-gate-mirrors-the-pipeline) above.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full development contract,
including the Zero-Panic policy, Fail-Closed coding standards, and required
test coverage obligations.

---

## Project Origin and Verification Status

Lux V1.0 was scaffolded over approximately four days using AI-assisted
development (Claude Code).  This is disclosed explicitly so that reviewers
calibrate their trust accordingly.

**What this means for consumers:**

- The architecture, invariants (I1–I4), and security contracts were designed
  by the project contributors and are documented in `docs/ARCHITECTURE.md`.
- The implementation was produced with AI assistance and has undergone
  internal review, adversarial testing (66 attack vectors), and TLA+ model
  checking (322,560 states).
- **Third-party security audit is not yet complete.**  Do not rely on this
  codebase in production until the external audit is finished
  (target: Q3 2026 — see [`AUDIT_ROADMAP.md`](AUDIT_ROADMAP.md)).

**Manual verification checklist (in progress):**

- [ ] Independent re-implementation of `Capability::authorises` to confirm
      generation and rights semantics
- [ ] End-to-end happy-path + denial-path trace through
      `BootState::run_topology_consensus` by a human reviewer
- [ ] All call sites of `Policy::check` audited for I1–I4 compliance across
      all feature flag combinations
- [ ] Lean 4 formal proof mechanical verification (`lake build` in `lean/`) —
      NOT completed. The proof suite is written but not machine-checked; no
      `lake build` has been witnessed in this session. Source inspection
      (grep) confirms 2 literal `sorry` placeholders in `lean/Refinement.lean`
      (both I3); the four core files contain none. This is a textual fact
      about the source, not a compilation result.

If you are performing the external audit, start with
[`docs/SECURITY.md`](docs/SECURITY.md) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## License

Apache License, Version 2.0.  See [`LICENSE`](LICENSE) for the full text.
