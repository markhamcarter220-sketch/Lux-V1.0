# Reference Implementation — Lux-Governed AI Hiring System

**Version:** 1.0  
**Date:** 2026-06-04  
**Repository:** `hiring-audit/` in Lux-V1.0

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                        │
│                                                             │
│   generate_data.py          model.py           phase2.py   │
│   ─────────────────         ─────────────      ──────────  │
│   100 candidate              Decision tree      Orchestrate │
│   profiles with              trains on 6        all layers  │
│   protected attrs            approved features  in sequence │
│   separated out              only; outputs                  │
│                              hire_probability               │
└────────────────────────┬────────────────────────────────────┘
                         │  features_used dict
                         │  (6 non-protected keys)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    GOVERNANCE LAYER                          │
│                                                             │
│   policy_gate.py                      audit_log.py         │
│   ─────────────────────               ──────────────────   │
│   PolicyGate.check(features_used)     AuditLog.append()    │
│                                                            │
│   Rule 1: exact set membership        SHA-256 hash chain   │
│   Rule 2: substring alias scan        prev_hash → entry    │
│   Rule 3: approved-feature allowlist  verify_chain() O(n)  │
│                                                            │
│   Returns ALLOW or DENY + reason      Returns True/False   │
│   before decision is recorded         on chain integrity   │
└────────────────────────┬────────────────────────────────────┘
                         │  audit entries
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               KERNEL GOVERNANCE LAYER (Lux)                  │
│                                                             │
│   Invariant 1: Fail-Closed   — errors produce DENY, never  │
│                                 ACCESS                      │
│   Invariant 2: Capability-   — no operation proceeds       │
│                Gated           without a verified token     │
│   Invariant 3: Accountable   — every resource allocation    │
│                Resources       is charged and bounded       │
│   Invariant 4: Topology-     — execution confined to       │
│                Bounded         declared graph               │
│                                                             │
│   (Rust no_std kernel; formal adversarial test suite:       │
│    63 attacks, 0 successful privilege escalations)          │
└─────────────────────────────────────────────────────────────┘
```

The Python governance layer (policy gate + audit log) directly mirrors the
Lux Kernel's security invariants, applied to the hiring domain:

| Lux Invariant | Hiring Analogue |
|---|---|
| Fail-Closed | Any policy gate error produces DENY, never ALLOW |
| Capability-Gated | No decision is recorded without a verified ALLOW token from the gate |
| Accountable Resources | Every decision has an audit entry; 100 % coverage enforced |
| Topology-Bounded | Only the declared feature set may appear in decision vectors |

---

## Layer 1 — Application

### Candidate Data (`generate_data.py`)

Generates 100 synthetic profiles.  Each profile has two disjoint sections:

**Model features** (passed to the decision tree):
- `years_experience` — integer, Gaussian(μ=7, σ=5), clamped [0, 30]
- `education_level` — categorical 0–4, weighted toward bachelor's (40 %)
- `technical_skills` — float, Gaussian(μ=65, σ=18), clamped [0, 100]
- `communication_score` — float, Gaussian(μ=70, σ=15), clamped [0, 100]
- `problem_solving` — float, Gaussian(μ=68, σ=17), clamped [0, 100]
- `fit_score` — float, Gaussian(μ=72, σ=14), clamped [0, 100]

**Protected attributes** (audit-only, never passed to the model):
- `age` — integer, Gaussian(μ=35, σ=10), clamped [22, 65]
- `gender` — uniform choice from {female, male, non-binary}
- `race` — uniform choice from {white, black, hispanic, asian, other}

The two sections are sampled independently.  There is no correlation between
a candidate's protected attributes and their model feature scores — by
construction.  The statistical tests (Phase 2) empirically confirm this.

### Decision Model (`model.py`)

A shallow decision tree is chosen deliberately for three properties:

1. **Interpretable** — the full tree structure fits on one page (`model_report.txt`).
2. **Auditable** — every split node names the feature and threshold.
3. **No implicit feature interactions** — unlike neural networks, there is no
   mechanism for race or gender to leak through learned latent representations.

Model configuration:

```python
DecisionTreeClassifier(
    max_depth       = 4,     # shallow → interpretable
    min_samples_leaf = 3,    # prevents singleton-leaf overfitting
    random_state    = 42,    # reproducible
)
```

Ground-truth labels are derived from a transparent scoring rule over
non-protected features only:

```
score = 0.30 × norm(years_experience, 0, 30)
      + 0.20 × norm(education_level,  0,  4)
      + 0.20 × norm(technical_skills, 0, 100)
      + 0.15 × norm(communication_score, 0, 100)
      + 0.15 × norm(problem_solving, 0, 100)
HIRE if score ≥ 0.50
```

Test-set accuracy: **95 %** (20-candidate held-out split, stratified).

---

## Layer 2 — Governance

### Policy Gate (`policy_gate.py`)

The gate is the enforcement point.  It has one method:

```python
gate.check(features_used: dict) -> PolicyResult(allowed: bool, reason: str)
```

It applies three rules in order, failing closed on the first violation:

**Rule 1 — Exact match:**  
```python
protected_violations = [k for k in features_used if k in {"age", "gender", "race"}]
```
Blocks the known protected attribute names directly.

**Rule 2 — Alias scan:**  
```python
alias_violations = [
    k for k in features_used
    if any(sub in k.lower() for sub in ("age", "gender", "race", "ethnicity", "sex"))
]
```
Blocks aliased columns.  A future engineer who adds a feature named
`candidate_age_group` or `gender_flag` is caught here without any schema
change.

**Rule 3 — Allowlist:**  
```python
unknown = [k for k in features_used if k not in APPROVED_FEATURES]
```
Blocks any feature not explicitly whitelisted.  New features require
a deliberate code change — they cannot silently enter the decision vector.

Any exception inside the gate also produces DENY (not ALLOW).  The gate is
stateless between calls; its internal statistics counter does not affect
decisions.

### Audit Log (`audit_log.py`)

The audit log is an append-only SHA-256 hash chain.

**Wire format** (all integers little-endian):

```
entry_hash = SHA-256(
    prev_hash         -- 32 bytes (genesis = 0x00 × 32)
    seq               -- uint64
    candidate_id      -- uint32
    decision          -- uint8  (HIRE=1, REJECT=0)
    confidence        -- float64 IEEE-754
    policy_allowed    -- uint8  (ALLOW=1, DENY=0)
    timestamp_ns      -- uint64
)
```

Why this structure catches tampering:

- **Changing a decision** (HIRE→REJECT) alters `decision` byte → hash changes
  → every subsequent entry's `prev_hash` is wrong.
- **Changing a confidence score** alters the `float64` field → same cascade.
- **Deleting an entry** shifts all sequence numbers → every subsequent hash fails.
- **Inserting a fabricated entry** requires finding a SHA-256 preimage → computationally infeasible.

`verify_chain()` recomputes every hash from genesis in O(n).  It is called
after all 100 entries are appended and before any export.

---

## Layer 3 — Statistical Validation

### Chi-Squared Test of Independence

For each protected attribute `A` and binary outcome `D` (HIRE/REJECT):

1. Build an r × 2 contingency table (r = number of groups for `A`).
2. Compute expected cell counts under independence: `E[i,j] = row_i × col_j / n`.
3. Compute the test statistic: `χ² = Σ (O - E)² / E`.
4. p-value = P(χ²(df) > χ²_observed), where df = (r-1) × (2-1) = r-1.
5. Cramér's V = √(χ² / (n × (min(r, 2) - 1))) — effect-size measure.

**Null hypothesis rejected if p ≤ 0.05.**

| Attribute | χ² | df | p-value | Cramér's V | Conclusion |
|---|---|---|---|---|---|
| Gender | 0.572 | 2 | 0.751 | 0.076 | Independent |
| Race | 2.771 | 4 | 0.597 | 0.167 | Independent |

Cramér's V interpretation: 0–0.1 = negligible, 0.1–0.3 = small effect.
Both values fall in the negligible-to-small range.

### Limitations

- **n = 100** is modest.  The chi-squared approximation is reliable when all
  expected cell counts ≥ 5.  The race test has one cell below that threshold;
  a Fisher's exact test on aggregated groups would be appropriate for formal
  regulatory submission.
- Synthetic data.  Results demonstrate the methodology, not real-world fairness
  of any deployed model.
- The test measures independence between decisions and protected attributes.
  It does not measure intersectional fairness (e.g., Black women vs. white men).
  Phase 4 (out of scope here) would add intersectional analysis.

---

## File Map

```
hiring-audit/
├── generate_data.py      Candidate generation (seeded, reproducible)
├── model.py              Decision tree training and prediction
├── policy_gate.py        Governance: protected-attribute exclusion check
├── audit_log.py          Governance: SHA-256 hash-chained audit log
├── bias_test.py          Statistical independence tests
├── phase2.py             Phase 2 orchestrator
├── main.py               Phase 1 orchestrator
├── docs/
│   ├── PROOF_STATEMENT.md          (this audit's regulatory deliverable)
│   ├── REFERENCE_IMPLEMENTATION.md (this document)
│   └── ONE_PAGER.md                (business-facing summary)
└── output/
    ├── candidates.csv / .json       Raw candidate profiles
    ├── decisions.csv                100 decisions, protected attrs masked
    ├── audit_log.json / .csv        Full hash-chained audit log
    ├── bias_report.txt              Statistical test results
    └── model_report.txt             Tree structure and accuracy
```

---

## Reproducing the Audit

```bash
cd hiring-audit

# Phase 1: generate candidates + train model
python3 main.py

# Phase 2: policy gate + audit log + bias tests
python3 phase2.py
```

Both scripts exit 0 on success, non-zero on any error.  All randomness is
seeded (seed = 42); outputs are byte-for-byte identical across runs on the
same Python version.
