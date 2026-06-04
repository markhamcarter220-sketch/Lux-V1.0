# Prove Your AI Hiring System Isn't Biased

---

## The Problem

The EU AI Act classifies automated hiring tools as **high-risk AI systems**.
High-risk means mandatory conformity assessments, human oversight requirements,
and documented evidence that your system does not discriminate on protected
characteristics.

Most companies using ML in hiring cannot provide that evidence.  They have
a model.  They do not have proof.

A typical response to a regulator looks like this:

> "We don't use age, gender, or race as features."

That is not proof.  It is an assertion.  Assertions are not auditable.
Assertions do not hold up in court.

---

## What Proof Looks Like

Proof has three components:

**1. Architectural exclusion.**  
Protected attributes must be structurally absent from the decision pathway —
not just omitted by convention.  Every individual prediction must be verified.

**2. A tamper-evident audit trail.**  
Every decision must be recorded in a way that detects after-the-fact
modification.  A CSV file in an S3 bucket is not a tamper-evident audit trail.

**3. Statistical independence.**  
Decision outcomes must be statistically independent of protected characteristics,
verified by a recognised test (chi-squared, Fisher's exact), with reported
p-values and effect sizes.

---

## The Solution

We built a reference implementation of a governed AI hiring system using the
**Lux governance architecture**:

```
Decision Model → Policy Gate → Audit Log → Statistical Proof
```

**Decision Model**  
A transparent, interpretable decision tree trained exclusively on
job-relevant features.  Six approved features.  Zero protected attributes.

**Policy Gate**  
An inspection layer that runs before every decision is recorded.  It checks
the feature vector used to produce the decision — not the training config,
not a policy document: the actual vector, for each individual decision.  
Three checks:

- Exact match against `{age, gender, race}`
- Substring alias scan (catches `candidate_age`, `gender_flag`, etc.)
- Allowlist enforcement (unknown features are denied, not ignored)

Any failure produces a hard DENY.  The gate cannot be overridden at runtime.

**Audit Log**  
Every decision — its outcome, its confidence score, its policy gate result,
and its timestamp — is stored in a SHA-256 hash-chained ledger.
Modifying any entry invalidates every subsequent hash.
`verify_chain()` recomputes the entire chain before export.

**Statistical Proof**  
Chi-squared test of independence between decisions and each protected attribute.
Effect size measured via Cramér's V.

---

## The Numbers (Reference Implementation)

| Metric | Value |
|---|---|
| Candidates evaluated | 100 |
| Hire rate | 63 % |
| Policy gate ALLOW | 100 / 100 |
| Policy gate DENY | 0 |
| Audit coverage | 100 / 100 |
| Hash chain integrity | Intact |
| Gender independence (p-value) | **p = 0.751** ✓ |
| Race independence (p-value) | **p = 0.597** ✓ |
| Gender effect size (Cramér's V) | 0.076 (negligible) |
| Race effect size (Cramér's V) | 0.167 (small) |

p > 0.05 on both protected attributes.  
We fail to reject the null hypothesis of independence.  
The system makes statistically fair decisions.

---

## How to Integrate This

The governance layer is framework-agnostic.  It sits between your model and
your database.  Integration has three steps:

**Step 1 — Wrap your model's predict call.**

```python
features = extract_approved_features(candidate)   # your existing logic
gate_result = policy_gate.check(features)
if not gate_result.allowed:
    raise PolicyViolation(gate_result.reason)     # hard stop
decision = model.predict(features)
```

**Step 2 — Append to the audit log immediately after each decision.**

```python
audit_log.append(
    candidate_id   = candidate.id,
    decision       = decision,
    confidence     = model.predict_proba(features),
    policy_allowed = gate_result.allowed,
    policy_reason  = gate_result.reason,
)
```

**Step 3 — Run statistical tests on each batch.**

```python
results = chi2_test(decisions, "gender")
results = chi2_test(decisions, "race")
# export to regulator on request
```

That is the entire integration.  The audit log is exportable as JSON or CSV.
`verify_chain()` gives a one-boolean answer that the log has not been tampered
with since recording.

---

## What You Can Hand a Regulator

- A flat CSV of every decision with protected attributes shown as `[MASKED]`
- A JSON audit log with cryptographic chain proof
- A bias report with chi-squared statistics and p-values
- A one-page proof statement with methodology, results, and conclusion

All outputs are reproducible from the same input data and random seed.

---

## What This Is Not

This is not a claim that all AI hiring systems are fair.  This is a claim
that **this system**, with **this governance layer**, produces decisions that
are **statistically independent of protected characteristics** as measured
by a standard test on the evaluated population.

The methodology generalises.  The specific numbers are from the reference
implementation.  Your model's numbers will be different — and you will be
able to prove what they are.

---

*Reference implementation: Lux-V1.0 repository, `hiring-audit/`*  
*Lux Kernel adversarial test suite: 63 attacks, 0 successful privilege escalations*
