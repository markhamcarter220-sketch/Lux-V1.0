# Lux Kernel — Refinement Gaps

**Status:** Lean 4 proofs in `lean/Refinement.lean` are scaffolded with named
`sorry` placeholders.  **No invariant in that file is mechanically verified.**

This document gives a plain-language description of what each `sorry` represents,
why it exists, and the estimated effort to close it.  It is intended as the
primary briefing document for an independent proof engineer or OSTIF auditor.

---

## Existing proved layer (do not re-prove)

The following are fully proved (no `sorry`) in the existing Lean files:

| Theorem | File | What it proves |
|---------|------|---------------|
| `concreteDeductSpec` | `LuxRefinement.lean` | `deduct` satisfies all 4 properties of `AbstractLedger.Spec` |
| `delegate_non_amplification` | `LuxRefinement.lean` | Delegation never escalates rights (`Finset Right` level) |
| `concreteDelegateSpec` | `LuxRefinement.lean` | Full `DelegateSpec` satisfied by `concreteDelegateCap` |
| `bitsContainsIffSubset` | `LuxCapabilityBridge.lean` | `u32` bitwise AND ↔ `Finset.Subset` (1024-case decision) |
| Roundtrip theorems | `LuxCapabilityBridge.lean` | `bitsToRights ∘ rightsToBits = id` and `rightsToBits ∘ bitsToRights = mask` |

The obligations below sit *above* these proofs: they ask whether the proved
layer is sufficient to discharge the four system-level invariants.

---

## I1 — Fail-Closed

### Gaps: `failClosed_generation`, `failClosed_revocation`, `failClosed_replay`

**What these say in plain language:**
If the generation check fails, or the nonce is revoked, or the nonce has been
replayed, then `policyCheck` returns `false`.

**Why they have `sorry`:**
The `policyCheck` model in `Refinement.lean` is an `&&`-chain of four Boolean
conditions.  Lean's `simp` needs to destructure `Bool.and_eq_false` across all
four conjuncts to show that a single false conjunct makes the whole chain false.
The tactic `simp [Bool.and_eq_false, Bool.not_true]` likely closes all three
immediately, but it has not been attempted.

**Prerequisite knowledge:**
Basic Lean 4 `simp` lemma lookup; no mathematical content.

**Estimated closure:** < 1 day.

**Missing model element:**
`policyCheck` omits the *mutation* side of `Policy::check_inner` — namely,
recording the nonce in `usedNonces` after a successful check.  The full
fail-closed property includes "nonce window exhaustion → deny" (step 4 in
`src/auth/policy.rs:99-103`).  Modelling this requires threading a state monad
through `policyCheck`.  Estimated additional work: 1 day.

---

## I2 — Capability-Gated

### Gap: `capabilityGated_rightRequired`

**What it says in plain language:**
If `policyCheck` returns `true`, then the requested right is actually in the
token's rights set.

**Why it has `sorry`:**
Same `Bool.and_eq_true` decomposition as the I1 gaps — the last conjunct of
`policyCheck` is the rights check.  `simp [Bool.and_eq_true]` applied four
times should extract it.

**Estimated closure:** < 1 day.

### Gap: `delegationNonAmplification` — **no sorry** (already closes)

The theorem in `Refinement.lean` closes directly from its hypotheses.  The
*real* work is constructing the hypotheses at a call site — specifically,
proving that `concreteDelegateCap` (from `LuxRefinement.lean`) satisfies those
hypotheses when called via `Policy::check`.  This coercion from the `Cap` type
used in `LuxRefinement` to the `RustCap` type defined in `Refinement.lean` is
not yet written.

**Estimated closure:** 1 day (write the coercion lemma; the proof then assembles
from existing proved theorems).

### TCB gap affecting I2: `WorkQueue::enqueue` bypass

The `Scheduler::schedule` wrapper in `src/scheduler/mod.rs` enforces
`CapabilitySet::SCHEDULE` via `Policy::check`.  However, `WorkQueue::enqueue`
remains a public method that bypasses the check.  There is no Lean model of
`WorkQueue` and therefore no theorem that closes this gap formally.

**Blast radius:** Any caller that accesses `WorkQueue` directly and calls
`enqueue` without first calling `Scheduler::schedule` bypasses I2 for
scheduling operations.  In the current codebase only test harnesses do this
(using `WorkQueue` directly for capacity tests).

**Estimated closure:** 2–3 days to write a Lean model of `Scheduler` and prove
that the `schedule` method is the only path to `WorkQueue::enqueue` visible
from the public API.

---

## I3 — Accountable Resources

### Gap: `accountableResources_soleDeductionPath`

**What it says in plain language:**
The only way a node's balance can decrease is via a call to `deductFn` that
satisfies `AbstractLedger.Spec`.

**Why it has `sorry`:**
This is a *meta-property* about the `Spec` predicate: it says that the four
Spec properties are *complete* in the sense that no other function satisfying
the Spec can reduce a balance except through `exact_amount`.  The argument
requires showing:
1. `over_quota` forbids deduction when `amount > balance`.
2. `exact_amount` forces the new balance to be `balance - amount`.
3. Combined, these two imply that the only reachable `(l', b')` pairs have
   `b' = balance - amount` for some `amount ≤ balance`.

This is a formal inductive argument over the Spec structure.  No novel
mathematics, but requires careful encoding.

**Estimated closure:** 2–3 days.

### Gap: `accountableResources_ceilingBound`

**What it says in plain language:**
After seeding a node with ceiling `c`, every successful deduction produces a
balance in `[0, c]`.

**Why it has `sorry`:**
`LuxCostModel.ledger_invariant` already proves this for the concrete `deduct`
function.  Lifting to any function satisfying `AbstractLedger.Spec` requires
combining `spec.exact_amount` (gives `b = ceiling - amount`) with
`spec.over_quota` (gives `amount ≤ ceiling` on success).  A 5-line Lean proof
once the induction structure is identified.

**Estimated closure:** 1 day.

### TCB gap affecting I3: u64 vs Lean `Nat`

`Ledger::deduct` in Rust uses `u64` arithmetic with `checked_sub`.  The Lean
model uses `Nat` (unbounded).  There is no Lean theorem bounding ledger
balances to `[0, 2^64 - 1]`.  The `checked_sub` gate prevents underflow
(and the Kani proof `successful_deduction_is_exact` verifies this at the Rust
level), but the 2^64 ceiling is not formally modelled.

**Impact:** The `accountableResources_ceilingBound` theorem would need a
`Fin (2^64)` version of the ledger to fully close this gap.

**Estimated closure:** 3–5 additional days beyond the `Nat` version.

---

## I4 — Topology-Bounded

### Gap: `topologyBounded_traversalSubsetDeclaredEdges` (under hypothesis)

**What it says in plain language:**
Every successful traversal corresponds to a declared edge.

**The theorem closes given `hCorrespondence`.**  The remaining work is proving
`hCorrespondence` — that the 64×64 `u64` bitmask in `OperationalGraph` is
equivalent to the set of edges passed to `permit_edge` during booting.

**Why this is hard:**
1. The Rust `edge_matrix: [u64; 64]` must be modelled in Lean as a
   `Fin 64 → Fin 64 → Bool` or a `Finset (Fin 64 × Fin 64)`.
2. The sealing step `BootingGraph::seal` copies `edge_matrix` verbatim.
   Lean needs a model of both `BootingGraph` and `OperationalGraph` and a
   proof that seal preserves the edge set.
3. `permit_edge` sets bit `di` in `edge_matrix[si]`.  The correspondence
   `(si, di) ∈ declaredEdges ↔ (edge_matrix[si] >> di) & 1 == 1` requires
   the `bitsContainsIffSubset` approach extended to 2D.

**Prerequisites:**
- Lean 4 `BitVec` or `Fin`-indexed array model for the bitmask
- Understanding of `LuxCapabilityBridge.lean`'s bitmask approach (reusable)

**Estimated closure:** 3–5 days for the `hCorrespondence` proof; an additional
1 day to write the `BootingGraph`/`OperationalGraph` Lean types.

### Gap: `topologyBounded_sealingIrreversible`

**What it says in plain language:**
Once the graph is sealed, no new edges can be added.

**Status:** The `Refinement.lean` theorem for this is a trivial placeholder
(proves `True`).  The meaningful statement — that no function of type
`OperationalGraph → Edge → OperationalGraph` can be defined from the current
Lean model — is a *structural property* of the model, not a theorem within it.

It is guaranteed at the Rust level by the ownership/move semantics of `seal`
(`src/topology/graph.rs:94`): `seal(self)` consumes `BootingGraph` by value,
making it impossible to call `permit_edge` on it afterward.  Lean's type system
would provide the same guarantee once `OperationalGraph` is defined without
any mutation methods.

**Estimated closure:** 1 day once the `OperationalGraph` Lean type is written
(dependency of I4-A above).

---

## Cross-cutting gaps

### Concurrent access
All proofs here are sequential.  The TLA+ model (`tla/LuxKernel.tla`) covers
distributed concurrency.  There is no Lean formalisation of concurrent
semantics.  This is a known, documented gap in `lean/LuxRefinement.lean §3`.

### Nonce window mutable state
`Policy::check_inner` mutates `used_nonces` on success (step 4).  The Lean
`policyCheck` model is a pure Boolean function and does not represent this
mutation.  A complete I1 formalisation requires a state-monad model of
`PolicyState` or an explicit `(input, output)` pair for `used_nonces`.

### Scheduler `WorkQueue` bypass
See I2 section above.

---

## Recommended proof engineering sequence

For an auditor closing these gaps top-down (highest value first):

1. **Close I1-A, I2-A** (< 2 days combined): pure `simp` / `Bool` algebra.
   These are the quickest wins and validate the `policyCheck` model.

2. **Write `OperationalGraph` Lean type** (1 day): prerequisite for I4-A and I4-B.
   Model `edge_matrix` as `Fin 64 → Fin 64 → Bool`.

3. **Close I4-A `hCorrespondence`** (3–5 days): the core topology proof.
   Reuse the bitmask approach from `LuxCapabilityBridge.lean`.

4. **Close I3-B `ceilingBound`** (1 day): short proof from existing Spec properties.

5. **Close I3-A `soleDeductionPath`** (2–3 days): the abstract completeness argument.

6. **Model mutable nonce window** (1–2 days): state monad extension of I1.

7. **Write `Scheduler` Lean model and close I2 scheduler gap** (2–3 days).

Total estimated investment to close all gaps: **11–17 days** of focused Lean 4
proof engineering.
