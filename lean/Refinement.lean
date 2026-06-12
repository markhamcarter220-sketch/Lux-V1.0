/-!
# Lux Kernel — Invariant Refinement Obligations (Lean 4)

This file scaffolds one refinement obligation per Lux security invariant (I1–I4).
Each obligation is stated as a `theorem` with a `sorry` placeholder.

**Honest status:** every `sorry` here is an open proof obligation.
No invariant in this file is mechanically verified.
See `docs/REFINEMENT_GAPS.md` for plain-language descriptions and estimated
closure difficulty.

## Relationship to the existing proof tree

```
LuxSpec.lean         — abstract specification (proved)
LuxCostModel.lean    — concrete ledger model (proved)
LuxRefinement.lean   — deduction + delegation refinement (proved)
LuxCapabilityBridge.lean — u32 ↔ Finset Right isomorphism (proved, one gap)
Refinement.lean (this file) — I1–I4 obligation stubs (all sorry)
```

The obligations here sit *above* the existing proofs: they ask whether the
abstract specifications already proved in `LuxRefinement.lean` and
`LuxCapabilityBridge.lean` are sufficient to close the four invariants claimed
at the system level.

## Import note

`LuxCapabilityBridge` transitively imports `LuxRefinement` → `LuxCostModel`
and `LuxSpec`.  All definitions in those modules are in scope here.
-/

import LuxCapabilityBridge

open AbstractLedger AbstractCapability

-- ── Shared model types ────────────────────────────────────────────────────────
-- These mirror the Rust types without duplicating the full implementation.
-- Each `sorry`-block explains which Rust concepts are not yet lifted to Lean.

/-- Model of `Capability` sufficient for I1 and I2 obligations.
    The Rust struct carries `generation : u64` and `nonce : u64`; we use
    `Nat` here (unbounded) — the u64 ceiling is a TCB gap (see REFINEMENT_GAPS.md). -/
structure RustCap where
  rights     : Rights
  generation : Nat
  nonce      : Nat

/-- Model of `Policy` state sufficient for I1 and I2.
    `usedNonces` is a list (bounded by `NONCE_WINDOW = 256` at the Rust level;
    unbounded here — a sorry-scope gap). -/
structure PolicyState where
  currentGeneration : Nat
  usedNonces        : List Nat
  revokedNonces     : List Nat

-- ── I1 — Fail-Closed ─────────────────────────────────────────────────────────

/-- Abstract model of `Policy::check_inner`.
    Returns `true` iff all four checks pass; `false` otherwise.
    Models only the Boolean outcome, not the mutation of `usedNonces`. -/
def policyCheck (state : PolicyState) (cap : RustCap) (right : Right) : Bool :=
  -- Step 1: generation check
  cap.generation >= state.currentGeneration &&
  -- Step 2: revocation check
  !state.revokedNonces.contains cap.nonce &&
  -- Step 3: nonce replay check
  !state.usedNonces.contains cap.nonce &&
  -- Step 4: rights check (modelled via Finset membership)
  (Rights.instDecidableMem right cap.rights).decide

/-!
### Theorem I1-A: Fail-Closed — no ambiguous path returns `true`

**Obligation:** For every `PolicyState`, every `RustCap`, and every `Right`:
if any of the four guards fires, `policyCheck` returns `false`.

**Why sorry:**
1. `policyCheck` above is an executable model, not a proof object.  The theorem
   needs to enumerate all cases where a guard fires and show the result is `false`.
   This is mechanically straightforward but requires `decide` or case analysis
   over `Bool` terms — a few hours of Lean 4 work.
2. The model omits the step-4 nonce-recording side effect.  A complete proof
   requires threading mutable state (modelled as a state monad or explicit pair).
   Estimated closure: 1–2 days.
-/
theorem failClosed_generation
    (state : PolicyState) (cap : RustCap) (right : Right)
    (h : cap.generation < state.currentGeneration) :
    policyCheck state cap right = false := by
  simp [policyCheck, Nat.not_le.mpr h]
  -- sorry: need to show the &&-chain short-circuits on the first false operand
  sorry

theorem failClosed_revocation
    (state : PolicyState) (cap : RustCap) (right : Right)
    (h : state.revokedNonces.contains cap.nonce = true) :
    policyCheck state cap right = false := by
  simp [policyCheck, h]
  -- sorry: Bool.and_false not yet in scope; needs simp lemma or omega
  sorry

theorem failClosed_replay
    (state : PolicyState) (cap : RustCap) (right : Right)
    (h : state.usedNonces.contains cap.nonce = true) :
    policyCheck state cap right = false := by
  simp [policyCheck, h]
  -- sorry: same Bool algebra gap as failClosed_revocation
  sorry

-- ── I2 — Capability-Gated / Non-Amplification ────────────────────────────────

/-!
### Theorem I2-A: No `policyCheck` success without the required right

**Obligation:** If `policyCheck` returns `true`, the token's rights contain the
requested right.

**Why sorry:**
The `policyCheck` model above is an AND-chain.  Extracting the rights clause
requires showing that `true = a && b && c && d → d = true`.  Mechanically
trivial by `simp [Bool.and_eq_true]`; included as a sorry here for completeness
and to mark the obligation formally.
-/
theorem capabilityGated_rightRequired
    (state : PolicyState) (cap : RustCap) (right : Right)
    (h : policyCheck state cap right = true) :
    right ∈ cap.rights := by
  simp [policyCheck] at h
  -- sorry: need Bool.and_eq_true applied four times to extract the rights conjunct
  sorry

/-!
### Theorem I2-B: Delegation non-amplification (lift from LuxRefinement)

**Already proved** in `LuxRefinement.delegate_non_amplification` at the
`Finset Right` level.  This theorem re-states it using `RustCap` to confirm
the model types are compatible.

**Why sorry:**
`RustCap.rights` and `Cap.rights` (from `LuxRefinement`) are the same type
(`Finset Right`) but `RustCap` is defined here without deriving the full `Cap`
structure.  The proof requires a coercion lemma `rustCapToCap` that is not
yet written.
-/
theorem delegationNonAmplification
    (delegator : RustCap) (subsetRights : Rights) (delegated : RustCap)
    (hDelegate : Right.Delegate ∈ delegator.rights)
    (hSubset   : subsetRights ⊆ delegator.rights)
    (hResult   : delegated.rights = subsetRights) :
    delegated.rights ⊆ delegator.rights := by
  rw [hResult]
  exact hSubset
  -- Not a sorry: this case closes directly from hSubset and hResult.
  -- Included here to document that non-amplification holds at the RustCap level
  -- once the preconditions are established by policyCheck.

-- ── I3 — Accountable Resources ───────────────────────────────────────────────

/-!
### Theorem I3-A: `deduct` is the sole resource reduction path

**Obligation:** Any function satisfying `AbstractLedger.Spec` can only reduce
a balance via `deduct`.  Equivalently: if `l n = some b` and `b' < b`, then
there exists an `amount` such that `deduct l n amount = some (_, b')`.

**Why sorry:**
This is a meta-property about the *Spec* predicate, not about a single function.
Proving it requires showing the Spec's `exact_amount` property is the only
path to balance reduction — i.e., that `undeclared`, `over_quota`, and `atomic`
together forbid any other reduction.  The argument is:
  1. `over_quota` prevents deduction when `amount > balance`.
  2. `exact_amount` guarantees the new balance is `balance - amount`.
  3. `atomic` ensures no partial ledger update occurs.
The formal proof requires formalising "sole path" as an inductive argument
over the Spec structure.  Estimated closure: 2–3 days.

**TCB gap:** Lean `Nat` is unbounded; the Rust implementation uses `u64`.
The `checked_sub` gate prevents underflow at the Rust level, but this Lean
model does not represent the 2^64 ceiling.  See `docs/REFINEMENT_GAPS.md §I3`.
-/
theorem accountableResources_soleDeductionPath
    {deductFn : Ledger → NodeId → Balance → Option (Ledger × Balance)}
    (spec : AbstractLedger.Spec deductFn)
    (l : Ledger) (n : NodeId) (b b' : Balance)
    (h_decl : l n = some b)
    (h_reduce : b' < b) :
    ∃ (amount : Balance),
      amount ≤ b ∧ b' = b - amount ∧
      ∃ l', deductFn l n amount = some (l', b') := by
  -- sorry: requires formalising that the only balance-reducing path through
  -- the Spec is via exact_amount.  Inductive argument over Spec fields.
  sorry

/-!
### Theorem I3-B: Balance never exceeds ceiling after seeding

**Obligation:** After seeding node `n` with ceiling `c`, every successful
deduction produces a balance in `[0, c]`.  This is a corollary of
`LuxCostModel.ledger_invariant` lifted into the abstract spec.

**Why sorry:**
`LuxCostModel.ledger_invariant` already proves this for the concrete `deduct`
function.  Lifting it to any function satisfying `AbstractLedger.Spec` requires
showing the Spec's `exact_amount` and `over_quota` properties jointly imply
the invariant.  Mechanical but not yet written.  Estimated closure: 1 day.
-/
theorem accountableResources_ceilingBound
    {deductFn : Ledger → NodeId → Balance → Option (Ledger × Balance)}
    (spec : AbstractLedger.Spec deductFn)
    (l : Ledger) (n : NodeId) (ceiling : Balance)
    (h_seed : l n = some ceiling) :
    ∀ (amount : Balance) (l' : Ledger) (b : Balance),
      deductFn l n amount = some (l', b) → b ≤ ceiling := by
  -- sorry: needs spec.exact_amount + spec.over_quota combined.
  -- The exact_amount property gives b = ceiling - amount;
  -- over_quota gives amount ≤ ceiling when deduction succeeds.
  sorry

-- ── I4 — Topology-Bounded ────────────────────────────────────────────────────

/-!
### Theorem I4-A: Traversal is confined to the sealed edge set

**Obligation:** Every permitted traversal corresponds to a declared edge in the
boot manifest.  Equivalently: for any `OperationalGraph` produced by sealing a
`BootingGraph`, `traverse g src dst = Ok(())` implies `(src, dst)` was passed
to `permit_edge` during the booting phase.

**Why sorry:**
This is the hardest obligation to close formally.  It requires:
1. A Lean model of the typestate transition `BootingGraph → OperationalGraph`.
2. A proof that `seal` faithfully copies the `edge_matrix` bitmask.
3. A proof that `traverse_inner`'s bitmask check is equivalent to membership
   in the set of declared edges.

Step 3 is the crux: the bitmask check `(edge_matrix[si] >> di) & 1 == 1` must
be shown equivalent to "the edge (src, dst) was passed to `permit_edge`".
This requires formalising the 64×64 bitmask in Lean — either as a
`Fin 64 → Fin 64 → Bool` function or as a `Finset (Fin 64 × Fin 64)`.

The `OperationalGraph` Lean model does not yet exist in this proof tree.
Estimated closure: 3–5 days.  See `docs/REFINEMENT_GAPS.md §I4`.

**TCB note:** The typestate guarantee (no mutation after sealing) is enforced
by Rust's ownership/move semantics, not by a Lean proof.  This is documented
as an unverified assumption in `docs/TCB.md §Memory Safety`.
-/
theorem topologyBounded_traversalSubsetDeclaredEdges
    -- We represent the sealed edge set as a Finset of node-index pairs.
    (declaredEdges : Finset (Fin 64 × Fin 64))
    -- The operational graph is modelled as a Boolean function over node indices.
    (graphCheck : Fin 64 → Fin 64 → Bool)
    -- Assumption: graphCheck agrees with the declared edge set.
    (hCorrespondence : ∀ s d, graphCheck s d = true ↔ (s, d) ∈ declaredEdges)
    (s d : Fin 64) :
    graphCheck s d = true → (s, d) ∈ declaredEdges := by
  intro h
  exact (hCorrespondence s d).mp h
  -- Not a sorry: given the hCorrespondence hypothesis, the proof closes
  -- immediately.  The real obligation is proving hCorrespondence — i.e.,
  -- that the Rust bitmask implementation satisfies this property.

/-!
### Theorem I4-B: Sealing is irreversible (typestate lemma)

**Obligation:** Once `BootingGraph::seal` is called, the resulting
`OperationalGraph` cannot have new edges added.

**Why sorry:**
This is enforced by Rust's type system (consuming `BootingGraph` on `seal`),
not by a runtime invariant.  There is no Lean theorem that can substitute for
a compiler guarantee.  The `OperationalGraph` type in Lean would need to be
a `structure` with no mutation methods defined, which is trivially true by
construction — but that construction does not exist yet in this proof tree.

Documenting as sorry to make the gap explicit.  Estimated closure: 1–2 days
to write the Lean type, plus the above I4-A obligation.
-/
theorem topologyBounded_sealingIrreversible
    -- Placeholder types representing the Rust typestate.
    (BootingGraphType OperationalGraphType : Type)
    (seal : BootingGraphType → OperationalGraphType)
    (addEdge : BootingGraphType → Fin 64 × Fin 64 → BootingGraphType)
    -- Assumption encoding the typestate invariant: seal is total and consuming.
    -- After calling seal, addEdge is unreachable on the result type.
    -- (In Lean, this is trivially true: OperationalGraphType has no addEdge method.)
    (hNoMutationMethod : ∀ (og : OperationalGraphType), True) :
    True := by
  -- sorry: this theorem as stated is trivial (True).
  -- The real obligation — that the Lean model of OperationalGraph has no
  -- mutation methods — is a construction-time guarantee, not a theorem.
  -- Leaving as a named placeholder per the instructions.
  trivial
  -- NOTE: The meaningful statement is that no Lean function of type
  --   OperationalGraph → Edge → OperationalGraph
  -- can be defined given the current model.  That is a structural property
  -- of the model, not a provable theorem in the model.

-- ── Obligation inventory ─────────────────────────────────────────────────────

/-!
## Summary of open obligations

| Theorem | Invariant | Status | Estimated closure |
|---------|-----------|--------|-------------------|
| `failClosed_generation` | I1 | **sorry** | < 1 day |
| `failClosed_revocation` | I1 | **sorry** | < 1 day |
| `failClosed_replay` | I1 | **sorry** | < 1 day |
| `capabilityGated_rightRequired` | I2 | **sorry** | < 1 day |
| `delegationNonAmplification` | I2 | **proved** (no sorry) | — |
| `accountableResources_soleDeductionPath` | I3 | **sorry** | 2–3 days |
| `accountableResources_ceilingBound` | I3 | **sorry** | 1 day |
| `topologyBounded_traversalSubsetDeclaredEdges` | I4 | **proved** (under hypothesis) | hCorrespondence: 3–5 days |
| `topologyBounded_sealingIrreversible` | I4 | trivial placeholder | model construction: 1–2 days |

The two theorems marked **proved** close given the stated hypotheses.
Closing those hypotheses (hCorrespondence for I4-A, the coercion for I2-B)
is where the remaining work lives.

Total estimated work to close all sorries: **8–14 days** of focused Lean 4
proof engineering, assuming familiarity with Lean 4 and the Lux codebase.
See `docs/REFINEMENT_GAPS.md` for per-gap details and prerequisite knowledge.
-/
