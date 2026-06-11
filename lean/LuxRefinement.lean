/-!
# Lux Kernel — Refinement Proofs (Lean 4)

Closes the **refinement gap** between `LuxSpec` (abstract ideal system) and
`LuxCostModel` (concrete Lean model of the Rust implementation).

```
LuxSpec (abstract ideal)       ←── this file ───→   LuxCostModel (concrete model)
"FOR ALL inputs, X holds"                            "THIS function does X"
(pure abstract math)                                 (mirrors Rust source)
                                                             ↑
                                          Kani proofs in src/metabolism/ledger.rs
                                          and src/auth/capability.rs close the
                                          gap to the actual compiled binary.
```

## §1 — Deduction Refinement

**Theorem `concreteDeductSpec`:** The `deduct` function from `LuxCostModel`
satisfies every property of `AbstractLedger.Spec`.

Supporting lemmas prove the two properties of the updated ledger `l'` that
`deduct_exact` in `LuxCostModel` does not directly expose:
- `l'` carries the new balance at the deducted node.
- `l'` is identical to `l` at every other node.

## §2 — Capability Non-Amplification

**Theorem `delegate_non_amplification`:** For `concreteDelegateCap` (the Lean
model of `Capability::delegate` from `src/auth/capability.rs`), any successful
delegation produces a token whose rights are a subset of the delegator's rights.

**Theorem `concreteDelegateSpec`:** The full `AbstractCapability.DelegateSpec`
is satisfied — packaging all three delegation invariants as a single proof
certificate.

## Verification

```sh
cd lean
lake build   # requires Lean 4 + Lake
```

Install Lean 4: https://leanprover.github.io/lean4/doc/quickstart.html
-/

import LuxCostModel
import LuxSpec

-- ── §1  Deduction Refinement ──────────────────────────────────────────────────

section DeductRefinement

/-!
### Supporting lemmas

`deduct_exact` in `LuxCostModel` provides `∃ l', deduct l n a = some (l', b - a)`
but does not characterise `l'` further.  The two lemmas below extract the
concrete structure of `l'` from the definition of `deduct`.
-/

/-- **Lemma: Updated node carries the new balance.**
    After a successful deduction, the target node's balance in the returned
    ledger is exactly `balance - amount`. -/
lemma deduct_self_updated
    (l : Ledger) (node : NodeId) (amount balance : Balance)
    (h_decl : l node = some balance) (h_ok : amount ≤ balance) :
    ∃ l', deduct l node amount = some (l', balance - amount) ∧
          l' node = some (balance - amount) := by
  unfold deduct
  rw [h_decl, dif_pos h_ok]
  exact ⟨_, rfl, by simp⟩

/-- **Lemma: Other nodes are unaffected by deduction.**
    The returned ledger agrees with `l` on every node other than `node`. -/
lemma deduct_other_unchanged
    (l : Ledger) (node : NodeId) (amount balance : Balance)
    (h_decl : l node = some balance) (h_ok : amount ≤ balance)
    (other : NodeId) (h_neq : other ≠ node) :
    ∃ l', deduct l node amount = some (l', balance - amount) ∧
          l' other = l other := by
  unfold deduct
  rw [h_decl, dif_pos h_ok]
  exact ⟨_, rfl, by simp [h_neq]⟩

/-- **Theorem: Deduction Refinement.**

    The concrete `deduct` function from `LuxCostModel` — the Lean mirror of
    `src/metabolism/ledger.rs` — satisfies every property of the abstract
    deduction specification.

    This proof packages the seven theorems from `LuxCostModel` into the
    four-property `AbstractLedger.Spec` structure, confirming that the
    concrete model is a valid refinement of the abstract ideal. -/
theorem concreteDeductSpec :
    AbstractLedger.Spec deduct := {

  -- Property 1: Undeclared node → always `none`.
  -- Delegated directly to `deduct_undeclared_node` from `LuxCostModel`.
  undeclared := deduct_undeclared_node

  -- Property 2: Over-quota → `none`.
  -- Delegated directly to `deduct_over_quota` from `LuxCostModel`.
  over_quota := deduct_over_quota

  -- Property 3: Exact accounting on success.
  -- The witness `l'` is the concrete updated ledger from `deduct`'s definition:
  --   `fun m => if m == node then some (b - a) else l m`
  exact_amount := by
    intro l nd a b h_decl h_ok
    unfold deduct
    rw [h_decl, dif_pos h_ok]
    -- Goal: ∃ l', some (fun m => if m == nd then some (b-a) else l m, b-a)
    --              = some (l', b-a) ∧ l' nd = some (b-a) ∧ ∀ m ≠ nd, l' m = l m
    refine ⟨fun m => if m == nd then some (b - a) else l m, rfl, by simp, ?_⟩
    intro m h_neq
    simp [h_neq]

  -- Property 4: Atomicity — failed deduction has no output ledger.
  -- Delegated directly to `deduct_atomic` from `LuxCostModel`.
  atomic := deduct_atomic
}

end DeductRefinement

-- ── §2  Capability Model and Non-Amplification ────────────────────────────────

section CapabilityRefinement

open AbstractCapability

/-!
### Concrete delegation model

`concreteDelegateCap` is the Lean 4 model of `Capability::delegate` from
`src/auth/capability.rs`.  The two guard conditions mirror the Rust exactly:

```rust
// Rust (src/auth/capability.rs)
pub const fn delegate(&self, new_target: NodeId, subset: CapabilitySet, nonce: u64)
    -> Option<Self>
{
    if !self.rights.contains(CapabilitySet::DELEGATE) { return None; }
    if !self.rights.contains(subset)                  { return None; }
    Some(Self { ..., rights: subset, ... })
}
```

The Lean model uses `Finset Right` instead of the Rust `u32` bitfield, making
the subset relationship (`⊆`) syntactically direct without bit-manipulation.
-/

/-- **Concrete delegation function.**

    Returns `none` when:
    - The delegator does not hold `Right.Delegate`, or
    - `subset` is not a subset of the delegator's rights.

    Returns `some delegated` otherwise, where `delegated.rights = subset`.

    This is the Lean mirror of `Capability::delegate` in `src/auth/capability.rs`. -/
def concreteDelegateCap (cap : Cap) (subset : Rights) : Option Cap :=
  if Right.Delegate ∉ cap.rights then none
  else if ¬(subset ⊆ cap.rights)  then none
  else some { cap with rights := subset }

/-!
### Individual property theorems

The three properties are proved individually before being packaged into
`concreteDelegateSpec`.
-/

/-- **Theorem: Delegation requires `Right.Delegate`.**

    A token without `Right.Delegate` cannot produce a delegation under any
    input.  Corresponds to the Kani proof `no_delegate_right_produces_no_delegation`
    in `src/auth/capability.rs`. -/
theorem delegate_requires_right (cap : Cap) (subset : Rights)
    (h : Right.Delegate ∉ cap.rights) :
    concreteDelegateCap cap subset = none := by
  simp [concreteDelegateCap, h]

/-- **Theorem: Non-subset delegation fails.**

    Requesting rights that are not held by the delegator is denied.
    Corresponds to the Rust guard `if !self.rights.contains(subset)`. -/
theorem delegate_rejects_superset (cap : Cap) (subset : Rights)
    (h : ¬(subset ⊆ cap.rights)) :
    concreteDelegateCap cap subset = none := by
  simp [concreteDelegateCap, h]

/-- **Theorem: Capability Non-Amplification (I2 — the central invariant).**

    For any successful delegation, the delegated token's rights are a subset
    of the delegator's rights.  Privilege escalation via delegation is
    **mathematically impossible** given this definition.

    Proof strategy:
    1. Unfold `concreteDelegateCap` and case-split on both guards.
    2. The two failure cases (`none` returned) immediately contradict `h`.
    3. In the success case, the guards guarantee `subset ⊆ cap.rights`,
       and the returned token carries exactly `subset` as its rights.

    This is the Lean 4 counterpart of the Kani proof
    `delegate_never_amplifies_rights` in `src/auth/capability.rs`. -/
theorem delegate_non_amplification
    (cap : Cap) (subset : Rights) (delegated : Cap)
    (h : concreteDelegateCap cap subset = some delegated) :
    delegated.rights ⊆ cap.rights := by
  simp only [concreteDelegateCap] at h
  -- Split on the two guard conditions.
  split_ifs at h with h1 h2
  · -- Guard 1 true: Right.Delegate ∉ cap.rights → result is `none`.
    -- h : none = some delegated — contradiction.
    simp at h
  · -- Guard 1 false, Guard 2 true: ¬(subset ⊆ cap.rights) → result is `none`.
    -- h : none = some delegated — contradiction.
    simp at h
  · -- Both guards false: result is `some { cap with rights := subset }`.
    -- h1 : ¬(Right.Delegate ∉ cap.rights)  →  Right.Delegate ∈ cap.rights
    -- h2 : ¬¬(subset ⊆ cap.rights)          →  subset ⊆ cap.rights
    -- h  : some { cap with rights := subset } = some delegated
    --
    -- Extract: delegated = { cap with rights := subset }
    have h_eq : delegated = { cap with rights := subset } :=
      (Option.some.inj h).symm
    -- Rewrite delegated in the goal and reduce the struct field access.
    rw [h_eq]
    -- Goal: { cap with rights := subset }.rights ⊆ cap.rights
    -- = subset ⊆ cap.rights  (definitionally)
    -- which follows from h2 : ¬¬(subset ⊆ cap.rights).
    exact Decidable.of_not_not h2

/-- **Theorem: Full Delegation Specification.**

    `concreteDelegateCap` satisfies the complete `AbstractCapability.DelegateSpec`,
    packaging all three delegation invariants as a single proof certificate.

    This is the main refinement statement for capability delegation:
    the concrete model is a valid refinement of the abstract ideal. -/
theorem concreteDelegateSpec :
    AbstractCapability.DelegateSpec concreteDelegateCap := {
  requires_delegate := delegate_requires_right
  non_amplification := fun cap subset delegated h =>
      delegate_non_amplification cap subset delegated h
  rejects_superset  := delegate_rejects_superset
}

end CapabilityRefinement

-- ── §3  Refinement Summary ────────────────────────────────────────────────────

/-!
## What these proofs establish

| Theorem | Abstract property | Concrete function |
|---------|-------------------|-------------------|
| `concreteDeductSpec.undeclared`   | Undeclared node → `none`             | `deduct` (LuxCostModel) |
| `concreteDeductSpec.over_quota`   | `amount > balance` → `none`          | `deduct` (LuxCostModel) |
| `concreteDeductSpec.exact_amount` | New balance = `balance − amount`     | `deduct` (LuxCostModel) |
| `concreteDeductSpec.atomic`       | Failed deduction has no output state | `deduct` (LuxCostModel) |
| `delegate_non_amplification`      | `delegated.rights ⊆ cap.rights`      | `concreteDelegateCap`   |
| `concreteDelegateSpec.requires_delegate` | No `DELEGATE` → no delegation | `concreteDelegateCap`   |
| `concreteDelegateSpec.rejects_superset`  | Non-subset request → `none`   | `concreteDelegateCap`   |

## What is NOT modelled here (honest gaps)

1. **`u64` bounds** — Lean `Nat` is unbounded; Rust `u64` wraps at 2⁶⁴ − 1.
   The `checked_sub` gate means no arithmetic path produces a balance above
   the seeded ceiling, but a `Fin (2^64)` formalisation is out of scope here.

2. **Bitfield ↔ `Finset` correspondence** — `concreteDelegateCap` uses
   `Finset Right`; the Rust implementation uses `u32` bitflags.  A full
   refinement would prove the two representations are isomorphic.
   That proof is the remaining gap between this file and the binary.

3. **Nonce replay / generation gating** — `Policy::check` enforces I1
   (Fail-Closed) via nonce tracking and generation comparison.  These are
   specified in `AbstractLedger` only implicitly (atomicity).  A future
   `LuxPolicySpec.lean` can formalise them.

4. **Concurrent access** — proofs here are sequential; the TLA+ model
   (`tla/LuxKernel.tla`) covers distributed concurrency.
-/
