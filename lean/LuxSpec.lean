/-!
# Lux Kernel — Abstract Formal Specification (Lean 4)

**Pure mathematical specification of two core security primitives.**

This file defines the *ideal system* — what the kernel primitives **must**
do — without any reference to implementation details such as bitwise operations,
`heapless` memory layouts, or `u64` overflow behaviour.

The refinement proofs in `LuxRefinement.lean` bridge this specification to the
concrete Lean model in `LuxCostModel.lean`, which mirrors the Rust source.

```
LuxSpec (this file)        LuxRefinement.lean        LuxCostModel.lean
"FOR ALL inputs, X holds"  ←─ refinement proof ──→   "THIS function does X"
(pure abstract math)                                  (mirrors Rust impl)
                                                            ↑
                                         Kani proofs in src/ close the gap
                                         between the Lean model and the binary
```

## §1 — Abstract Resource Ledger (I3: Accountable Resources)

> *Every allocation is charged; over-quota requests are hard-rejected.*

The specification is a predicate on any deduction function:
four required properties capture the "what" without constraining the "how".

## §2 — Abstract Capability Rights (I2: Capability-Gated / Non-Amplification)

> *No operation proceeds without a valid, scoped capability token.*

The delegation specification requires that the delegated token's rights are
always a subset of the delegator's rights — privilege amplification is
algebraically forbidden.

## Verification

```sh
cd lean
lake build   # requires Lean 4 + Lake
```

Install Lean 4: https://leanprover.github.io/lean4/doc/quickstart.html
-/

-- ── §1  Abstract Resource Ledger ─────────────────────────────────────────────

namespace AbstractLedger

/-- Abstract node identifier.  `Nat` subsumes `NonZeroU32`; the non-zero
    constraint is a deployment invariant not needed for these proofs. -/
abbrev NodeId  := Nat

/-- Abstract resource balance.  `Nat` has no negative values by construction,
    which is the property `checked_sub` enforces in Rust. -/
abbrev Balance := Nat

/-- Abstract ledger: a partial map from node IDs to balances.
    `none` denotes an undeclared (never-seeded) node. -/
def Ledger := NodeId → Option Balance

/-- **Abstract deduction specification.**

    A predicate on any deduction function `deduct`.  Captures the four
    required properties independently of any particular implementation.

    Corresponds to the Kani proofs in `src/metabolism/ledger.rs` and the
    theorems in `LuxCostModel.lean`, but stated at the *abstract* level. -/
structure Spec
    (deduct : Ledger → NodeId → Balance → Option (Ledger × Balance)) : Prop where

  /-- **Undeclared-node rejection.**
      Deducting from a node that was never seeded always fails.
      Rust: `balances.get_mut(&node.get())?` returns `None`. -/
  undeclared :
      ∀ (l : Ledger) (n : NodeId) (a : Balance),
        l n = none → deduct l n a = none

  /-- **Over-quota rejection.**
      When `amount > balance`, the deduction fails and the ledger is unchanged.
      Rust: `balance.checked_sub(amount)?` returns `None`. -/
  over_quota :
      ∀ (l : Ledger) (n : NodeId) (a b : Balance),
        l n = some b → a > b → deduct l n a = none

  /-- **Exact accounting.**
      A successful deduction reduces the balance by exactly `amount`, not more
      and not less.  The updated ledger differs from `l` only at node `n`. -/
  exact_amount :
      ∀ (l : Ledger) (n : NodeId) (a b : Balance),
        l n = some b → a ≤ b →
        ∃ l', deduct l n a = some (l', b - a)
             ∧ l' n = some (b - a)
             ∧ ∀ m, m ≠ n → l' m = l m

  /-- **Atomicity.**
      A failed deduction produces no output ledger.  Partial state does not
      exist: if `deduct` returns `none`, there is no `(l', b)` pair. -/
  atomic :
      ∀ (l : Ledger) (n : NodeId) (a : Balance),
        deduct l n a = none →
        ¬ ∃ (l' : Ledger) (b : Balance), deduct l n a = some (l', b)

end AbstractLedger

-- ── §2  Abstract Capability Rights ───────────────────────────────────────────

namespace AbstractCapability

/-- The five distinct operation rights that a capability token can carry.

    Modelled as an inductive type rather than a bitfield so that subset
    reasoning (`s ⊆ t`) is directly expressed with `Finset.Subset`, making
    the non-amplification proof syntactically straightforward. -/
inductive Right : Type where
  | ReadTopology  : Right   -- may read topology edges at the bound node
  | AllocResource : Right   -- may request allocation from the ledger
  | Schedule      : Right   -- may enqueue work items
  | Delegate      : Right   -- may delegate a subset of own rights
  | Shutdown      : Right   -- may invoke the graceful-shutdown path
  deriving DecidableEq, Repr

/-- A rights set: a `Finset` over the five `Right` values.
    Subset relationships (`s ⊆ t`) express non-amplification directly. -/
abbrev Rights := Finset Right

/-- An abstract capability token. -/
structure Cap where
  rights     : Rights
  /-- Generation epoch at which the token was issued. -/
  generation : Nat
  deriving Repr

/-- **Abstract delegation specification.**

    A predicate on any delegation function `delegate`.
    Three required properties capture capability non-amplification (I2).

    Corresponds to the Kani proofs `delegate_never_amplifies_rights` and
    `no_delegate_right_produces_no_delegation` in `src/auth/capability.rs`. -/
structure DelegateSpec (delegate : Cap → Rights → Option Cap) : Prop where

  /-- **Delegation requires the `Delegate` right.**
      A token without `Right.Delegate` cannot produce any delegation.
      Rust: `if !self.rights.contains(CapabilitySet::DELEGATE) { return None }`. -/
  requires_delegate :
      ∀ (cap : Cap) (subset : Rights),
        Right.Delegate ∉ cap.rights → delegate cap subset = none

  /-- **Non-amplification (I2 — the core invariant).**
      The delegated token's rights are always a subset of the delegator's.
      Privilege escalation via delegation is algebraically impossible. -/
  non_amplification :
      ∀ (cap : Cap) (subset : Rights) (delegated : Cap),
        delegate cap subset = some delegated →
        delegated.rights ⊆ cap.rights

  /-- **Superset delegation fails.**
      Requesting rights not held by the delegator is denied.
      Rust: `if !self.rights.contains(subset) { return None }`. -/
  rejects_superset :
      ∀ (cap : Cap) (subset : Rights),
        ¬(subset ⊆ cap.rights) → delegate cap subset = none

end AbstractCapability
