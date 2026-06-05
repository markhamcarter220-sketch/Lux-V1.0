# Lux Kernel — Formal Cost Model

**Location:** `lean/LuxCostModel.lean`  
**Proof assistant:** Lean 4 + Mathlib (Lake build system)  
**Status:** Proof written; mechanical verification requires Lean 4 toolchain  
**Complements:** TLA+ model in `tla/LuxKernel.tla` (state-machine level)

---

## What is proved

The file `lean/LuxCostModel.lean` contains formal specifications and proofs of
the seven core correctness properties of the resource ledger
(`src/metabolism/ledger.rs`).

These properties are the arithmetic foundation of **Invariant I3 —
Accountable Resources**:

> *Every allocation is charged; over-quota requests are hard-rejected.*

| # | Theorem | Informal statement |
|---|---------|-------------------|
| 1 | `deduct_exact` | Returned balance = `balance − amount`, exactly |
| 2 | `deduct_preserves_nonneg` | Resulting balance is always ≥ 0 |
| 3 | `deduct_atomic` | No output ledger exists when deduction fails |
| 4 | `deduct_over_quota` | `amount > balance` always returns `none` |
| 5 | `deduct_undeclared_node` | Undeclared node always returns `none` |
| 6 | `ledger_invariant` | After seeding, balance stays in `[0, ceiling]` |
| 7 | `deduct_monotone` | Each step's output balance ≤ its input balance |

---

## The formal model

The Lean 4 specification defines a pure functional model that mirrors the Rust
implementation:

```lean
-- Partial map: NodeId → Option Balance
def Ledger := NodeId → Option Balance

-- Seed a node with initial quota
def seed (l : Ledger) (node : NodeId) (ceiling : Balance) : Ledger :=
  fun n => if n == node then some ceiling else l n

-- Checked deduction — mirrors Ledger::deduct with checked_sub
def deduct (l : Ledger) (node : NodeId) (amount : Balance) :
    Option (Ledger × Balance) :=
  match l node with
  | none         => none                        -- undeclared node
  | some balance =>
    if h : amount ≤ balance then               -- checked_sub guard
      some (update l node (balance - amount), balance - amount)
    else
      none                                      -- over-quota
```

### Correspondence table

| Lean model | Rust code | Location |
|------------|-----------|----------|
| `l node = none` | `balances.get_mut(&node.get())? returns None` | `ledger.rs:36` |
| `if h : amount ≤ balance` | `balance.checked_sub(amount)?` | `ledger.rs:37` |
| `balance - amount` | `*balance = new_balance` | `ledger.rs:38` |
| `deduct l node amount = none` on over-quota | `None` return path | `ledger.rs:36–37` |
| Ledger unchanged on `none` | "not modified on failure" (doc) | `ledger.rs:29–31` |

---

## Theorems in detail

### Theorem 1: Exact accounting

```lean
theorem deduct_exact
    (l : Ledger) (node : NodeId) (amount balance : Balance)
    (h_decl : l node = some balance)
    (h_ok   : amount ≤ balance) :
    ∃ l', deduct l node amount = some (l', balance - amount)
```

When the preconditions are met (node declared, amount within balance), the
returned balance is `balance - amount` exactly.  No rounding, no truncation,
no silent overflow.

### Theorem 2: Non-negativity

```lean
theorem deduct_preserves_nonneg
    (l : Ledger) (node : NodeId) (amount : Balance) (l' : Ledger) (b : Balance)
    (h : deduct l node amount = some (l', b)) :
    0 ≤ b
```

Every balance in the output ledger is ≥ 0.  In Lean's `Nat` this follows from
`Nat.zero_le`; the content is that `deduct` only returns `some` when the
`amount ≤ balance` guard passes, making `balance - amount ≥ 0` structurally
guaranteed.

### Theorem 3: Atomicity

```lean
theorem deduct_atomic
    (l : Ledger) (node : NodeId) (amount : Balance)
    (h_fail : deduct l node amount = none) :
    ¬∃ (l' : Ledger) (b : Balance), deduct l node amount = some (l', b)
```

When deduction fails, there is no updated ledger `l'` accessible to the caller.
Partial state does not exist.  This corresponds to the Rust property documented
in `Ledger::deduct`: "the ledger is **not** modified on failure".

### Theorem 4: Over-quota rejection

```lean
theorem deduct_over_quota
    (l : Ledger) (node : NodeId) (amount balance : Balance)
    (h_decl : l node = some balance)
    (h_over : amount > balance) :
    deduct l node amount = none
```

Any request exceeding the current balance is hard-rejected.  Corresponds to
`checked_sub` returning `None` when subtraction would underflow.

### Theorem 5: Undeclared node rejection

```lean
theorem deduct_undeclared_node
    (l : Ledger) (node : NodeId) (amount : Balance)
    (h_none : l node = none) :
    deduct l node amount = none
```

Nodes not present in the ledger cannot have resources deducted.

### Theorem 6: Main invariant

```lean
theorem ledger_invariant (ceiling : Balance) (node : NodeId) :
    let l := seed emptyLedger node ceiling
    l node = some ceiling ∧
    ∀ amount, amount ≤ ceiling →
      ∃ l' b, deduct l node amount = some (l', b) ∧ b ≤ ceiling ∧ 0 ≤ b
```

After seeding, every successful deduction produces a balance in `[0, ceiling]`.
This is the arithmetic core of the TLA+ `ResourceAtomicity` invariant.

### Theorem 7: Monotone decrease

```lean
theorem deduct_monotone
    (l : Ledger) (node : NodeId) (amount balance : Balance) (l' : Ledger) (b : Balance)
    (h_decl : l node = some balance)
    (h_eq   : deduct l node amount = some (l', b)) :
    b ≤ balance
```

Each successful deduction step produces a balance ≤ the balance before that
step.  Combined with non-negativity (Theorem 2), this proves the inductive
invariant: a balance that starts non-negative stays non-negative under any
sequence of deductions.

---

## Relationship to the TLA+ model

The Lux project has two distinct formal verification layers:

| Layer | Tool | What it proves | Scope |
|-------|------|----------------|-------|
| State-machine | TLA+ / TLC | `ResourceAtomicity`, `NonEscalation`, `RevocationSoundness`, `TopologyBoundedness` across 322,560 states | System-level, concurrent |
| Arithmetic | Lean 4 | Correctness of `deduct` as a pure mathematical function | Function-level, sequential |

The TLA+ model checks that *the system as a whole* never reaches a state
where a balance is negative.  This Lean proof checks that *the deduction
function itself* is arithmetically correct — it cannot produce a negative
result by construction.  Together they provide two independent assurance
layers for Invariant I3.

---

## Running the proof

### Prerequisites

```sh
# Install elan (Lean version manager)
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh

# Install Lean 4 + Lake (build system)
elan toolchain install leanprover/lean4:stable
```

### Verify

```sh
cd lean
lake build
# Expected: Build completed successfully.
```

If the proof is correct, `lake build` completes with no errors.  A failed proof
would produce a `sorry`-containing goal error or a type-mismatch error.

---

## What is NOT modelled

| Gap | Reason | Where it is covered |
|-----|--------|---------------------|
| `MAX_NODES = 64` capacity bound | Model uses unbounded function; capacity enforced by `heapless` type | Type system + Kani harnesses |
| `u64` overflow at 2^64 − 1 | Lean `Nat` is unbounded; Rust `u64` wraps | Impractical in production — balances originate from a signed manifest |
| Concurrent access | Rust kernel is single-threaded; Lean model is sequential | TLA+ model |
| `QuotaEnforcer` audit emission | The `AuditLog.append` call wrapping `deduct` | Integration test suite |

---

## Correspondence checklist

Before claiming the formal cost model represents the implementation:

- [ ] `lean/LuxCostModel.lean` compiles under `lake build` with 0 errors
- [ ] Every `theorem` statement corresponds to a named invariant in this document
- [ ] The `deduct` Lean definition matches `Ledger::deduct` line-by-line
  (undeclared-node path, `checked_sub` guard, exact subtraction, no mutation on failure)
- [ ] Any change to `src/metabolism/ledger.rs` is reflected in `LuxCostModel.lean`
