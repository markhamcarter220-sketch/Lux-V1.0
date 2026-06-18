/-!
# Lux Kernel — Function Spec Layer: Metabolism Module

Covers every production function in:
- `src/metabolism/ledger.rs` (5 functions: `new`, `seed`, `deduct`, `balance`,
  `default`)
- `src/metabolism/quota.rs` (1 function: `QuotaEnforcer::deduct`)

Total: 6 functions specified.

This module backs **I3 (Accountable Resources)**.  `Ledger::deduct` already
has a fully *proved* (not just specified) Lean counterpart in
`lean/LuxCostModel.lean` (`deduct`, theorems 1–7) and a refinement proof in
`lean/LuxRefinement.lean` (`concreteDeductSpec`) — this file does NOT
re-prove that; it restates the contract at the spec-layer level for
uniformity with the rest of `FunctionSpecs/`, and additionally covers
`seed`, `balance`, `new`, `default`, and the `QuotaEnforcer::deduct` wrapper,
none of which have existing Lean treatment. No proofs are attempted anywhere
in this file.

## REFINEMENT_GAP entries in this file

None.  Every function in `src/metabolism/` is a pure, deterministic function
of its inputs.
-/

import FunctionSpecs.Core

open FunctionSpecs

namespace FunctionSpecs.Metabolism

-- ── Domain type mirroring `src/metabolism/ledger.rs::Ledger` ─────────────────

/-- Mirrors `src/metabolism/ledger.rs::Ledger`.  `balances` is
    `heapless::LinearMap<u32, u64, MAX_NODES>` in Rust; modelled here as
    `NodeId → Option Balance`, matching `lean/LuxCostModel.lean`'s
    `AbstractLedger.Ledger` shape exactly (this file restates rather than
    imports that definition, to keep the unproved spec layer decoupled from
    the proved one — see `FunctionSpecs.Core`'s module doc). -/
def Ledger := NodeId → Option Balance

def maxNodes : Nat := 64

-- ── `Ledger::new` (`src/metabolism/ledger.rs:24`) ─────────────────────────────

/-- Rust: `pub const fn new() -> Self`. -/
def ledgerNew : Ledger := fun _ => none

def ledgerNew_pre : Prop := True

def ledgerNew_post (l : Ledger) : Prop := ∀ n, l n = none

-- ── `Ledger::seed` (`src/metabolism/ledger.rs:42`) ────────────────────────────

/-- Rust: `pub fn seed(&mut self, node: NodeId, ceiling: Quota) -> Result<()>`.
    Post P3-Fix-1 (duplicate-seed rejection): a node that is already
    declared is rejected rather than silently overwritten — see
    `seed_duplicate_node_is_rejected` in `src/metabolism/ledger.rs`'s
    `#[cfg(test)]` module. -/
opaque seed (l : Ledger) (node : NodeId) (ceiling : Balance) (declaredCount : Nat) :
    Ledger × LuxResult Unit
-- `declaredCount` stands in for "number of currently-seeded nodes," needed
-- to express the `MAX_NODES` capacity guard; the real Rust type
-- (`heapless::LinearMap`) carries this count internally, but `Ledger` here
-- (a bare function `NodeId → Option Balance`) has no notion of size, so it
-- is threaded explicitly as an extra parameter.

def seed_pre (_l : Ledger) (_node : NodeId) (_ceiling : Balance) (declaredCount : Nat) : Prop :=
  declaredCount ≤ maxNodes

/-- If `node` is already declared (`l node ≠ none`): returns
    `LuxError.ManifestInvalid "duplicate node quota in manifest"` and `l` is
    unchanged.  Else if `declaredCount = maxNodes` (table full): returns
    `LuxError.ManifestInvalid "ledger node capacity exceeded (MAX_NODES)"`
    and `l` is unchanged.  Else: succeeds, and the returned ledger agrees
    with `l` everywhere except `node`, where it is now `some ceiling`. -/
def seed_post (l : Ledger) (node : NodeId) (ceiling : Balance) (declaredCount : Nat)
    (r : Ledger × LuxResult Unit) : Prop :=
  let (l', res) := r
  (l node ≠ none →
    res = .error (.ManifestInvalid "duplicate node quota in manifest") ∧ l' = l) ∧
  (l node = none ∧ declaredCount = maxNodes →
    res = .error (.ManifestInvalid "ledger node capacity exceeded (MAX_NODES)") ∧ l' = l) ∧
  (l node = none ∧ declaredCount < maxNodes →
    res = .ok () ∧ l' node = some ceiling ∧ ∀ n, n ≠ node → l' n = l n)

-- ── `Ledger::deduct` (`src/metabolism/ledger.rs:61`) ──────────────────────────

/-- Rust: `pub fn deduct(&mut self, node: NodeId, amount: u64) -> Option<u64>`.
    Structurally identical to `LuxCostModel.lean`'s `deduct` (proved: see
    `deduct_exact`, `deduct_atomic`, `deduct_over_quota`,
    `deduct_undeclared_node` there). Restated here, unproved, for
    `FunctionSpecs` uniformity. -/
def deduct (l : Ledger) (node : NodeId) (amount : Nat) : Option (Ledger × Nat) :=
  match l node with
  | none => none
  | some balance =>
    if amount ≤ balance then
      let newBalance := balance - amount
      some (fun n => if n = node then some newBalance else l n, newBalance)
    else none

def deduct_pre (_l : Ledger) (_node : NodeId) (_amount : Nat) : Prop := True

/-- Returns `none` if `node` is undeclared or `amount > balance`. On
    success, the new balance is exactly `balance - amount`, every other
    node's balance is untouched, and a failed deduction leaves no trace
    (no partial mutation — same atomicity property as `deduct_atomic` in
    `LuxCostModel.lean`). -/
def deduct_post (l : Ledger) (node : NodeId) (amount : Nat) (r : Option (Ledger × Nat)) : Prop :=
  (l node = none → r = none) ∧
  (∀ balance, l node = some balance → amount > balance → r = none) ∧
  (∀ balance, l node = some balance → amount ≤ balance →
    ∃ l', r = some (l', balance - amount) ∧
      l' node = some (balance - amount) ∧ ∀ n, n ≠ node → l' n = l n)

-- ── `Ledger::balance` (`src/metabolism/ledger.rs:70`) ─────────────────────────

/-- Rust: `pub fn balance(&self, node: NodeId) -> Option<u64>`. Trivial pure
    accessor. -/
def balanceOf (l : Ledger) (node : NodeId) : Option Balance := l node

def balanceOf_pre (_l : Ledger) (_node : NodeId) : Prop := True

def balanceOf_post (l : Ledger) (node : NodeId) (r : Option Balance) : Prop := r = l node

-- ── `impl Default for Ledger` (`src/metabolism/ledger.rs:76`) ────────────────

/-- Rust: `fn default() -> Self { Self::new() }`. -/
def ledgerDefault : Ledger := ledgerNew

def ledgerDefault_pre : Prop := True

def ledgerDefault_post (l : Ledger) : Prop := ∀ n, l n = none

-- ── `QuotaEnforcer::deduct` (`src/metabolism/quota.rs:25`) ────────────────────

/-- Rust: `pub fn deduct(&self, ledger: &mut Ledger, node: NodeId, amount: u64,
    resource: &'static str, audit: &mut AuditLog) -> Result<u64>`.  Wraps
    `Ledger::deduct` with audit logging and the P2 fail-closed
    audit-completeness fix.  `auditIsFull` stands in for `audit.is_full()`
    (see `FunctionSpecs.Audit` for the real `AuditLog` spec; not imported
    here to avoid a cross-module dependency — see `FunctionSpecs.Core`'s
    module doc on this convention). The **pre-check** ordering here (audit
    capacity checked *before* the ledger is touched) is the specific fix
    that distinguishes this gate from `Policy::check`/`OperationalGraph::traverse`
    — see `src/metabolism/quota.rs`'s comment on atomicity. -/
opaque quotaEnforcerDeduct (l : Ledger) (node : NodeId) (amount : Nat) (resource : String)
    (auditIsFull : Bool) : Ledger × LuxResult Nat

def quotaEnforcerDeduct_pre (_l : Ledger) (_node : NodeId) (_amount : Nat) (_resource : String)
    (_auditIsFull : Bool) : Prop := True

/-- If `auditIsFull = true`: returns `LuxError.AuditFull` and `l` is
    **unchanged** — the ledger is never touched (this is the atomicity fix;
    contrast with `Policy::check`, where the pre-existing check still runs
    before the audit-capacity gate can matter). Else: behaves exactly like
    `Ledger::deduct`, with a failed deduction mapped to
    `LuxError.QuotaExceeded resource`. -/
def quotaEnforcerDeduct_post (l : Ledger) (node : NodeId) (amount : Nat) (resource : String)
    (auditIsFull : Bool) (r : Ledger × LuxResult Nat) : Prop :=
  let (l', res) := r
  (auditIsFull → res = .error .AuditFull ∧ l' = l) ∧
  (¬ auditIsFull →
    (deduct l node amount = none → res = .error (.QuotaExceeded resource) ∧ l' = l) ∧
    (∀ l'' newBal, deduct l node amount = some (l'', newBal) →
      res = .ok newBal ∧ l' = l''))

end FunctionSpecs.Metabolism
