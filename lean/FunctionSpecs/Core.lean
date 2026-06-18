/-!
# Lux Kernel — Function Spec Layer: Core Shared Types

This file is the **shared vocabulary** for the per-module spec files in
`lean/FunctionSpecs/`.  Every other file in this directory imports `Core` and
must reuse these types rather than redefining its own `Error`, `NodeId`, etc.

## Scope and honesty disclosure

This whole `FunctionSpecs` tree is a **spec layer only**: for every production
Rust function in `src/`, we record a Lean signature plus a precondition and a
postcondition.  **No proofs are attempted anywhere in this tree.**  Function
bodies are declared `opaque` (uninterpreted) unless the Rust function is a
trivial one-line pure accessor, in which case a direct `def` is given for
readability — but even then, no theorem links the `def` to its `_pre`/`_post`
companions.  This is intentionally a lighter, less rigorous layer than
`lean/Refinement.lean` (which states real obligations, even if `sorry`d) and
`lean/LuxRefinement.lean`/`lean/LuxCapabilityBridge.lean` (which contain real
proved theorems).  Do not confuse the three.

None of the files in this tree have been checked with `lake build` — the Lean
4 toolchain is not available in this environment (see `docs/REFINEMENT_GAPS.md`
for the same disclosure made about `Refinement.lean`).  Treat every signature,
precondition, and postcondition below as an unverified human/AI transcription
of the Rust source, not as a mechanically-checked fact.

## Calling convention used throughout `FunctionSpecs/`

- A free function or associated function (`Foo::bar(args) -> T`) becomes
  `bar : Args -> T`.
- A `&self` method (`fn bar(&self, args) -> T`) becomes `bar : Receiver -> Args -> T`.
- A `&mut self` method (`fn bar(&mut self, args) -> T`) becomes
  `bar : Receiver -> Args -> Receiver × T`, even when the Rust return type is
  `()` (i.e. `T := Unit`), so that every mutator has a uniform paired-return
  shape and the postcondition can talk about the new receiver state.
- A constructor (`fn new(args) -> Self`) becomes `new : Args -> Self`.
- `Result<T, Error>` becomes `LuxResult T`.
- `Option<T>` becomes `Option T` (Lean's stdlib type, used as-is).
- `&'static str` becomes `String`.
- Rust integer types (`u32`, `u64`, `usize`) become `Nat` — unbounded, as in
  the existing `LuxCostModel.lean` (`abbrev Balance := Nat` etc.).  Wraparound
  / bit-width truncation is *not* modelled in this spec layer; this mirrors
  the documented gap in `LuxCostModel.lean`'s "What is NOT modelled" section.

## Reused vs. new types

`NodeId`, `Balance` are reused verbatim from `LuxCostModel.lean`'s top-level
namespace (this file does not import `LuxCostModel` to avoid coupling the
unproved spec layer to the proved one; the abbreviations are simply restated
here with the same names and meaning, kept in sync by convention).
-/

namespace FunctionSpecs

-- ── Domain primitives (mirrors `src/types.rs`) ────────────────────────────────

/-- Corresponds to `NodeId = NonZeroU32` in `src/types.rs`.  Modelled as `Nat`;
    the non-zero constraint is a deployment invariant not enforced here, same
    convention as `LuxCostModel.lean`. -/
abbrev NodeId := Nat

/-- Corresponds to `Generation(pub u64)` in `src/types.rs`. -/
abbrev GenerationNat := Nat

/-- Corresponds to `Quota(u64)` in `src/types.rs` — a private-field wrapper
    around a ceiling value, exposed via `new`/`get`/`checked_sub`. -/
structure Quota where
  ceiling : Nat

/-- Corresponds to `u64` resource balances in `src/metabolism/`. -/
abbrev Balance := Nat

-- ── Error taxonomy (mirrors `src/error.rs::Error`) ────────────────────────────

/-- Mirrors `src/error.rs::Error`.  Field shapes:
    - `&'static str` fields become `String`.
    - `u32` fields (`TopologyViolation.src/dst`) become `Nat`.
    `#[non_exhaustive]` in Rust is not representable in a Lean `inductive`;
    this type is treated as closed for the purposes of this spec layer. -/
inductive LuxError where
  | CapabilityDenied (reason : String)
  | QuotaExceeded (resource : String)
  | TopologyViolation (src dst : Nat)
  | ManifestInvalid (detail : String)
  | SchedulerInvariant (detail : String)
  | UndefinedState (context : String)
  | WasmFault (detail : String)
  | AuditFull
  deriving DecidableEq, Repr

/-- Mirrors `src/error.rs::DenialClass`. -/
inductive LuxDenialClass where
  | Halt
  | Failure
  deriving DecidableEq, Repr

/-- Mirrors `pub type Result<T> = core::result::Result<T, Error>;` in `src/error.rs`. -/
abbrev LuxResult (T : Type) := Except LuxError T

-- ── `src/error.rs` impl block ──────────────────────────────────────────────────

/-- Rust: `impl Error { pub const fn denial_reason_str(&self) -> &'static str }`
    (`src/error.rs:133`). -/
opaque denialReasonStr (e : LuxError) : String

def denialReasonStr_pre (_e : LuxError) : Prop := True

/-- Every variant maps to a specific, non-empty static string; the mapping is
    a total pattern match in the Rust source (no wildcard arm). -/
def denialReasonStr_post (e : LuxError) (r : String) : Prop :=
  match e with
  | .CapabilityDenied reason => r = reason
  | .QuotaExceeded resource => r = resource
  | .TopologyViolation _ _ => r = "edge not in boot manifest"
  | .ManifestInvalid detail => r = detail
  | .SchedulerInvariant detail => r = detail
  | .WasmFault detail => r = detail
  | .UndefinedState context => r = context
  | .AuditFull => r = "audit log full; rotate to reclaim"

/-- Rust: `impl Error { pub const fn denial_class(&self) -> DenialClass }`
    (`src/error.rs:152`). -/
opaque denialClass (e : LuxError) : LuxDenialClass

def denialClass_pre (_e : LuxError) : Prop := True

/-- Every variant is assigned to exactly one class (the module doc on
    `src/error.rs` states this is a closed, non-ambiguous partition). -/
def denialClass_post (e : LuxError) (c : LuxDenialClass) : Prop :=
  match e with
  | .CapabilityDenied _ | .TopologyViolation _ _ | .ManifestInvalid _
  | .UndefinedState _ | .WasmFault _ | .AuditFull => c = .Halt
  | .QuotaExceeded _ | .SchedulerInvariant _ => c = .Failure

-- ── `src/types.rs::Quota` impl block ──────────────────────────────────────────

/-- Rust: `impl Quota { pub const fn new(ceiling: u64) -> Self }`
    (`src/types.rs:46`).  Trivial pure constructor — given directly as a
    `def` rather than `opaque`, per the "trivial pure function" exception in
    the calling convention above. -/
def quotaNew (ceiling : Nat) : Quota := { ceiling := ceiling }

def quotaNew_pre (_ceiling : Nat) : Prop := True

def quotaNew_post (ceiling : Nat) (q : Quota) : Prop := q.ceiling = ceiling

/-- Rust: `impl Quota { pub const fn get(self) -> u64 }` (`src/types.rs:52`).
    Trivial pure accessor. -/
def quotaGet (q : Quota) : Nat := q.ceiling

def quotaGet_pre (_q : Quota) : Prop := True

def quotaGet_post (q : Quota) (r : Nat) : Prop := r = q.ceiling

/-- Rust: `impl Quota { pub fn checked_sub(self, amount: u64) -> Option<Self> }`
    (`src/types.rs:58`).  Not given a direct `def` despite being simple,
    because the underlying `u64::checked_sub` wraparound semantics are
    explicitly out of scope for this `Nat`-based spec layer (see module doc);
    kept `opaque` to avoid silently asserting unbounded-`Nat` semantics as a
    fact about the `u64` original. -/
opaque quotaCheckedSub (q : Quota) (amount : Nat) : Option Quota

def quotaCheckedSub_pre (_q : Quota) (_amount : Nat) : Prop := True

def quotaCheckedSub_post (q : Quota) (amount : Nat) (r : Option Quota) : Prop :=
  (amount > q.ceiling → r = none) ∧
  (amount ≤ q.ceiling → ∃ q', r = some q' ∧ q'.ceiling = q.ceiling - amount)

end FunctionSpecs
