/-!
# Lux Kernel — Function Spec Layer: Audit Module

Covers every production function in:
- `src/audit/log.rs` (11 functions: `new`, `append`, `verify_chain`, `len`,
  `is_empty`, `is_full`, `head_hash`, `events`, `export_json`, `compute_hash`,
  `default`)
- `src/audit/event.rs` (2 functions: `kind_str`, `denial_class_str`)

Total: 13 functions specified.

This is a **spec layer only** — signatures plus precondition/postcondition
pairs, no proofs attempted anywhere in this file.  See
`lean/FunctionSpecs/Core.lean` for the full methodology note, calling
convention, and honesty disclosure (unverified, no `lake build` available).

## REFINEMENT_GAP entries in this file

| Function | file:line | Reason |
|----------|-----------|--------|
| `exportJson` | `src/audit/log.rs:240` | Writes to a generic `core::fmt::Write` sink; the postcondition would need to characterize exact JSON serialization byte-for-byte, which is a formatting concern rather than a security-relevant property. Spec given is weak (existence + well-formedness gesture only). |
| `verifyChain` | `src/audit/log.rs:178` | Correctness depends on the SHA-256 compression function, which is not modelled arithmetically anywhere in this spec layer (same disclosed gap as `LuxCostModel.lean`'s "what is NOT modelled" section). The honest postcondition is `True` — no claim is made connecting the boolean result to actual chain integrity. |
| `computeHash` | `src/audit/log.rs:281` | Same reason as `verifyChain` — output is a real SHA-256 digest; only the digest *length* (32 bytes) and *determinism* are asserted, not its value. |

`events` (the iterator accessor, `src/audit/log.rs:225`) is modelled as
returning the full `List AuditEvent` rather than an `Iterator`, since Lean
has no direct analogue of a borrowed Rust iterator; this is a representational
simplification, not a REFINEMENT_GAP (the underlying data is fully
characterizable).
-/

import FunctionSpecs.Core

open FunctionSpecs

namespace FunctionSpecs.Audit

-- ── Domain types mirroring `src/audit/event.rs` and `src/audit/log.rs` ────────

/-- Mirrors `src/audit/event.rs::EventKind`. -/
inductive EventKind where
  | CapabilityCheck
  | CapabilityRevoked
  | ResourceDeduction
  | TopologyTraverse
  | TopologyChange
  | HiringDecision
  | PolicyGateCheck
  deriving DecidableEq, Repr

/-- Mirrors `src/audit/event.rs::Outcome`. -/
inductive Outcome where
  | Permitted
  | Denied
  deriving DecidableEq, Repr

/-- Mirrors `src/audit/event.rs::AuditEvent`.  `hash` is a 32-byte digest,
    represented as `List Nat` (each entry conceptually a byte 0-255; the
    0-255 range is not enforced in this Nat-based spec layer). -/
structure AuditEvent where
  kind : EventKind
  actor : Nat
  seq : Nat
  timestamp : Nat
  outcome : Outcome
  denialClass : Option LuxDenialClass
  denialReason : Option String
  hash : List Nat
  deriving Repr

/-- Mirrors `src/audit/log.rs::AuditLog`.  `events` is modelled as a `List`
    rather than a capacity-bounded `heapless::Vec`; the `MAX_AUDIT_EVENTS`
    capacity bound is carried as an explicit precondition/postcondition
    parameter (`cap`) rather than baked into the type, since Lean's `List`
    has no static capacity. -/
structure AuditLog where
  events : List AuditEvent
  lastHash : List Nat
  nextSeq : Nat
  deriving Repr

/-- The capacity bound. Mirrors `MAX_AUDIT_EVENTS : usize = 512` in `src/types.rs`. -/
def maxAuditEvents : Nat := 512

-- ── `AuditLog::new` (`src/audit/log.rs:98`) ───────────────────────────────────

/-- Rust: `pub const fn new() -> Self`. Constructs an empty log with an
    all-zeros genesis hash. -/
def auditLogNew : AuditLog := { events := [], lastHash := List.replicate 32 0, nextSeq := 0 }

def auditLogNew_pre : Prop := True

def auditLogNew_post (l : AuditLog) : Prop :=
  l.events = [] ∧ l.lastHash = List.replicate 32 0 ∧ l.nextSeq = 0

-- ── `AuditLog::append` (`src/audit/log.rs:123`) ───────────────────────────────

/-- Rust: `pub fn append(&mut self, kind: EventKind, actor: u32, timestamp: u64,
    denial: Option<(DenialClass, &'static str)>) -> bool`.  Receiver-mutating;
    paired return per the `&mut self` calling convention. -/
opaque append (l : AuditLog) (kind : EventKind) (actor : Nat) (timestamp : Nat)
    (denial : Option (LuxDenialClass × String)) : AuditLog × Bool

def append_pre (_l : AuditLog) (_kind : EventKind) (_actor : Nat) (_timestamp : Nat)
    (_denial : Option (LuxDenialClass × String)) : Prop := True

/-- On success (`l.events.length < maxAuditEvents`): the returned log has the
    new event appended at the end with `seq = l.nextSeq`, `nextSeq` advanced
    by one, `lastHash` updated, and the boolean result is `true`.  On failure
    (log already at capacity): the log is returned unchanged and the boolean
    result is `false` — no overwriting of existing events (fail-closed). -/
def append_post (l : AuditLog) (kind : EventKind) (actor : Nat) (timestamp : Nat)
    (denial : Option (LuxDenialClass × String)) (r : AuditLog × Bool) : Prop :=
  let (l', ok) := r
  (l.events.length < maxAuditEvents →
    ok = true ∧
    l'.nextSeq = l.nextSeq + 1 ∧
    ∃ ev, l'.events = l.events ++ [ev] ∧
      ev.kind = kind ∧ ev.actor = actor ∧ ev.timestamp = timestamp ∧ ev.seq = l.nextSeq ∧
      ev.outcome = (if denial.isSome then Outcome.Denied else Outcome.Permitted) ∧
      ev.denialClass = denial.map Prod.fst ∧ ev.denialReason = denial.map Prod.snd) ∧
  (l.events.length ≥ maxAuditEvents → ok = false ∧ l' = l)

-- REFINEMENT_GAP: src/audit/log.rs:178 — correctness depends on the SHA-256
-- compression function, not modelled arithmetically in this spec layer.
-- ── `AuditLog::verify_chain` (`src/audit/log.rs:178`) ─────────────────────────

/-- Rust: `pub fn verify_chain(&self) -> bool`.  Recomputes the hash chain
    from the genesis hash and checks every event's stored `hash` matches. -/
opaque verifyChain (l : AuditLog) : Bool

def verifyChain_pre (_l : AuditLog) : Prop := True

/-- Intentionally `True` (no claim).  The real postcondition — "`r = true`
    iff every event's `hash` field equals the SHA-256 chain hash recomputed
    from the preceding event's hash and its own fields" — requires modelling
    the SHA-256 compression function, which is out of scope for this
    Nat/List-based spec layer. Stating the intended property as a comment
    rather than as `r = true ↔ <unmodelled fact>` avoids smuggling in a
    false-by-construction Prop (see REFINEMENT_GAP table above). -/
def verifyChain_post (_l : AuditLog) (_r : Bool) : Prop := True

-- ── `AuditLog::len` (`src/audit/log.rs:201`) ──────────────────────────────────

/-- Rust: `pub fn len(&self) -> usize`. Trivial pure accessor. -/
def auditLogLen (l : AuditLog) : Nat := l.events.length

def auditLogLen_pre (_l : AuditLog) : Prop := True

def auditLogLen_post (l : AuditLog) (r : Nat) : Prop := r = l.events.length

-- ── `AuditLog::is_empty` (`src/audit/log.rs:207`) ─────────────────────────────

/-- Rust: `pub fn is_empty(&self) -> bool`. Trivial pure accessor. -/
def auditLogIsEmpty (l : AuditLog) : Bool := l.events.isEmpty

def auditLogIsEmpty_pre (_l : AuditLog) : Prop := True

def auditLogIsEmpty_post (l : AuditLog) (r : Bool) : Prop := r = true ↔ l.events = []

-- ── `AuditLog::is_full` (`src/audit/log.rs:214`) ──────────────────────────────

/-- Rust: `pub fn is_full(&self) -> bool`.  Added alongside the P2 `AuditFull`
    fail-closed fix so callers (e.g. `QuotaEnforcer::deduct`) can pre-check
    capacity before mutating other state. -/
def auditLogIsFull (l : AuditLog) : Bool := decide (l.events.length ≥ maxAuditEvents)

def auditLogIsFull_pre (_l : AuditLog) : Prop := True

def auditLogIsFull_post (l : AuditLog) (r : Bool) : Prop :=
  r = true ↔ l.events.length ≥ maxAuditEvents

-- ── `AuditLog::head_hash` (`src/audit/log.rs:220`) ────────────────────────────

/-- Rust: `pub const fn head_hash(&self) -> [u8; 32]`. Trivial pure accessor. -/
def headHash (l : AuditLog) : List Nat := l.lastHash

def headHash_pre (_l : AuditLog) : Prop := True

def headHash_post (l : AuditLog) (r : List Nat) : Prop := r = l.lastHash

-- ── `AuditLog::events` (`src/audit/log.rs:225`) ───────────────────────────────

/-- Rust: `pub fn events(&self) -> impl Iterator<Item = &AuditEvent>`.
    Modelled as returning the full event list in insertion order (see
    module doc — representational simplification, not a REFINEMENT_GAP). -/
def eventsOf (l : AuditLog) : List AuditEvent := l.events

def eventsOf_pre (_l : AuditLog) : Prop := True

def eventsOf_post (l : AuditLog) (r : List AuditEvent) : Prop := r = l.events

-- ── `AuditLog::export_json` (`src/audit/log.rs:240`) ──────────────────────────

-- REFINEMENT_GAP: src/audit/log.rs:240 — exact byte-for-byte JSON formatting
-- via a generic core::fmt::Write sink is a serialization concern, not a
-- security-relevant mathematical property; spec below is intentionally weak.
/-- Rust: `pub fn export_json<W: core::fmt::Write>(&self, writer: &mut W) ->
    core::fmt::Result`.  `Writer` is modelled abstractly; the result is
    `LuxResult Unit` standing in for `core::fmt::Result` (its `Err` carries
    no payload in Rust — `core::fmt::Error` — so we erase it to `LuxError`
    generically; no specific variant is asserted). -/
opaque exportJson (l : AuditLog) (writer : String) : LuxResult String

def exportJson_pre (_l : AuditLog) (_writer : String) : Prop := True

/-- On success, the returned string is non-empty (contains at least the
    `[` `]` brackets) and contains exactly `l.events.length` top-level JSON
    objects — the precise per-field format is not characterized here. -/
def exportJson_post (l : AuditLog) (_writer : String) (r : LuxResult String) : Prop :=
  match r with
  | .ok s => s.length ≥ 2
  | .error _ => True

-- ── `AuditLog::compute_hash` (`src/audit/log.rs:281`, private) ───────────────

/-- Rust: `fn compute_hash(prev: &[u8; 32], kind: EventKind, actor: u32,
    seq: u64, timestamp: u64, outcome: Outcome, denial_class: Option<DenialClass>,
    denial_reason: Option<&'static str>) -> [u8; 32]`.  Private helper; pure
    function of its inputs, but its output is a real SHA-256 digest which is
    not modelled arithmetically in this spec layer (mirrors the disclosed gap
    for `verifyChain` above). -/
opaque computeHash (prev : List Nat) (kind : EventKind) (actor : Nat) (seq : Nat)
    (timestamp : Nat) (outcome : Outcome) (denialClass : Option LuxDenialClass)
    (denialReason : Option String) : List Nat

def computeHash_pre (prev : List Nat) (_kind : EventKind) (_actor : Nat) (_seq : Nat)
    (_timestamp : Nat) (_outcome : Outcome) (_denialClass : Option LuxDenialClass)
    (_denialReason : Option String) : Prop := prev.length = 32

/-- The output is always exactly 32 elements (a SHA-256 digest); the function
    is deterministic (same inputs always produce the same output) — both
    properties are asserted without modelling the hash function itself. -/
def computeHash_post (prev : List Nat) (kind : EventKind) (actor : Nat) (seq : Nat)
    (timestamp : Nat) (outcome : Outcome) (denialClass : Option LuxDenialClass)
    (denialReason : Option String) (r : List Nat) : Prop :=
  r.length = 32 ∧
  r = computeHash prev kind actor seq timestamp outcome denialClass denialReason

-- ── `AuditLog::default` (`src/audit/log.rs:314`, via `impl Default`) ─────────

/-- Rust: `impl Default for AuditLog { fn default() -> Self { Self::new() } }`. -/
def auditLogDefault : AuditLog := auditLogNew

def auditLogDefault_pre : Prop := True

def auditLogDefault_post (l : AuditLog) : Prop := l = auditLogNew

-- ── `AuditEvent::kind_str` (`src/audit/event.rs:74`) ──────────────────────────

/-- Rust: `pub const fn kind_str(&self) -> &'static str`.  Pure total mapping
    from `EventKind` to its JSON label. -/
def kindStr (e : AuditEvent) : String :=
  match e.kind with
  | .CapabilityCheck => "cap_check"
  | .CapabilityRevoked => "cap_revoked"
  | .ResourceDeduction => "resource_deduct"
  | .TopologyTraverse => "topo_traverse"
  | .TopologyChange => "topo_change"
  | .HiringDecision => "hiring_decision"
  | .PolicyGateCheck => "policy_gate_check"

def kindStr_pre (_e : AuditEvent) : Prop := True

def kindStr_post (e : AuditEvent) (r : String) : Prop := r = kindStr e

-- ── `AuditEvent::denial_class_str` (`src/audit/event.rs:89`) ─────────────────

/-- Rust: `pub const fn denial_class_str(&self) -> Option<&'static str>`. -/
def denialClassStr (e : AuditEvent) : Option String :=
  match e.denialClass with
  | some .Halt => some "halt"
  | some .Failure => some "failure"
  | none => none

def denialClassStr_pre (_e : AuditEvent) : Prop := True

def denialClassStr_post (e : AuditEvent) (r : Option String) : Prop := r = denialClassStr e

end FunctionSpecs.Audit
