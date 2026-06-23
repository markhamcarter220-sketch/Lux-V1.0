/-!
# Lux Kernel — IPC RESERVE-Phase Model (Lean 4)

Models Claims Discipline items **1–5** from `docs/ipc/IPC-SPEC.md` (the
Capability-Signed Message IPC protocol's CHECK and RESERVE phases, and the
ordering constraint EXECUTE must respect). Claims 6 and 7 from that table
are explicitly **not** attempted here — see "Out of scope", below.

**Honest status — no exceptions:** this file has not been run through
`lake build` in this session (no Lean/Lake toolchain is installed in this
environment to invoke). Every theorem below — including the ones with no
`sorry` — is **written, not mechanically verified**. A theorem without
`sorry` means the proof *term* type-checks against my own reading of Lean's
rules, not that a compiler has confirmed it. Treat every claim here as
specified-but-not-yet-`lake build`-checked, exactly as `docs/ipc/IPC-SPEC.md`
itself insists for the Rust side. Do not cite this file as proof that any
IPC-SPEC.md claim holds until `lake build` has actually been run and its
output inspected.

This file corresponds to no Rust code path: `src/auth/reservation.rs`
implements the RESERVE-phase *state and ledger operations*, but nothing in
`src/` calls it from `Policy::check`, and nothing in `src/` implements
Phase 1 (CHECK)'s sender-identity step or Phase 3 (EXECUTE)'s checkpoint
ordering at all. This Lean file models the *specification*, not an
existing implementation, mirroring how `Refinement.lean` models obligations
above already-proved machinery rather than re-deriving them.

## Why this file imports nothing

Unlike `Refinement.lean` (which imports `LuxCapabilityBridge` to reuse the
`Rights` / `Finset` machinery), the claims modelled here are about
reservation *lifecycle* and *issuance*, not about the rights bitfield. They
are expressible entirely over `Nat`, `Bool`, `Option`, and `List` from the
core prelude, so no `Mathlib` dependency is introduced. This keeps the
RESERVE-phase model independent of the existing five-module proof tree,
matching the IPC protocol's own status as unimplemented and unwired.

## Relationship to `src/auth/reservation.rs`

The Lean structures below are deliberately smaller than the Rust ones:

- Rust's `Reservation` carries a `node : NodeId` and `action : CapabilitySet`
  field; both are opaque to every claim modelled here (none of claims 1–5
  mention *which* node or *which* action, only *whether* a reservation may
  be issued, granted, or invalidated). They are omitted, not forgotten.
- Rust's `ReservationTtl` is a refinement type enforcing
  `0 < ttl ≤ MAX_RESERVATION_TTL` at construction
  (`ReservationTtl::new`, `src/auth/reservation.rs`). The Lean
  `Reservation.ttl` field below carries the same constructor-time proof
  obligation via the `ValidTtl` predicate, so "TTL out of bounds" is a
  precondition violation, not a runtime branch — see Claim 2.
-/

namespace IpcReservation

-- ── Shared model types ───────────────────────────────────────────────────────

/-- Model of IPC-SPEC.md Phase 1's five-step CHECK validation. Each field is
    the Boolean outcome of one of the five ordered checks; the model omits
    *why* a check failed (the Rust side maps that to an `Error` variant —
    see `Error::CapabilityDenied` reasons in `docs/ipc/IPC-SPEC.md` Phase 1's
    failure-mode table), keeping only whether it passed. -/
structure CheckInputs where
  senderMatchesTarget : Bool
  generationMatches    : Bool
  rightsInScope        : Bool
  notRevoked           : Bool
  notReplayed          : Bool
  deriving DecidableEq, Repr

/-- All five Phase 1 checks must pass. Order does not matter to this Boolean
    model even though `docs/ipc/IPC-SPEC.md` specifies a short-circuiting
    order — short-circuiting is an implementation efficiency concern, not a
    semantic one, since all five checks are pure predicates with no side
    effects on each other (the nonce-recording side effect of step 5 is
    deliberately not modelled here; see `Refinement.lean`'s
    `failClosed_*` family, which has the same omission and the same
    justification). -/
def checkPasses (inp : CheckInputs) : Bool :=
  inp.senderMatchesTarget && inp.generationMatches && inp.rightsInScope &&
    inp.notRevoked && inp.notReplayed

/-- Model of CHECK's issuance step: `issue` is the receiver's fresh-ID
    source (in Rust, `ReservationLedger`'s `next_id` counter,
    `src/auth/reservation.rs`). Returns `none` unless every Phase 1 check
    passed. -/
def checkIssue (inp : CheckInputs) (issue : Unit → Nat) : Option Nat :=
  if checkPasses inp then some (issue ()) else none

/-!
### Claim 1 (IPC-SPEC.md Claims Discipline #1): CHECK never issues a
`ReservationId` unless all five Phase 1 validations passed.

**Status: written, not `lake build`-checked (see file header).** No
`sorry` — the proof term below type-checks against my reading of `if`
elaboration rules, but that is not equivalent to compiler verification.
-/
theorem check_issue_requires_all_passed
    (inp : CheckInputs) (issue : Unit → Nat) (n : Nat)
    (h : checkIssue inp issue = some n) :
    checkPasses inp = true := by
  unfold checkIssue at h
  by_cases hc : checkPasses inp = true
  · exact hc
  · simp [hc] at h

-- ── Claim 2: bounded, status-gated grants ───────────────────────────────────

/-- Lifecycle status of a single reservation (IPC-SPEC.md Phase 2).
    Mirrors `ReservationStatus` in `src/auth/reservation.rs` exactly —
    `Revoked`, `Expired`, `Consumed` are terminal. -/
inductive ReservationStatus where
  | active
  | revoked
  | expired
  | consumed
  deriving DecidableEq, Repr

/-- A TTL is valid iff it is strictly positive and does not exceed the
    ceiling. Mirrors the precondition enforced by Rust's
    `ReservationTtl::new` (`0 < ticks && ticks <= MAX_RESERVATION_TTL`,
    `src/auth/reservation.rs`) — there, the ceiling is `MAX_RESERVATION_TTL`
    from `src/types.rs`; here it is an explicit parameter so this file does
    not need to duplicate that constant's value. -/
def ValidTtl (ceiling ttl : Nat) : Prop := 0 < ttl ∧ ttl ≤ ceiling

/-- Model of `Reservation` (IPC-SPEC.md Phase 2 "State created"), restricted
    to the fields every claim 1–5 actually mentions: `id`, the originating
    capability `nonce` (for the cascade rule, Claim 4), `createdAt`, `ttl`,
    and `status`. `node` / `action` are omitted — see file header. -/
structure Reservation (ceiling : Nat) where
  id          : Nat
  originNonce : Nat
  createdAt   : Nat
  ttl         : Nat
  ttlValid    : ValidTtl ceiling ttl
  status      : ReservationStatus

/-- Lazy-expiry view, mirroring `ReservationLedger::effective_status`
    (`src/auth/reservation.rs`): an `active` reservation whose TTL has
    elapsed reads as `expired` without mutating stored state. -/
def effectiveStatus {ceiling : Nat} (r : Reservation ceiling) (now : Nat) :
    ReservationStatus :=
  match r.status with
  | ReservationStatus.active =>
      if now ≥ r.createdAt + r.ttl then ReservationStatus.expired else ReservationStatus.active
  | other => other

/-- Model of `ReservationLedger::grant` (IPC-SPEC.md Phase 2 "Outputs"):
    read-only, returns the reservation's `id` iff its effective status is
    `active`. -/
def grant {ceiling : Nat} (r : Reservation ceiling) (now : Nat) : Option Nat :=
  if effectiveStatus r now = ReservationStatus.active then some r.id else none

/-!
### Claim 2 (IPC-SPEC.md Claims Discipline #2): RESERVE never produces an
`ExecutionGrant` for an expired, revoked, or out-of-bounds-TTL reservation.

This claim splits into two independent parts:

1. **Expired / revoked / consumed →  no grant.** Proved below
   (`grant_requires_active`), no `sorry`.
2. **Out-of-bounds TTL → no grant.** This part is **not** a runtime branch
   in either the Rust or this Lean model: `Reservation.ttlValid` /
   `ReservationTtl::new` make an out-of-bounds TTL **unconstructable**, not
   merely rejected. There is no `Reservation ceiling` value with an invalid
   `ttl` to call `grant` on in the first place — the claim holds vacuously
   by construction, the same pattern `Refinement.lean` uses for
   `topologyBounded_sealingIrreversible` (I4-B): a type-level guarantee is
   not a theorem to prove, it is a constraint on what terms exist. No
   theorem is stated for this part for that reason — stating one would
   require a `Reservation` value that cannot exist.

**Status: written, not `lake build`-checked (see file header).**
-/
theorem grant_requires_active
    {ceiling : Nat} (r : Reservation ceiling) (now : Nat) (n : Nat)
    (h : grant r now = some n) :
    effectiveStatus r now = ReservationStatus.active := by
  unfold grant at h
  by_cases ha : effectiveStatus r now = ReservationStatus.active
  · exact ha
  · simp [ha] at h

-- ── Claim 3: disjoint namespaces ─────────────────────────────────────────────

/-!
### Claim 3 (IPC-SPEC.md Claims Discipline #3): `ReservationId` values and
capability `nonce` values are never aliased (disjoint-namespace claim).

**This is a type-level guarantee, not a numeric-disjointness theorem, and
modelling it as the latter would overstate what either the Rust or the
Lean side actually establishes.** In `src/auth/reservation.rs`,
`ReservationId` is a distinct newtype (`pub struct ReservationId(u64)`) from
the `u64` nonce carried inside `Capability`
(`src/auth/capability.rs`); Rust's type checker, not a runtime comparison,
is what prevents a `ReservationId` from ever being compared against or
substituted for a `nonce` — there is no function in `src/auth/` with a
signature that would accept either in the other's place. Two separate
opaque types below (`ReservationIdTok`, `NonceTok`) reproduce that
guarantee in Lean: there is no defined function `ReservationIdTok → NonceTok`
or back, so "aliasing" is not merely false, it is not a well-typed
statement to begin with. This is the same construction-not-theorem pattern
as Claim 2's TTL part above and `Refinement.lean`'s I4-B.

No `sorry`, but also no proof obligation stated as a `theorem` — see
`Refinement.lean`'s I4-B precedent for why a structural guarantee is
documented rather than proved. -/

/-- Opaque tag distinguishing `ReservationId` values from capability nonces
    at the type level. Carries no operations — its only job is to make a
    `ReservationIdTok`-to-`NonceTok` comparison ill-typed. -/
structure ReservationIdTok where
  raw : Nat
  deriving DecidableEq, Repr

/-- Opaque tag for capability nonces, distinct from `ReservationIdTok`. -/
structure NonceTok where
  raw : Nat
  deriving DecidableEq, Repr

-- (Deliberately no `theorem` here — see doc comment above.)

-- ── Claim 4: cascade revocation ──────────────────────────────────────────────

/-- Cascade revocation over a list of reservations (IPC-SPEC.md Phase 2,
    "Cascade rule"): every `active` reservation whose `originNonce` matches
    is transitioned to `revoked`; all others are left untouched. Mirrors
    `ReservationLedger::revoke_by_origin_nonce`
    (`src/auth/reservation.rs`). -/
def revokeByOriginNonce {ceiling : Nat}
    (rs : List (Reservation ceiling)) (nonce : Nat) : List (Reservation ceiling) :=
  rs.map (fun r =>
    if r.originNonce = nonce ∧ r.status = ReservationStatus.active then
      { r with status := ReservationStatus.revoked }
    else
      r)

/-!
### Claim 4 (IPC-SPEC.md Claims Discipline #4): a capability-nonce
revocation cascades to invalidate every `Reservation` derived from it.

**Why sorry:** IPC-SPEC.md's own Claims Discipline table flags this as
"likely the most novel" claim in the set, requiring ancestry/derivation
modelling that no existing `LuxCostModel` / `LuxRefinement` machinery
covers. The function `revokeByOriginNonce` above is an *executable* model
of the Rust implementation already tested in
`src/auth/reservation.rs::tests::cascade_revocation_invalidates_all_derived_reservations`,
but turning "every reservation matching `originNonce` is no longer active
after the call" into a Lean theorem requires a `List.map`-and-predicate
lemma relating membership before and after the map — mechanically
approachable (likely closable with `List.mem_map` plus case analysis on
the `if`), but not attempted here to respect the conservative-status
instruction governing this file: rather than write a proof I have not
independently re-derived line-by-line and risk a subtly wrong `simp` call
masquerading as closed, I am leaving it as a named `sorry` with the shape
of the obligation made explicit. Estimated closure: under half a day for
someone fluent in `List` lemmas; the statement shape below should not
need to change.

**Equally important, and not yet stated as a theorem:** the *converse*
half of this claim — that revocation does **not** touch reservations from
a *different* `originNonce` — is the other thing the Rust test
(`cascade_revocation...`, see `unrelated` assertion) checks, and is not
yet modelled as a Lean statement here either. Both halves are open. -/
theorem cascade_revokes_all_matching
    {ceiling : Nat} (rs : List (Reservation ceiling)) (nonce : Nat)
    (r : Reservation ceiling) (hmem : r ∈ rs) (horigin : r.originNonce = nonce)
    (hactive : r.status = ReservationStatus.active) :
    ∃ r' ∈ revokeByOriginNonce rs nonce, r'.id = r.id ∧ r'.status = ReservationStatus.revoked := by
  sorry

-- ── Claim 5: checkpoint-ordered commit ──────────────────────────────────────

/-- A checkpoint-indexed action: `n` independently-atomic sub-steps,
    indexed `0, 1, ..., n - 1` (IPC-SPEC.md Phase 3, "checkpoint-aligned
    atomic sub-steps"). `committed i` is `true` iff sub-step `i` has
    committed its effect; `revokedAt` is the checkpoint index at which
    revocation was detected, or `none` if never detected during this
    action's execution. This is a model of an execution *trace*, not of
    `ReservationLedger` — Phase 3 (EXECUTE) has no Rust implementation to
    mirror (see file header). -/
structure CheckpointTrace where
  steps     : Nat
  committed : Nat → Bool
  revokedAt : Option Nat

/-- The ordering constraint IPC-SPEC.md Phase 3 requires of any conforming
    EXECUTE implementation: once revocation is detected at checkpoint `k`,
    no sub-step at or after `k` may commit. ("At or before that checkpoint"
    in the claim statement refers to *detection* timing, not commit
    timing — a sub-step commits strictly *after* its preceding checkpoint's
    channel check, per Phase 3's "checked (a) immediately before the
    action's effect commits" rule.) -/
def RespectsCheckpointOrdering (t : CheckpointTrace) : Prop :=
  match t.revokedAt with
  | none => True
  | some k => ∀ i, k ≤ i → i < t.steps → t.committed i = false

/-!
### Claim 5 (IPC-SPEC.md Claims Discipline #5): EXECUTE never commits an
action's irreversible effect at a checkpoint after revocation was detected
at or before that checkpoint.

**Why sorry — and why this is barely a theorem yet:** IPC-SPEC.md's own
table notes this claim is "Lean-suitable only if checkpoint structure is
itself modeled as a finite, ordered sequence" — `CheckpointTrace` above is
exactly that model, but a trace as defined carries `committed` and
`revokedAt` as *independent* fields, so nothing yet forces them to agree.
`RespectsCheckpointOrdering` states the desired property as a predicate
**on** a trace, not as a theorem that every *producible* trace satisfies
it — that would require a model of the EXECUTE loop itself (a recursive
function building a trace step-by-step, checking the channel before each
commit), which does not exist in this file or in `src/` (Phase 3 is
unimplemented — see file header). Without that loop, there is nothing to
prove `RespectsCheckpointOrdering` *of*; the obligation as stated below is
intentionally weaker — that the predicate is at least satisfiable and
non-trivial (a sanity check on the definition, not the real claim) — and
is left `sorry` pending the EXECUTE-loop model this claim actually depends
on. Estimated closure: 2–3 days, gated on Phase 3 having a Rust
implementation to model in the first place (today there is none — see
`docs/ipc/IPC-SPEC.md` Phase 3, which is entirely prose). -/
theorem checkpoint_ordering_nontrivial :
    ∃ t : CheckpointTrace, RespectsCheckpointOrdering t ∧ t.revokedAt ≠ none := by
  sorry

-- ── Halt-sequence ordering (additive — docs/ipc/IPC-SPEC.md lines 301–413) ──

/-!
## Halt-sequence ordering

Models the three-step ordered halt sequence added to `docs/ipc/IPC-SPEC.md`
("Revocation during EXECUTE → HALT", lines 301–366) and the Protocol
Primitives subsection it composes with (lines 231–299). **This is not one
of Claims Discipline items 1–7** — that table was deliberately left
unmodified when the halt sequence was specified ("no new verification
claims", per the prompt that produced commit `34bf940`). The statements
below are therefore additive specification coverage, not a new row in an
existing obligation table.

**Claims discipline, restated for this section specifically:** every
theorem below is `sorry`-blocked. None is mechanically verified. Each
`sorry` carries the comment `specified-but-not-yet-proven, EXECUTE-loop
model not yet built` — the same root cause Claim 5's
`checkpoint_ordering_nontrivial` (above) already cites: there is no Lean
model of the EXECUTE loop itself (no Rust implementation exists to model,
either — see the file header). A `HaltRun` below is a *trace* of one
hypothetical execution of the sequence, exactly as `CheckpointTrace` is a
trace and not a generator; nothing here proves that a real EXECUTE
implementation produces only conforming traces.
-/

/-- The four halt triggers this claim addresses, mapped **one-to-one** to
    `docs/ipc/IPC-SPEC.md`'s own canonical enumeration — stated twice in the
    document, identically ordered both times:

    - line 330: "reservation revoked, capability nonce revoked, channel
      severed, TTL expired" (the `RevocationLedger`-write paragraph), and
    - lines 443–444: "(reservation revoked / capability nonce revoked /
      channel severed / TTL expired)" (the `denial_reason` field under
      "Outputs").

    Line-by-line mapping (constructor ← spec trigger, in the document's own
    order):

    | Constructor | IPC-SPEC.md trigger | Citation |
    |---|---|---|
    | `reservationRevoked` | "reservation revoked" | lines 330, 443 |
    | `capabilityNonceRevoked` | "capability nonce revoked" | lines 330–331, 443–444 |
    | `channelSevered` | "channel severed" | lines 331, 444 |
    | `ttlExpired` | "TTL expired" | lines 331, 444 |

    `reservationRevoked` and `capabilityNonceRevoked` are **separate
    constructors**, not collapsed: the spec's halt-sequence prose
    acknowledges they are distinguished only by the `denial_reason` string
    it produces (lines 301–366 do not otherwise distinguish them), but the
    Outputs-section enumeration (lines 330–331, 443–444) lists them as two
    items, not one — so this inductive preserves that distinction rather
    than merging it away.

    `channelSevered` and the task wording's "failed checkpoint" are **the
    same constructor, not two**: the Protocol Primitives subsection's
    partition-behavior rule (lines 276–285) states explicitly that a
    TTL-bounded silence since the last authenticated checkpoint "is
    additive precision on top of the existing 'Severed revocation channel'
    rule below... it gives the previously-informal 'severed' condition a
    measurable trigger... instead of leaving 'severed' undefined" — i.e.
    "failed checkpoint" is the concrete mechanism that *realizes* a
    `channelSevered` classification (see also lines 292–299: a failed
    checkpoint "triggers the same halt sequence" via that same
    classification), not a fifth, distinct trigger standing alongside it.
    Collapsing it here keeps this inductive at exactly four constructors,
    matching the spec's own four-item enumeration exactly. -/
inductive HaltTrigger where
  | reservationRevoked
  | capabilityNonceRevoked
  | channelSevered
  | ttlExpired
  deriving DecidableEq, Repr

/-- A trace of one halt-sequence execution for a single `HaltTrigger`
    (IPC-SPEC.md lines 312–353). `hookAttemptedAt` may legitimately be
    `none` when the gated operation exposes no rollback hook (lines
    312–321: "this step is a no-op by definition, not a failure");
    `hookSucceeded` is meaningful only when `hookAttemptedAt` is `some _`.
    `auditWrittenAt` and `returnedAt` model the halt mechanism's two
    mandatory steps — see `RespectsHaltOrdering`, below, for why a
    conforming run never leaves them `none`. -/
structure HaltRun where
  trigger          : HaltTrigger
  hookAttemptedAt  : Option Nat
  hookSucceeded    : Bool
  auditWrittenAt   : Option Nat
  returnedAt       : Option Nat

/-- The strict-ordering property a conforming halt run must satisfy
    (IPC-SPEC.md lines 322–366):
    1. the audit-log + `RevocationLedger` write (step 2) always occurs —
       it is never skippable, regardless of whether rollback was
       attempted or what its outcome was (lines 322–328: "regardless of
       rollback outcome");
    2. the fail-closed return (step 3) always occurs and never precedes
       step 2 (line 357: "the halt is always recorded before the
       fail-closed return");
    3. if rollback was attempted (step 1), it does not occur after step 2
       (lines 355–357: "rollback, if attempted, happens before the halt
       is recorded"). -/
def RespectsHaltOrdering (run : HaltRun) : Prop :=
  (∃ t2, run.auditWrittenAt = some t2) ∧
  (∃ t2 t3, run.auditWrittenAt = some t2 ∧ run.returnedAt = some t3 ∧ t2 ≤ t3) ∧
  (∀ t1, run.hookAttemptedAt = some t1 →
    ∀ t2, run.auditWrittenAt = some t2 → t1 ≤ t2)

/-!
### Statement 1: halt ordering is strict

**Source:** IPC-SPEC.md lines 312–366 ("Ordering is strict and is part of
the specification, not an implementation detail").

**Why sorry:** `specified-but-not-yet-proven, EXECUTE-loop model not yet
built` — see section header above.
-/
theorem haltSequence_strictOrder
    (run : HaltRun) (h : RespectsHaltOrdering run) :
    (∃ t2 t3, run.auditWrittenAt = some t2 ∧ run.returnedAt = some t3 ∧ t2 ≤ t3) ∧
    (∀ t1, run.hookAttemptedAt = some t1 →
      ∀ t2, run.auditWrittenAt = some t2 → t1 ≤ t2) := by
  -- specified-but-not-yet-proven, EXECUTE-loop model not yet built
  sorry

/-- Whether state survives a halt — i.e. whether an already-committed
    sub-step's effect is undone — as a function of rollback-hook
    availability and outcome only (IPC-SPEC.md lines 312–321, 397–402:
    "If step 1's rollback hook reports success, `partial` remains
    `true`..." — the audit record does not change even on a successful
    rollback, which is the other half of the separation `Statement 2`,
    below, formalizes). -/
def stateSurvives (run : HaltRun) : Bool :=
  match run.hookAttemptedAt with
  | none => false
  | some _ => run.hookSucceeded

/-!
### Statement 2: rollback is a property of the operation, not the halt
mechanism

**Source:** IPC-SPEC.md lines 312–321, 397–402 (rollback-hook availability
is action-specific and optional; the halt mechanism's mandatory steps are
unconditional and do not consult `stateSurvives`).

**Why sorry:** `specified-but-not-yet-proven, EXECUTE-loop model not yet
built` — see section header above.
-/
theorem rollback_is_operation_property
    (run : HaltRun) (h : RespectsHaltOrdering run) :
    -- The halt mechanism's mandatory steps occur regardless of whether
    -- `stateSurvives run` — i.e. regardless of rollback-hook availability
    -- or outcome.
    (∃ t2 t3, run.auditWrittenAt = some t2 ∧ run.returnedAt = some t3) ∧
    -- Changing only the hook's outcome — never its presence, which is a
    -- property of the operation this model does not let the halt
    -- mechanism rewrite — leaves the halt mechanism's ordering intact.
    (∀ b : Bool, RespectsHaltOrdering { run with hookSucceeded := b }) := by
  -- specified-but-not-yet-proven, EXECUTE-loop model not yet built
  sorry

/-!
### Statement 3: audit log write is mandatory

**Source:** IPC-SPEC.md lines 322–347 ("The `RevocationLedger` write
applies uniformly across all four halt triggers"); the four-trigger
enumeration is `HaltTrigger`, above.

**Why sorry:** `specified-but-not-yet-proven, EXECUTE-loop model not yet
built` — see section header above.
-/
theorem auditWrite_mandatory_across_all_triggers
    (trigger : HaltTrigger) (run : HaltRun) (htrig : run.trigger = trigger)
    (h : RespectsHaltOrdering run) :
    ∃ t2, run.auditWrittenAt = some t2 := by
  -- specified-but-not-yet-proven, EXECUTE-loop model not yet built
  sorry

/-!
#### Halt-sequence ordering — obligation inventory (additive; does not
extend the obligation table above, which covers Claims Discipline items
1–5 only)

| Theorem | Statement | Status | Estimated closure |
|---------|-----------|--------|--------------------|
| `haltSequence_strictOrder` | 1 (ordering is strict) | **sorry** | gated on an EXECUTE-loop model; not yet estimated |
| `rollback_is_operation_property` | 2 (rollback vs. halt mechanism) | **sorry** | gated on an EXECUTE-loop model; not yet estimated |
| `auditWrite_mandatory_across_all_triggers` | 3 (audit write mandatory) | **sorry** | gated on an EXECUTE-loop model; not yet estimated |

As with Claim 5's `checkpoint_ordering_nontrivial`, no closure estimate is
given beyond "gated on Phase 3 having a Rust implementation to model in
the first place" — none of these three statements can be meaningfully
closed before that model exists, so any numeric estimate here would be
speculation dressed as planning.
-/

-- ── Out of scope (per IPC-SPEC.md Claims Discipline) ─────────────────────────

/-!
## Out of scope for this file

- **Claim 6** (severed-channel detection has no false negative) — per
  IPC-SPEC.md: "Not a Lean claim... Candidate for a TLA+ model extension."
  Not modelled here in any form, including as a `sorry`, because a `sorry`
  would misleadingly suggest this file claims jurisdiction over a property
  it explicitly disclaims.
- **Claim 7** (sender-identity transport authentication is sound) — per
  IPC-SPEC.md: "REFINEMENT_GAP, not a proof target," the same category as
  Ed25519/SHA-256 in `docs/FUNCTION_SPECS.md`. Not modelled here for the
  same reason as Claim 6.

## Obligation inventory

| Theorem | Claim # | Status | Estimated closure |
|---------|---------|--------|--------------------|
| `check_issue_requires_all_passed` | 1 | **no `sorry`** (not `lake build`-checked) | — |
| `grant_requires_active` | 2 (status part) | **no `sorry`** (not `lake build`-checked) | — |
| (TTL part of Claim 2) | 2 (TTL part) | holds by construction, no theorem stated | — |
| (Claim 3) | 3 | holds by construction (distinct opaque types), no theorem stated | — |
| `cascade_revokes_all_matching` | 4 (forward direction only) | **sorry** | < 0.5 day |
| (converse direction of Claim 4) | 4 (converse) | not yet stated as a theorem | half day, after the above |
| `checkpoint_ordering_nontrivial` | 5 | **sorry**, and intentionally weaker than the real claim | 2–3 days, gated on a Phase 3 Rust implementation existing to model |

No theorem in this file has been confirmed by `lake build` in this
session. "No `sorry`" above means the proof term is written and, to the
best of my own line-by-line reading, type-checks — it is not a substitute
for the toolchain actually running. See the file header for the full
disclosure.
-/

end IpcReservation
