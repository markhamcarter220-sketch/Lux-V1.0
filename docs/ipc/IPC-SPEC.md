# IPC-SPEC — Capability-Signed Message Protocol

**Status: SPECIFICATION ONLY. No implementation exists.** No Rust code, no
Lean code, no wire format has been built, tested, kani-proven, or
`lake build`-checked against anything in this document. Every "must" /
"shall" below is a requirement on a future implementation, not a
description of present kernel behavior. Treat every claim in this document
as **specified-but-not-yet-proven** unless explicitly marked otherwise (see
**Claims Discipline**, below).

This document formalizes the three-phase CHECK → RESERVE → EXECUTE protocol
for transmitting a capability-gated request across an IPC boundary (a
boundary that, as of this writing, does not exist in `src/` — today's
`Policy::check` is synchronous and in-process; see `src/auth/policy.rs`).
It is the specification anchor for any future Lean proof obligations and
any future Rust implementation. Neither has been started.

---

## Why three phases

Today's kernel has zero transit time between presenting a capability and
acting on it (`Policy::check` runs in the same call stack as the gated
operation). Introducing IPC introduces, for the first time, a real window
between "capability validated" and "operation executed." This protocol
makes that window an explicit, bounded, and monitored phase (RESERVE) with
its own revocability and TTL — rather than leaving it implicit and
unguarded. EXECUTE then re-validates against a live revocation channel
before committing the gated effect.

---

## PHASE 1: CHECK

**Purpose:** Validate that the presented capability authorizes the
requested action, at the receiver, at a single instant. This phase is a
direct formalization of today's `Policy::check_inner` (`src/auth/policy.rs:89-118`),
extended with one new check that current in-process code does not need:
sender-identity binding.

### Inputs

| Field | Type (proposed) | Source |
|---|---|---|
| `cap` | `Capability` (existing type, `src/auth/capability.rs:37`) | Deserialized from the wire message |
| `requested_action` | `CapabilitySet` (existing type) | Wire message |
| `sender` | `NodeId` (existing type, `NonZeroU32`) | Transport-layer claimed identity of the message originator |

### Validation (in order — every step is fail-closed; first failure halts and short-circuits)

1. **Sender-identity binding** — `sender == cap.target()`. This check has
   no precedent in the existing codebase: today's `Capability` is bound to
   a target node but the *caller's identity* is never independently
   checked against it, because today's caller and the bound target are the
   same execution context by construction. Over IPC, the wire-level sender
   must be authenticated as `cap.target()` by the transport layer **before**
   this comparison is meaningful. **REFINEMENT_GAP:** how the transport
   authenticates `sender` (signature scheme, MAC, mutual TLS, or other) is
   explicitly out of scope for this document — it is a cryptographic
   primitive, not a pure predicate, and follows the same flagging
   convention as `docs/FUNCTION_SPECS.md`'s `REFINEMENT_GAP` register
   (Ed25519/SHA-256 treated as black boxes there; the same applies here).
2. **Epoch / generation match** — `cap.generation == current_generation`
   at the receiver, by exact equality (reusing `Capability::authorises`,
   `src/auth/capability.rs:69-71`). Not `>=`, for the same reason already
   documented there: a future-generation token must not survive rotation.
3. **Rights / scope bounds** — `cap.rights.contains(requested_action)`.
4. **Revocation** — `!revocation.is_revoked(cap.nonce)` against the
   receiver's `RevocationLedger` (`src/auth/revocation.rs`).
5. **Nonce replay** — `!used_nonces.contains(cap.nonce)`, then record
   `cap.nonce` into the receiver's replay window
   (`src/auth/policy.rs:104-116`). Recording happens at CHECK, not later —
   this prevents the same capability from being used to mint two
   reservations.

All five steps run as one atomic, receiver-local operation — there is no
partial-CHECK state visible to any other party, matching the atomicity
already guaranteed by `Policy::check_inner` today.

### Outputs

- **Success:** a fresh `ReservationId` (proposed new type, `u64`,
  receiver-issued, monotonic, **disjoint namespace from capability
  nonces** — a `ReservationId` must never be numerically confusable with a
  `cap.nonce`, to keep "this capability was used" and "this attempt is
  reserved" independently revocable; see Claims Discipline).
- **Failure:** a rejection carrying exactly one reason (below). No
  reservation is created on any failure path.

### Failure modes

| Failure | Existing precedent | Proposed error shape |
|---|---|---|
| Sender identity ≠ `cap.target()` | None — new check | `Error::CapabilityDenied { reason: "sender identity does not match capability target" }` |
| Malformed / undecodable capability or message | `Error::ManifestInvalid`-style HALT | `Error::CapabilityDenied { reason: "malformed capability" }` |
| Epoch mismatch | `Capability::authorises` exact-equality | `Error::CapabilityDenied { reason: "token expired, insufficient rights, or wrong generation" }` (reuse existing reason string) |
| Out of scope (rights) | `CapabilitySet::contains` | same reason string as above (today's code does not distinguish generation failure from rights failure in the reason string — this protocol does not change that; see Claims Discipline for whether it should) |
| Revoked | `RevocationLedger::is_revoked` | `Error::CapabilityDenied { reason: "capability revoked" }` (existing string) |
| Replayed nonce | `used_nonces.contains` | `Error::CapabilityDenied { reason: "nonce replayed" }` (existing string) |
| Nonce window exhausted | `used_nonces.push` capacity | `Error::CapabilityDenied { reason: "nonce window exhausted; rotate generation" }` (existing string) |

Every failure mode classifies as `DenialClass::Halt` — authorization was
never established, so no kernel state is modified (matches the existing
HALT contract, `src/error.rs:11-13`).

---

## PHASE 2: RESERVE

**Purpose:** Convert a validated CHECK result into a time-bounded,
independently-revocable authorization to perform the action, without yet
committing the action's effect.

### Inputs

| Field | Type (proposed) | Notes |
|---|---|---|
| `reservation_id` | `ReservationId` | From Phase 1 |
| `action_params` | action-specific (e.g. deduction amount, edge, work item) | Opaque to this phase — RESERVE does not interpret them, only stores them |
| `ttl` | `ReservationTtl` (proposed, bounded `u64` logical-tick count) | Must satisfy `0 < ttl <= MAX_RESERVATION_TTL` (proposed new constant, analogous in spirit to `NONCE_WINDOW = 256`, `MAX_REVOCATIONS = 256` in `src/types.rs`) — checked, not wrapping, arithmetic only, per the project's existing "checked arithmetic only in `metabolism::`" rule extended here by analogy |

### State created

A new receiver-local, bounded store — proposed `ReservationLedger`,
structurally parallel to `RevocationLedger` (`src/auth/revocation.rs`:
`heapless`-backed, fixed capacity `MAX_RESERVATIONS`, no heap allocation).

```text
struct Reservation {
    id:         ReservationId,
    node:       NodeId,              // = cap.target() at CHECK time
    action:     CapabilitySet,
    generation: Generation,          // snapshot taken at CHECK time
    ttl:        ReservationTtl,
    status:     ReservationStatus,   // Active | Revoked | Expired | Consumed
}
```

- **What:** the `Reservation` record above, plus the opaque `action_params`
  blob (stored only long enough for EXECUTE to retrieve it).
- **Where:** the receiver node's `ReservationLedger` only. No reservation
  state is ever held by the sender or by any third party.
- **By whom:** the receiver, and only the receiver — same single-authority
  ownership model as `Policy` owning `RevocationLedger` today. There is no
  cross-node write path in this phase.

### Revocation during RESERVE — mechanism

A `Reservation` must be invalidatable by the same authority that can
revoke a capability today (`Policy::revoke_capability`,
`src/auth/policy.rs:124-126`), addressed by `reservation_id` instead of
`nonce`. Revoking a reservation is a synchronous, receiver-local mutation:
`status` transitions to `Revoked`, irreversibly (no `Revoked → Active`
transition exists).

**Cascade rule (explicit, load-bearing):** revoking the *underlying
capability's nonce* — not just the reservation — must also invalidate
every `Reservation` derived from it. The mechanism: EXECUTE's
revocation check (Phase 3) tests **both** the reservation's own `status`
**and** `RevocationLedger::is_revoked(cap.nonce)` for the originating
nonce captured in the reservation's lineage. This means a single
capability-nonce revocation invalidates all outstanding reservations
derived from it without requiring the revoker to enumerate
`reservation_id`s. This is a new requirement; nothing in
`RevocationLedger` today tracks derivation/ancestry between a nonce and
anything reserved from it (see Claims Discipline).

### Outputs

- **Success:** an `ExecutionGrant` (proposed):
  ```text
  struct ExecutionGrant {
      reservation_id: ReservationId,
      generation:     Generation,
      action:         CapabilitySet,
      expires_at:     LogicalTick,   // created_at + ttl, checked addition
  }
  ```
- **Failure / rejection modes:**
  | Failure | Reason |
  |---|---|
  | `ttl == 0` or `ttl > MAX_RESERVATION_TTL` | Proposed `Error::ReservationDenied { reason: "ttl out of bounds" }` (new variant — see below) |
  | `ReservationLedger` at capacity | `Error::ReservationDenied { reason: "reservation capacity exhausted" }` — fail-closed deny, mirroring `RevocationLedger::revoke` returning `false` on full (`src/auth/revocation.rs:53-60`) |
  | `reservation_id` not found / already `Consumed` | `Error::ReservationDenied { reason: "reservation not active" }` |

  Proposed new `Error` variant (additive — `Error` is already
  `#[non_exhaustive]`, `src/error.rs:51-52`):
  ```text
  ReservationDenied { reason: &'static str }   // DenialClass::Halt
  ```

---

## PHASE 3: EXECUTE

**Purpose:** Commit the gated action's effect, having re-confirmed at the
last possible moment that nothing invalidated the authorization since
RESERVE.

### Inputs

`execution_grant: ExecutionGrant`, `action` (the actual operation: a
ledger deduction, a topology traversal, a scheduler enqueue — interpreted
by whichever existing subsystem owns that operation; this protocol does
not replace `Ledger::deduct`, `OperationalGraph::traverse`, or
`Scheduler::schedule` — it gates the call into them).

### Live revocation channel — what it checks, and at what granularity

The channel checks exactly two things, every time it is consulted:

1. `ReservationLedger[reservation_id].status == Active`
2. `!RevocationLedger.is_revoked(originating_nonce)` (the cascade rule
   from Phase 2)

**Granularity, not wall-clock interval:** the kernel owns no wall clock
(the audit log already documents this: timestamps are caller-supplied
ticks, `src/audit/event.rs:39-41`) and has no async runtime today — a
literal "poll every N milliseconds" framing does not fit the existing
`no_std`, single-threaded architecture. This protocol instead specifies
**checkpoint-based** consultation: the channel must be checked (a)
immediately before the action's effect commits, and (b) at every internal
sub-step boundary for any action whose execution is not a single atomic
step (e.g., a multi-entry scheduler drain, or a WASM call composed of
multiple host-function invocations). If a future implementation needs a
literal wall-clock-bounded check (e.g. driven by a hardware timer), that
is a new hardware dependency not present anywhere in `src/` today and must
be flagged the same way TPM/HSM dependencies are flagged in
`docs/FUNCTION_SPECS.md`'s `REFINEMENT_GAP` register — not assumed here.

### Protocol Primitives

The two-step check above (`ReservationLedger` status, `RevocationLedger`
membership) is, as of this writing, a conceptual checkpoint check, not a
wire primitive — no message crosses a process or node boundary in the
current single-node architecture (see "Severed revocation channel",
below). This subsection elevates the channel to a named protocol
primitive so a future multi-node implementation has a single
specification to build against, rather than reverse-engineering one from
single-node behavior. **Specified-but-not-yet-proven:** none of the five
properties below has a Lean theorem, a TLA+ model, or a Rust
implementation — they are additive specification, flagged the same way
the rest of this document flags every other unimplemented requirement.

- **Channel directionality.** The authoritative direction is *push*: the
  node holding the `RevocationLedger` (the authority) pushes a checkpoint
  message to the executor whenever a relevant nonce or reservation changes
  state. Push is primary because it minimizes the window between a
  revocation taking effect at the authority and the executor learning of
  it. The executor additionally *polls* the authority at each of its own
  Phase 3 checkpoints (the same checkpoints described above) as a
  fallback — polling exists to bound the staleness of the executor's view
  if a push message is lost, not to replace the push path.
- **Checkpoint message format.** Each checkpoint message (pushed or
  polled-for) carries, at the logical level — byte-level encoding remains
  out of scope for this document (see "Out of scope", below):
  - the capability nonce the message concerns (the same value carried in
    the originating `Reservation.origin_nonce`, `src/auth/reservation.rs`),
  - the generation counter the message is valid for (`Generation`,
    `src/types.rs`),
  - a timestamp, in the sender's own logical-tick units (the kernel owns
    no wall clock; see "Granularity, not wall-clock interval", above),
  - a signature over the preceding three fields.
- **Authentication of revocation signals.** A checkpoint message is
  trusted only if its signature verifies against the issuing Lux
  instance's key. **REFINEMENT_GAP:** the signature scheme itself (which
  algorithm, which key material, how keys are provisioned or rotated) is
  a cryptographic primitive, not a pure predicate, and is explicitly not
  specified here — same flagging convention as claim 7 in Claims
  Discipline, below, and as the Ed25519/SHA-256 black boxes in
  `docs/FUNCTION_SPECS.md`'s `REFINEMENT_GAP` register. An unauthenticated
  or unverifiable checkpoint message is treated as no message at all (it
  cannot update the executor's view of `Active`/`Revoked` in either
  direction), which folds it into the partition-behavior rule below
  rather than into any new acceptance path.
- **Partition behavior.** Any gap since the last *authenticated*
  checkpoint message that exceeds the reservation's own TTL, with no
  valid checkpoint received in that window, is treated identically to an
  explicit revocation: same `DenialClass::Halt`, same halt sequence (see
  "Revocation during EXECUTE → HALT", below), same `partial` flag logic.
  This is additive precision on top of the existing "Severed revocation
  channel" rule below ("ambiguity defaults to denial") — it does not
  relax or replace that rule; it gives the previously-informal "severed"
  condition a measurable trigger (TTL-bounded silence since the last
  authenticated checkpoint) instead of leaving "severed" undefined.
- **Composition with `ReservationLedger`.** Receipt of a valid,
  authenticated checkpoint message updates the receiver's
  `ReservationLedger` entry for the named reservation: a revocation signal
  transitions `status → Revoked` exactly as `ReservationLedger::revoke`
  already does for a local call (`src/auth/reservation.rs`) — the
  checkpoint is a remote trigger for the same local state transition, not
  a new state shape. A *failed* checkpoint (unauthenticated, malformed, or
  absent past the partition-behavior window above) does not write
  `Revoked` — it has no positive information to record — and instead
  triggers the same halt sequence as below, leaving the
  `ReservationLedger` entry's stored `status` unchanged; only the
  *effective* outcome for this EXECUTE attempt is a halt, so a transient
  partition cannot corrupt ledger state that a later, successfully
  authenticated checkpoint might still need to read accurately.

### Revocation during EXECUTE → HALT: what halt means

This kernel has **no general-purpose transactional rollback mechanism
anywhere in `src/` today** (no undo log, no shadow-write-then-commit
pattern outside of `Ledger::deduct`'s own all-or-nothing `checked_sub`).
This protocol does not invent one. What it does specify, precisely, is the
**ordered halt sequence** every conforming EXECUTE implementation must
follow once revocation — or an equivalent ambiguity, see "Severed
revocation channel" and "Partition behavior", above — is detected at a
checkpoint:

1. **Attempt rollback if and only if the operation exposes a rollback
   hook.** "Rollback hook" means an action-specific, opt-in mechanism the
   gated operation itself provides (e.g. a scheduler's own dequeue-on-abort
   path). This protocol does not require any operation to provide one,
   does not define what one looks like, and does not introduce a
   general-purpose rollback capability to the kernel — it only specifies
   where, in the halt sequence, an existing hook (if any) is invoked.
   Where no hook exists, this step is a no-op by definition, not a
   failure: skipping an unavailable hook is not the same as a rollback
   attempt failing.
2. **Write the halt event to the audit log and to the `RevocationLedger`,
   regardless of rollback outcome.** This step runs whether step 1 was a
   no-op, succeeded, or failed — rollback outcome never gates whether the
   halt is recorded. **If rollback (step 1) fails** — the hook was
   attempted and itself errored, or could not confirm completion — that
   failure is logged as part of this same step, not swallowed and not
   treated as a separate outcome; the halt proceeds regardless. The
   `RevocationLedger` write applies uniformly across all four halt
   triggers named under "Outputs" below (reservation revoked, capability
   nonce revoked, channel severed, TTL expired) — this protocol already
   treats all four as equivalent to a confirmed revocation (see "Severed
   revocation channel": "ambiguity defaults to denial"), so recording each
   into the `RevocationLedger` is a direct application of that existing
   equivalence, not a new exception carved out for one trigger.
   Concretely, the write targets the reservation's `origin_nonce`
   (`src/auth/reservation.rs`) — the capability nonce the reservation was
   derived from — even when the immediate trigger was TTL expiry or a
   severed channel rather than an explicit `Policy::revoke_capability`
   call, so a subsequent attempt using the same capability is denied for
   the same settled reason rather than re-litigating an already-resolved
   ambiguity. **New requirement, no existing precedent:** nothing in
   `RevocationLedger` today (`src/auth/revocation.rs`) is invoked by
   `ReservationLedger` or by any TTL/channel-severance code path — there
   is no Rust call site for this write yet, exactly as the cascade rule
   (Phase 2, above) introduced a requirement with no prior precedent in
   the codebase.
3. **Return fail-closed to the caller, unconditionally, with a halt reason
   code** (the `denial_reason` field named under "Outputs", below). This
   step is not gated on steps 1 or 2 succeeding — there is no path back to
   "permitted" once a halt has been triggered, and no path on which the
   caller receives anything other than a denial once this sequence has
   started.

**Ordering is strict and is part of the specification, not an
implementation detail:** rollback, if attempted, happens before the halt
is recorded, and the halt is always recorded before the fail-closed
return. An implementation that returns to the caller before completing
step 2, or that skips step 2 because step 1 failed, does not conform to
this protocol. **Specified-but-not-yet-proven:** this ordering is asserted
here as a requirement; no Lean theorem or TLA+ model establishes that a
future EXECUTE implementation actually honors it. This is additive scope
on top of Claims Discipline claim 5, below — claim 5 covers checkpoint-
aligned *commit* ordering; the ordering specified here is a distinct,
three-step *halt-handling* ordering layered on top of it, not a
restatement of it.

Restating the rest of this protocol's existing constraints, unchanged by
the above:

- **Constraint on action design, not a new capability of the kernel:**
  EXECUTE must be checkpoint-aligned such that every sub-step between
  checkpoints is independently atomic and leaves no partially-visible
  effect crossing a checkpoint boundary. A design requiring rollback of an
  already-committed sub-step beyond what an action's own optional rollback
  hook (step 1, above) can provide is **out of scope** for this protocol
  until a general-purpose rollback mechanism is separately specified,
  proposed, and proven — not assumed to exist here.
- **Halt semantics, concretely:**
  - If revocation is detected **before** any sub-step has committed: the
    action does not execute at all. Equivalent to today's `DenialClass::Halt`
    — no kernel state modified beyond the halt sequence's own step 2 write.
  - If revocation is detected **between** sub-steps (some already
    committed, e.g. 3 of 5 work items already scheduled): the action stops
    immediately at the next checkpoint, running the halt sequence above.
    Step 1's rollback hook, if present, is the only mechanism that can
    undo an already-committed sub-step; absent one, already-committed
    sub-steps are **not** rolled back — this is honestly a
    **partial-execution** outcome, not a clean halt, and must be labeled
    as such.
  - **Partial-execution flag:** the resulting event carries
    `partial: bool`, `true` iff at least one sub-step committed before the
    halt sequence's step 1 began. This flag must never be silently
    dropped — a `partial: true` halt is a materially different outcome
    from a clean halt and downstream auditing must be able to distinguish
    them.
  - **`partial` is not cleared by a successful rollback.** If step 1's
    rollback hook reports success, `partial` remains `true` rather than
    being reset to `false`: rollback-hook correctness is not itself a
    proof obligation in Claims Discipline below, so the audit record must
    continue to show that a commit occurred and a halt followed, not
    silently imply nothing happened.
  - **Audit event:** every EXECUTE outcome — completion or halt, partial
    or clean — is appended to the audit log unconditionally: for the halt
    case, per step 2 of the halt sequence above; for the completion case,
    per the existing rule that an audit event is always emitted regardless
    of outcome (`src/auth/policy.rs:79`, comment). Proposed: reuse the
    existing two-axis `EventKind` × `Outcome` schema
    (`src/audit/event.rs:8-33`) rather than inventing a parallel "halted"
    taxonomy — add one new variant, `EventKind::IpcExecute`, and represent
    completion as `Outcome::Permitted` / halt as `Outcome::Denied`, with
    `partial` carried as an additional field on `AuditEvent` (a schema
    addition, not a new orthogonal concept).

### Severed revocation channel → HALT: specified identically to revocation-during-EXECUTE

"Severed" is only a meaningful failure mode once revocation-checking
crosses a process or node boundary — i.e., once CHECK/RESERVE happen on
one node and EXECUTE's live-channel check must reach a `RevocationLedger`
or `ReservationLedger` that is not locally addressable. **This case does
not exist in the current single-node, single-threaded architecture** — a
local function call to a local data structure cannot be "severed." This
section therefore specifies the rule for the distributed case, should one
ever be built, rather than describing a present capability:

> **Inability to confirm a non-revoked state is treated identically to a
> confirmed revocation. Ambiguity defaults to denial.**

Concretely: if the channel does not return a definite answer (timeout,
disconnect, malformed response) before the next checkpoint, EXECUTE halts
exactly as it would for a confirmed revocation — same `partial` flag
logic, same audit event shape, same `DenialClass::Halt`. There is no
"proceed optimistically and reconcile later" path. This is a conscious
availability/safety tradeoff — see **Invariants → Tradeoff**, below.

### Outputs

- **Completion event:** `EventKind::IpcExecute`, `Outcome::Permitted`,
  `partial: false`, referencing the underlying operation's own result
  (e.g. the `Ledger::deduct` return value) — this protocol does not
  replace that subsystem's own success reporting, only wraps it.
- **Halt event:** `EventKind::IpcExecute`, `Outcome::Denied`, `partial`
  set per the rule above, `denial_reason` naming which of (reservation
  revoked / capability nonce revoked / channel severed / TTL expired)
  triggered the halt.

---

## INVARIANTS SECTION

| Invariant | Touched by this protocol | How |
|---|---|---|
| **I1 — Fail-Closed** | All three phases | Every ambiguity — malformed message, sender mismatch, TTL out of bounds, capacity exhaustion, severed channel, mid-execute revocation — denies or halts. No phase has a default-permit path. This is the most pervasive invariant in the document; nearly every "Failure modes" / "HALT" subsection above is I1 in a specific guise. |
| **I2 — Capability-Gated** | CHECK (foundational), RESERVE, EXECUTE | No `Reservation` or `ExecutionGrant` may be created without a prior successful CHECK. Critically: a `ReservationId` / `ExecutionGrant` is **not** a new form of ambient authority — it is a derived, time-bounded, revocable artifact of a capability check, never a substitute for one. EXECUTE re-checks revocation rather than trusting RESERVE's grant as a standing pass. |
| **I3 — Accountable Resources** | EXECUTE only, by design choice | RESERVE reserves **authorization**, not **resources** — it does not pre-charge `Ledger::deduct` speculatively. The actual ledger deduction (if the gated action is a resource allocation) happens only at EXECUTE's commit point, preserving `Ledger::deduct`'s existing atomicity guarantee unmodified. A "soft hold" mechanism in the ledger itself is explicitly **not** introduced by this protocol — that would be a separate proposal requiring its own proof obligations. |
| **I4 — Topology-Bounded** | CHECK (sender-identity step) | If sender and receiver are different nodes, the implied `(src, dst)` edge must still resolve through `OperationalGraph::traverse` against the boot manifest — this protocol does not add a parallel routing mechanism that could bypass the existing edge declaration check. IPC transport must ride on top of I4, not around it. |

### Tradeoff — flagged explicitly, per instruction

**Severed revocation channel ⇒ HALT is a conscious availability-for-safety
trade.** A node that loses connectivity to the revocation-confirmation
path becomes unable to complete any in-flight EXECUTE phase at all, for as
long as the channel is down — even if the underlying capability was
perfectly valid and nothing was actually revoked. This is consistent with
the kernel's existing fail-closed posture and has direct precedent: every
existing HALT path already accepts an availability cost for a safety
guarantee (most directly, `Error::AuditFull` denies an otherwise-valid
operation rather than risk an unlogged enforcement decision,
`src/error.rs:109-122`). This protocol introduces no new philosophy here —
it extends an existing one to a new failure mode (network/channel
partition) that the single-node kernel has never previously had to
consider.

---

## CLAIMS DISCIPLINE

No claim in this document has been mechanically verified. Nothing here has
been run through `lake build`, Kani, or `cargo test` — none of those
artifacts exist yet for this protocol. The table below identifies which
statements are shaped like theorems and will need a corresponding Lean 4
proof obligation (or, where noted, a TLA+ model extension instead) before
any implementation may claim correctness rather than just intent.

| # | Claim (specified, not proven) | Proof vehicle needed | Notes |
|---|---|---|---|
| 1 | CHECK never issues a `ReservationId` unless all five Phase 1 validations passed | New Lean theorem, shape similar to `concreteDeductSpec` (`lean/LuxRefinement.lean`) | Pure function over receiver-local state — Lean-suitable |
| 2 | RESERVE never produces an `ExecutionGrant` for an expired, revoked, or out-of-bounds-TTL reservation | New Lean theorem | Pure function — Lean-suitable |
| 3 | `ReservationId` values and capability `nonce` values are never aliased (disjoint-namespace claim) | New Lean theorem (likely a straightforward injective-issuance argument) | Pure function — Lean-suitable |
| 4 | A capability-nonce revocation cascades to invalidate every `Reservation` derived from it | New Lean theorem — likely the most novel one in this set; requires modeling derivation/ancestry between a nonce and the reservations created from CHECK results that consumed it | Pure function over an extended ledger model — Lean-suitable, but needs new lemmas; no existing `LuxCostModel`/`LuxRefinement` machinery covers ancestry today |
| 5 | EXECUTE never commits an action's irreversible effect at a checkpoint after revocation was detected at or before that checkpoint | New Lean theorem, conditioned on the "checkpoint-aligned atomic sub-steps" constraint stated in Phase 3 | Lean-suitable only if checkpoint structure is itself modeled as a finite, ordered sequence; if action structure is unbounded/dynamic this may need restating |
| 6 | Severed-channel detection has no false negative — i.e., it never mistakes a severed channel for a confirmed non-revoked state | **Not a Lean claim.** This is a property of detection/timeout behavior under network partition, the same category as the TLA+-proved invariants (`ResourceAtomicity`, etc.), not a pure mathematical function. Candidate for a **TLA+ model extension**, mirroring the existing split where state-machine/concurrent properties go to TLA+ and function-level arithmetic goes to Lean (`docs/FORMAL_VERIFICATION.md` §1, §6) | Out of scope for Lean entirely |
| 7 | Sender-identity authentication (the transport-layer mechanism binding `sender` to `cap.target()`) is sound | **Not modeled here at all.** Same category as Ed25519/SHA-256 in the existing `REFINEMENT_GAP` register (`docs/FUNCTION_SPECS.md`) — a cryptographic primitive treated as an opaque black box, not a provable Lean predicate | REFINEMENT_GAP, not a proof target |

No statement above is asserted as true of any running code, because no
running code exists. This table exists so that the eventual proof effort
(if undertaken) has a checklist, not so that the protocol can be cited as
already verified in any sense.

---

## Out of scope for this document

- Wire format / serialization encoding of `Capability`, `Reservation`, or
  `ExecutionGrant`.
- Transport-layer authentication mechanism for `sender` (REFINEMENT_GAP,
  claim 7 above).
- Multi-node deployment topology, network partition model, or the
  concrete shape of a "channel" in the severed-channel case (TLA+
  candidate, claim 6 above).
- Any Rust implementation. Any Lean proof. Both are future work gated on
  approval of this specification.
