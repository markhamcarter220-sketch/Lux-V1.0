# ADR 0003 — Epoch-Based O(1) Capability Revocation

**Status:** Accepted  
**Date:** 2026-Q2  
**Gate:** This ADR must be approved before any Tier 2 revocation ledger code is written.

---

## Context

ADR 0002 noted that "revocation requires generation rotation (a coarse-grained
instrument)" and deferred fine-grained revocation to Tier 2.  Before
implementing the Tier 2 revocation ledger, the architecture must specify:

1. **Why generation rotation is the correct structural primitive** for
   invalidating capabilities.
2. **The race condition** inherent in check-then-act revocation schemes, and
   how epoch architecture eliminates it.
3. **The concrete data structure** required for Tier 2.

---

## Decision

The Lux Tier 2 revocation ledger **must** use epoch-based, O(1) revocation.
No alternative revocation architecture is permitted without a superseding ADR.

---

## Rationale

### 1. Generation Rotation as a Structural Primitive

A capability token in Lux carries a `generation: Generation` field.
`Policy::check` rejects any token whose generation is less than
`current_generation`.  `rotate_generation` atomically:

1. Increments `current_generation`.
2. Clears the nonce replay window.
3. Clears the per-generation revocation set.

This means every capability issued in generation G becomes invalid the
instant generation G+1 is entered.  **The cost of revoking all capabilities
of generation G is O(1)** — it is a single integer increment plus two
`Vec::clear()` calls, regardless of how many tokens were issued in generation G.

This property is load-bearing for the kernel's security guarantees: an
attacker who holds N tokens cannot make revocation of those tokens
O(N) by accumulating them.

### 2. The Check-Then-Act Race Condition

Naive revocation schemes suffer from a structural race condition:

```
Thread A                          Thread B (attacker)
──────────────────────────────    ─────────────────────────────
1. read: is_revoked(cap) → false
                                  2. use cap before it is revoked
3. revoke(cap)
4. [too late: cap already used]
```

Even in a single-threaded kernel, the equivalent sequential pattern exists:

```
1. caller presents cap
2. policy check: cap valid at time T
3. revoke(cap) is called at time T+ε (by another subsystem or caller)
4. operation executes using the pre-check authorization
5. revoked cap produced an observable effect after revocation
```

Step 5 is the violation: a revoked capability caused a side effect.

### 3. How Epoch Architecture Closes the Race

Epoch rotation eliminates step 5 by making the authorization and the
generation check **indivisible** at the architectural level.

The key insight: once `rotate_generation` executes, **no token from the
previous generation can pass `Policy::check`**, regardless of when the
check runs.  There is no window.

For fine-grained (per-token) revocation within a generation:

- `RevocationLedger::revoke(nonce)` adds the nonce to an O(1) hash set.
- `Policy::check` consults the revocation set at step 2 (before consuming
  the nonce in step 4).
- The check-then-act window is reduced to the scope of a single `Policy::check`
  call.

Since `Policy::check` is `&mut self` and the kernel is single-threaded with
no async execution, there is no preemption between step 2 and step 4.
The check-then-act window is **zero** by the memory model.

If the kernel ever gains concurrent execution (e.g. multi-core support in
Tier 3), this must be re-evaluated.  The constraint to preserve is:
`Policy::check` must be atomic with respect to `RevocationLedger::revoke`.

### 4. Required Data Structure for Tier 2

The existing `RevocationLedger` (in `src/auth/revocation.rs`) already
implements the correct architecture:

| Property | Implementation |
|---|---|
| O(1) revoke | `heapless::FnvIndexSet::insert` |
| O(1) is_revoked | `heapless::FnvIndexSet::contains` |
| Atomic generation clear | `clear()` called by `Policy::rotate_generation` |
| Bounded capacity | `MAX_REVOCATIONS` (power of two; currently 256) |

The Tier 2 work is to wire the existing `RevocationLedger` into the
operational call path so that callers can revoke capabilities by nonce
without rotating the entire generation.

**`Policy::revoke_capability` already exposes this** (see `auth/policy.rs`).
Tier 2 integration requires:

1. Exposing `Policy::revoke_capability` through `BootState` or an equivalent
   operational handle.
2. Deciding the authority model: who may call `revoke_capability`?  Currently
   there is no capability right gating revocation itself.  A `REVOKE` right
   in `CapabilitySet` may be required.
3. Emitting an audit event (via `AuditLog::append`) with `EventKind::CapabilityRevoked`
   and `DenialClass::Halt` on every revocation.

---

## Consequences

- **The Tier 2 revocation ledger must not introduce any O(N) path** in the
  hot revocation or check path.  Complexity regressions here are a P0 issue.
- **`MAX_REVOCATIONS` is a security parameter**: if the revocation set fills
  before the generation is rotated, `revoke_capability` returns `false`.
  Callers must handle this as a HALT-class event and force generation rotation.
- **Generation rotation is the safety valve**: if fine-grained revocation
  capacity is exhausted, rotating the generation revokes all tokens atomically.
  This is always available as a fallback.
- **No Tier 2 revocation ledger code should be written until this ADR is
  reviewed and merged.**  The implementation approach is locked by this document.
