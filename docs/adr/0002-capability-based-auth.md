# ADR 0002 — Object-Capability Model over RBAC/ABAC

**Status:** Accepted  
**Date:** 2026-Q1

## Context

Three authentication models were evaluated for Lux:

1. **RBAC (Role-Based Access Control)** — callers assert a role; the system
   checks whether that role is permitted to perform the operation.
2. **ABAC (Attribute-Based Access Control)** — callers assert attributes;
   policy rules map attributes to permissions.
3. **Object-Capability (OCap)** — callers present an unforgeable reference
   (the capability token); possession of the reference is the proof of authority.

## Decision

Object-capability model.

## Rationale

RBAC and ABAC both require the system to *trust the identity assertion* made
by the caller.  If the caller can forge or escalate its role/attribute claims,
the entire access control system is bypassed.

In an OCap model, the caller cannot forge the token because:
- The token type has `pub(crate)` fields — it cannot be constructed outside
  the kernel.
- The token is `!Clone` — possession is transfer; there is no way to
  "copy" authority.
- Delegation is strictly rights-reducing — the algebra prevents amplification.

The result is that the kernel does not need to maintain a global identity
registry or a role assignment table.  Authority is proven by possession, and
possession is enforced by the type system.

## Consequences

- Capability tokens must be treated as secrets by callers.
- Revocation requires generation rotation (a course-grained instrument).
  A fine-grained revocation ledger is planned for Tier 2.
- The delegation graph must be tracked by the caller if audit trails of
  authority delegation are required.  The kernel records denials, not grants.
