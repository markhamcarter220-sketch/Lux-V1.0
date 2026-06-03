# ADR 0001 — Fail-Closed as a Structural Property

**Status:** Accepted  
**Date:** 2026-Q1

## Context

Early prototypes of Lux used a policy-rule approach to denial: a set of
`if` conditions that checked for known bad states and returned errors.  All
unrecognised states fell through to a default-permit path.

This is the standard approach in application software and is adequate when
the threat model is accidental misconfiguration.  It is inadequate when the
threat model includes an adversary actively searching for unrecognised inputs.

## Decision

Fail-closed is a *structural* property of the API, not a policy rule.

This is achieved by:

1. Returning `Result<T, Error>` from every operation.  `Ok(())` is only
   possible when all checks explicitly pass.
2. Making the `Error` enum `#[non_exhaustive]` so that callers cannot write
   exhaustive matches with a wildcard arm that permits on unknown errors.
3. Ensuring that `Capability` fields are `pub(crate)` — callers cannot
   construct a token without going through the boot path.

## Consequences

- Every new code path that returns `Ok` must be a deliberate grant, not a
  fallen-through default.
- Adding a new operation requires adding a new check, not merely not-blocking.
- The audit surface for the granting paths is small and localized to
  `auth::policy::Policy::check`.
