# ADR 0005: Capability Revocation Strategy

**Status:** Approved  
**Decision Date:** 2026-06-05  
**Decided by:** Security review + framework audit

---

## Context

Lux V1.0 implements revocation via a monotonic `Generation` counter. When a capability is checked, it must satisfy:

```
cap.generation >= current_generation
```

If the generation advances, all tokens issued before that point expire simultaneously.

**Limitation:** This is revocation-by-reset. There is no granular per-token revocation. If you need to revoke token T1 without affecting token T2, the current design cannot do it—you must advance the generation, which revokes T2 as well.

**Precedent:** axium-core's `AuthorityLedger` implements epoch-based revocation, achieving O(1) per-token revocation with O(1) lookup. It passed 53+ adversarial exploit attempts.

---

## Decision

Keep generation-based revocation in Tier 1. Document its limitation explicitly in ARCHITECTURE.md. Defer granular per-token revocation to Tier 2.

**Rationale:** Tier 1 is stable and ready for external audit. Introducing epoch-ledger now would delay the release and require re-auditing the entire revocation subsystem. Generation-based revocation is sufficient for the initial threat model (policy enforcement at initialization, not runtime token lifecycle management).

---

## Consequences

- **Tier 1 constraint:** Revocation is revocation-by-reset. Callers must manage token generation boundaries at a higher level.
- **Tier 2 prerequisite:** When designing Tier 2 features, assume the revocation ledger will be added. Current code structure allows for it without breaking changes to the capability model.
- **Documentation:** ARCHITECTURE.md now explicitly states this limitation, so future contributors don't rediscover it.

---

## Alternatives Considered

### A: Promote Epoch-Ledger to Tier 1.5
- Pros: Stronger revocation model; aligns with axium-core precedent
- Cons: Extends Tier 1 release timeline; requires re-audit
- Decision: Rejected for now; pursue in Tier 2 roadmap

### B: Invite RFC for Post-Release Upgrade
- Pros: Community input on revocation semantics
- Cons: Leaves the gap unowned during Tier 1 release
- Decision: Rejected; ownership stays with security team

---

## Related Decisions

- [`ADR 0003`](0003-epoch-based-revocation.md): Specifies the O(1) epoch-based architecture that the Tier 2 revocation ledger must follow.
- `ARCHITECTURE.md` Section 4.2: Resource Ledger now clarifies that the revocation ledger (Tier 2) is distinct from the resource ledger (Tier 1).
