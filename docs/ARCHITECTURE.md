# Architecture — Lux Kernel

**Revision:** 1.0.0  
**Status:** Stable — changes require ADR

---

## 1. Purpose of This Document

This document bridges the gap between the governance concepts that motivate Lux
and the Rust implementation that enforces them.  It is written for two
audiences simultaneously:

- **Architects** evaluating whether Lux is the right trust substrate for their
  system, who need to understand the conceptual model and its security claims.
- **Systems engineers** building on or contributing to Lux, who need to
  understand precisely how those concepts map to specific types, functions, and
  module boundaries.

If you find that the implementation diverges from this document, the
implementation is wrong.  File a bug.

---

## 2. Conceptual Model

### 2.1 The Governance Inversion

Conventional systems grant access by default and restrict it through policy
rules applied at check points.  The failure mode of such systems is
well-understood: a missed check point, a policy rule that doesn't compose
correctly with another, or a new code path added by a contributor who didn't
know about the restriction — and access is silently permitted where it should
not be.

Lux inverts this.  Access is **denied by default at the type level**.  A
subsystem that has not been handed a valid capability token literally cannot
call the operation it wants to perform — there is no API surface that bypasses
the check.  The burden of proof falls on the caller.

### 2.2 The Object-Capability Model

Lux implements a pure object-capability (ocap) security model.  Authority in
this model is embodied by *unforgeable references* rather than by identity
assertions or access control lists.

A `Capability` token in Lux:

- Is non-cloneable (Rust's ownership model enforces this structurally).
- Is time-scoped via a monotonic generation counter.
- Is operation-scoped via a bitflag set — a token grants specific named
  operations, not a broad role.
- Is node-bound — it carries an `(issuer, target)` pair; it can only be used
  by the target on the issuer's resources.
- Can be delegated — but only to a *strict subset* of its own rights.
  Privilege amplification is algebraically impossible.

### 2.3 The Four Core Invariants

These invariants are the kernel's security specification.  Every design
decision, every API boundary, every test is a proof that they hold.

```
I1 — Fail-Closed
     ∀ operation O: (O is ambiguous) ∨ (O encounters error) → O is denied.
     There is no default-permit path.

I2 — Capability-Gated
     ∀ operation O: O requires a token T where:
       T.rights ⊇ {right required by O}
       T.generation ≥ current_generation
     No token → denial.  Insufficient rights → denial.  Expired generation → denial.

I3 — Accountable Resources
     ∀ allocation A(node, amount):
       ledger[node].balance ≥ amount → A is permitted, balance decremented.
       ledger[node].balance < amount → A is hard-rejected (Err), balance unchanged.
     No silent over-commit.  No graceful degradation.

I4 — Topology-Bounded
     ∀ traversal (src → dst):
       edge (src, dst) ∈ manifest.edges → traversal is permitted.
       edge (src, dst) ∉ manifest.edges → TopologyViolation.
     The manifest is sealed at boot and immutable thereafter.
```

---

## 3. The Fail-Closed Design Pattern

Fail-closed is not merely a design goal — it is a structural property of the
codebase.  It is achieved through three concrete techniques:

### 3.1 Error-First Return Types

Every kernel operation that can fail returns `Result<T, Error>`.  The `Error`
enum is `#[non_exhaustive]`, ensuring that callers cannot match it exhaustively
and then add a wildcard that grants access.  Every variant is an explicit,
named denial reason.

The sentinel pattern "catch-all / unknown error" is explicitly absent from
the `Error` enum.  A developer adding a new error condition must name it
precisely, which forces documentation of the denial reason.

### 3.2 Deny-by-Default Types

The `Policy::check` function signature is:

```rust
pub fn check(&self, cap: &Capability, required_right: CapabilitySet) -> Result<()>
```

There is no overload and no optional parameter that widens the check.  The only
path to `Ok(())` is a token that satisfies all three conditions simultaneously:
valid generation, non-empty rights, and the specific required right present.
The function body is:

```rust
if cap.authorises(required_right, self.current_generation) {
    Ok(())
} else {
    Err(Error::CapabilityDenied { ... })
}
```

This is the entire enforcement surface.  It is trivially auditable.

### 3.3 Structural Impossibility of Amplification

`Capability::delegate` is the only mechanism for producing a derived token.
Its logic enforces two conditions that together make privilege amplification
structurally impossible:

1. The delegating token must hold `CapabilitySet::DELEGATE`.
2. The requested `subset` must be a bitwise subset of `self.rights`:
   `self.rights.contains(subset)`.

If either condition fails, the method returns `None`.  Because `Capability`
is `!Clone` and there is no `unsafe` code in the crate, there is no mechanism
for a caller to construct a `Capability` with arbitrary rights.

### 3.4 Fail-Closed Negative-Space Specification

Fail-closed is defined by what it excludes. The following patterns violate fail-closed and will be rejected in code review:

- **Silent defaults that grant access:** Any code path that returns `Ok` when input is unrecognized.
- **Graceful degradation:** Reducing rights rather than denying the operation. Fail-closed never scales back privileges; it denies.
- **Privilege escalation via exception handling:** Catching an error and proceeding anyway. The error is the denial.
- **"Hidden yes" paths:** A code path disguised as a deny-by-default but containing a backdoor check that permits access.
- **Ambient authority:** Any operation that doesn't require an explicit capability token at the call site.

**Decision tree for contributors:** If your code path answers "maybe" to "would an adversary call this legitimate?", you've violated fail-closed. The kernel must answer only "yes" (token valid, operation authorized) or "no" (explicit error). There is no "proceed with reduced rights."

---

## 4. Subsystem Map

```
┌─────────────────────────────────────────────────────────────┐
│                        Caller                               │
└────────────────────────┬────────────────────────────────────┘
                         │  presents Capability token
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              auth::policy::Policy::check()                  │  ← I1, I2
│  Validates: generation, rights, token integrity             │
└────────────────────────┬────────────────────────────────────┘
                         │  Ok(()) → proceed  /  Err → deny
            ┌────────────┼────────────┐
            ▼            ▼            ▼
   ┌────────────┐ ┌────────────┐ ┌────────────────┐
   │ topology   │ │ metabolism │ │   scheduler    │
   │  graph     │ │  ledger    │ │   work queue   │
   │  traverse()│ │  deduct()  │ │   enqueue()    │
   │    I4      │ │    I3      │ │                │
   └────────────┘ └────────────┘ └────────────────┘
            │            │            │
            └────────────┴────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │   boot::BootState   │  ← manifest is sealed here
              │   (immutable after  │
              │    initialise())    │
              └─────────────────────┘
```

### Module Responsibilities

| Module | Invariants | Key Type | Notes |
|--------|-----------|----------|-------|
| `boot` | I4 (manifest sealing) | `BootState`, `Manifest` | Only entry point for policy declaration |
| `auth` | I1, I2 | `Capability`, `Policy` | Capability minting, delegation, check |
| `topology` | I4 | `TopologyGraph` | Graph traversal, deny-by-default |
| `metabolism` | I3 | `Ledger`, `QuotaEnforcer` | Checked arithmetic, no over-commit |
| `scheduler` | — | `WorkQueue` | Bounded queue, enqueue requires prior auth check |
| `error` | I1 | `Error` | Exhaustive denial taxonomy |
| `types` | — | `NodeId`, `Quota`, `Generation` | Domain primitives |

### 4.1 Topology Invariant — Boundary Conditions

The topology graph is derived from the manifest and enforced at traversal time. The following boundary conditions are resolved as follows:

**Self-loops (A → A):** Allowed. The kernel does not forbid a node declaring an edge to itself. The authorization check `I2` (capability-gated) still applies; the operation must be authorized regardless of graph shape.

**Missing nodes:** If the manifest declares an edge A → B but B is not in the quota table, this is caught at manifest parse time in `boot::Manifest::parse_and_verify()`. The manifest is rejected with `ManifestInvalid` before the kernel is initialized. No partial state is created.

**Cycles (A → B → A):** Allowed. The topology is a general directed graph, not a DAG. Cycles do not violate `I4`. However, cycles combined with unbounded traversal could create livelock; the caller's responsibility is to provide a traversal policy (e.g., maximum hop count).

**Undeclared edges (caller attempts A → C when only A → B → C exists):** Denied at traversal time with `TopologyViolation` error. The caller must follow the manifest graph exactly; shortcutting through intermediate nodes is not permitted by the kernel.

### 4.2 Resource Ledger — State and Concurrency Semantics

The ledger in `metabolism::Ledger` tracks quota balances per node. Its state model is as follows:

**Stateless vs. Stateful:** The ledger is stateful. The quota *ceilings* are derived from the manifest and immutable (set at boot). The quota *balances* are mutable runtime state, decremented by each `deduct()` call and never replenished except at reboot. There is no "reset to ceiling" operation.

**Concurrent deductions:** If two requests attempt to deduct quota for the same node simultaneously, the ledger enforces atomicity via checked arithmetic in `Ledger::deduct()`. The first deduction that would cause `balance < 0` returns `Err(QuotaExceeded)`. The second deduction is evaluated independently against the updated balance. Both operations are fail-closed (no silent over-commit).

**Negative balance prevention:** The kernel prevents negative balance by design: `checked_sub()` returns `None` if the subtraction would underflow. The caller receives `Err(QuotaExceeded)` before any state mutation. This is not a matter of runtime validation alone; it is structural.

**Relation to revocation ledger:** The resource ledger (this subsystem) is distinct from the "Tier 2: Capability revocation ledger" mentioned in the maturity table. The resource ledger enforces `I3` (accountable resources). The revocation ledger (future) will track which tokens have been explicitly revoked. They serve different invariants and may be unified in a later design review, but are currently separate concerns.

---

## 5. Boot Sequence

The boot sequence is the **only** window during which kernel policy may be
established.  After `BootState::initialise` returns `Ok`, the manifest is
sealed and no mutations to topology, quotas, or capability seeds are possible
through the public API.

```
1. Caller provides raw manifest bytes to BootState::initialise()
2. Manifest::parse_and_verify() validates:
   a. Non-empty, well-formed wire format
   b. Declared edge table (no duplicates, valid node IDs)
   c. Quota table (non-zero ceilings, declared nodes only)
   d. Cryptographic signature over the manifest body (Tier 2)
3. TopologyGraph is constructed from the edge table — immutable after this point
4. Ledger is seeded from the quota table
5. Policy is constructed with Generation(0)
6. BootState is returned — sealed and immutable
```

Any failure in steps 2–5 returns `Err(ManifestInvalid)` and leaves no partial
state.  The caller receives either a fully-initialised, consistent kernel state
or nothing.

---

## 6. Architecture Decision Records

Detailed rationale for key design choices is recorded in
[`docs/adr/`](adr/):

- [`0001-fail-closed-design.md`](adr/0001-fail-closed-design.md) — why
  deny-by-default is a structural property, not a policy rule.
- [`0002-capability-based-auth.md`](adr/0002-capability-based-auth.md) — why
  object-capabilities rather than RBAC or ABAC.
- [`0005-revocation-semantics.md`](adr/0005-revocation-semantics.md) — generation-based
  revocation limitation and deferral of per-token granular revocation to Tier 2.

---

## 7. What This Architecture Does Not Cover

The following are explicitly out of scope for Lux V1.0:

- **Process isolation** — Lux enforces policy; it does not provide memory or
  execution isolation.  That is the responsibility of the hosting environment
  (e.g., hypervisor, WASM runtime, OS process model).
- **Network transport** — capability tokens are in-process objects.  Serialising
  and transmitting them across a network boundary requires a separate trust
  establishment protocol (Tier 3 roadmap).
- **Key management** — capability seeds are generated by the boot path.
  HSM-backed key management is a Tier 3 feature.
