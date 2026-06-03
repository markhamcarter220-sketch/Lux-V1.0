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
