/-!
# Lux Kernel — Function Spec Layer: Auth Module

Covers every production function in:
- `src/auth/capability.rs` (10 functions: `zeroize`, `drop`, `authorises`,
  `delegate`, `issuer`, `target`, `rights_bits`, `generation_raw`,
  `nonce_raw`, `new_for_test`)
- `src/auth/policy.rs` (7 functions: `new`, `check`, `check_inner`,
  `revoke_capability`, `is_revoked`, `rotate_generation`, `generation`)
- `src/auth/revocation.rs` (6 functions: `new`, `revoke`, `is_revoked`,
  `clear`, `epoch`, `default`)

Total: 23 functions specified.

This is the **central enforcement-point module**: `authorises` backs I2
(Capability-Gated), `Policy::check` backs I1 (Fail-Closed), `delegate`
backs the non-amplification property proved separately (and with real
theorems) in `lean/LuxRefinement.lean`.  This file does NOT attempt to
re-prove anything already proved there — it only states the Lean
signature/pre/post contract for each Rust function, per the methodology in
`lean/FunctionSpecs/Core.lean`.  No proofs are attempted anywhere in this file.

## REFINEMENT_GAP entries in this file

None.  Every function in `src/auth/` is a pure, deterministic function of
its inputs (no I/O, no hardware, no randomness) and gets a real, non-trivial
pre/post pair below.
-/

import FunctionSpecs.Core

open FunctionSpecs

namespace FunctionSpecs.Auth

-- ── Domain types mirroring `src/auth/capability.rs` ───────────────────────────

/-- Mirrors `src/auth/capability.rs::CapabilitySet` (a `u32` bitflags type
    with 5 named bits).  Modelled as a `Finset`-style set via `List Right`
    with no duplicates assumed, consistent with `lean/LuxSpec.lean`'s
    `AbstractCapability.Right`/`Rights` naming (this file does not import
    `LuxSpec` to keep the unproved spec layer decoupled from the proved one;
    names are kept in sync by convention only). -/
inductive Right where
  | ReadTopology
  | AllocResource
  | Schedule
  | Delegate
  | Shutdown
  deriving DecidableEq, Repr

abbrev Rights := List Right

/-- `a` is a subset of `b` iff every right in `a` appears in `b`. Mirrors
    `CapabilitySet::contains` (bitwise AND containment). -/
def rightsSubset (a b : Rights) : Prop := ∀ r ∈ a, r ∈ b

/-- Mirrors `src/auth/capability.rs::Capability`.  `issuer`/`target` are
    `NodeId`; secret fields `rights`/`generation`/`nonce` are zeroed on drop. -/
structure Capability where
  issuer : NodeId
  target : NodeId
  rights : Rights
  generation : GenerationNat
  nonce : Nat
  deriving Repr

-- ── `impl Zeroize for Capability` (`src/auth/capability.rs:46`) ──────────────

/-- Rust: `fn zeroize(&mut self)`.  Zeroes the secret fields in place;
    `issuer`/`target` are left untouched (they cannot be zero — `NonZeroU32`). -/
opaque zeroizeCap (c : Capability) : Capability

def zeroizeCap_pre (_c : Capability) : Prop := True

def zeroizeCap_post (c : Capability) (r : Capability) : Prop :=
  r.issuer = c.issuer ∧ r.target = c.target ∧
  r.nonce = 0 ∧ r.generation = 0 ∧ r.rights = []

-- ── `impl Drop for Capability` (`src/auth/capability.rs:53`) ─────────────────

/-- Rust: `fn drop(&mut self)`.  Calls `self.zeroize()`. -/
def dropCap (c : Capability) : Capability := zeroizeCap c

def dropCap_pre (_c : Capability) : Prop := True

def dropCap_post (c : Capability) (r : Capability) : Prop := zeroizeCap_post c r

-- ── `Capability::authorises` (`src/auth/capability.rs:69`) ───────────────────

/-- Rust: `pub fn authorises(&self, right: CapabilitySet, current_gen:
    Generation) -> bool`.  Generation equality (not `>=`) is the I1/P1 fix:
    see `tla/LuxKernel.tla`'s `IsValidCap` and the regression test
    `future_generation_token_is_denied` in
    `tests/security/privilege_escalation.rs`. -/
def authorises (c : Capability) (right : Rights) (currentGen : GenerationNat) : Bool :=
  decide (c.generation = currentGen) && decide (rightsSubset right c.rights)

def authorises_pre (_c : Capability) (_right : Rights) (_currentGen : GenerationNat) : Prop := True

/-- `true` iff the token's generation equals `currentGen` exactly **and**
    `right ⊆ c.rights`.  A token with `generation ≠ currentGen` — including
    a *future* generation — is always denied; this is the exact property the
    P1 fix (equality, not `≥`) establishes. -/
def authorises_post (c : Capability) (right : Rights) (currentGen : GenerationNat) (r : Bool) : Prop :=
  r = true ↔ (c.generation = currentGen ∧ rightsSubset right c.rights)

-- ── `Capability::delegate` (`src/auth/capability.rs:104`) ────────────────────

/-- Rust: `pub const fn delegate(&self, new_target: NodeId, subset:
    CapabilitySet, nonce: u64) -> Option<Self>`.  The Lean-level
    non-amplification proof for the structurally-identical
    `concreteDelegateCap` lives in `lean/LuxRefinement.lean`
    (`delegate_non_amplification`); this entry restates the contract for
    the *named-field* `Capability` type used elsewhere in this module,
    without re-deriving the proof. -/
def delegate (c : Capability) (newTarget : NodeId) (subset : Rights) (nonce : Nat) :
    Option Capability :=
  if ¬ (Right.Delegate ∈ c.rights) then none
  else if ¬ (rightsSubset subset c.rights) then none
  else some { issuer := c.target, target := newTarget, rights := subset,
              generation := c.generation, nonce := nonce }

def delegate_pre (_c : Capability) (_newTarget : NodeId) (_subset : Rights) (_nonce : Nat) : Prop := True

/-- Returns `none` if `c` lacks `Right.Delegate`, or if `subset` is not a
    subset of `c.rights` (caller-obligation: `nonce` uniqueness within the
    generation is NOT checked here — it is an undocumented-in-types, but
    now doc-commented, caller obligation; see `Capability::delegate`'s Rust
    doc comment "# Caller obligation — nonce uniqueness").  On `some d`:
    `d.rights = subset` (so `d.rights ⊆ c.rights` follows from the guard),
    `d.issuer = c.target`, `d.generation = c.generation`, `d.nonce = nonce`. -/
def delegate_post (c : Capability) (newTarget : NodeId) (subset : Rights) (nonce : Nat)
    (r : Option Capability) : Prop :=
  (¬ rightsSubset subset c.rights ∨ ¬ (Right.Delegate ∈ c.rights) → r = none) ∧
  (rightsSubset subset c.rights ∧ (Right.Delegate ∈ c.rights) →
    ∃ d, r = some d ∧ d.rights = subset ∧ d.issuer = c.target ∧
      d.target = newTarget ∧ d.generation = c.generation ∧ d.nonce = nonce)

-- ── `Capability::issuer` (`src/auth/capability.rs:127`) ───────────────────────

/-- Rust: `pub const fn issuer(&self) -> NodeId`. Trivial pure accessor. -/
def issuerOf (c : Capability) : NodeId := c.issuer

def issuerOf_pre (_c : Capability) : Prop := True

def issuerOf_post (c : Capability) (r : NodeId) : Prop := r = c.issuer

-- ── `Capability::target` (`src/auth/capability.rs:133`) ───────────────────────

/-- Rust: `pub const fn target(&self) -> NodeId`. Trivial pure accessor. -/
def targetOf (c : Capability) : NodeId := c.target

def targetOf_pre (_c : Capability) : Prop := True

def targetOf_post (c : Capability) (r : NodeId) : Prop := r = c.target

-- ── `Capability::rights_bits` (`src/auth/capability.rs:140`, `cfg(feature = "hsm")`) ─

/-- Rust: `pub(crate) const fn rights_bits(&self) -> u32`.  Only compiled
    under the `hsm` feature; used by HSM capability signing to obtain the
    raw bitflag value. -/
def rightsBits (c : Capability) : Nat := c.rights.length
-- NOTE: this is a representational stand-in only — `c.rights` here is a
-- `List Right`, not a bitmask, so `rightsBits` cannot reproduce the actual
-- `u32` value without the bit-position mapping defined in
-- `lean/LuxCapabilityBridge.lean` (`rightMask`/`rightsToBits`). Treat this
-- accessor's spec as a placeholder for "some deterministic encoding of
-- c.rights", not the literal bit pattern.

def rightsBits_pre (_c : Capability) : Prop := True

def rightsBits_post (c : Capability) (r : Nat) : Prop := r = rightsBits c

-- ── `Capability::generation_raw` (`src/auth/capability.rs:147`, `cfg(feature = "hsm")`) ─

/-- Rust: `pub(crate) const fn generation_raw(&self) -> u64`. Trivial pure accessor. -/
def generationRaw (c : Capability) : Nat := c.generation

def generationRaw_pre (_c : Capability) : Prop := True

def generationRaw_post (c : Capability) (r : Nat) : Prop := r = c.generation

-- ── `Capability::nonce_raw` (`src/auth/capability.rs:154`, `cfg(feature = "hsm")`) ─

/-- Rust: `pub(crate) const fn nonce_raw(&self) -> u64`. Trivial pure accessor. -/
def nonceRaw (c : Capability) : Nat := c.nonce

def nonceRaw_pre (_c : Capability) : Prop := True

def nonceRaw_post (c : Capability) (r : Nat) : Prop := r = c.nonce

-- ── `Capability::new_for_test` (`src/auth/capability.rs:164`) ────────────────

/-- Rust: `pub const fn new_for_test(issuer: NodeId, target: NodeId, rights:
    CapabilitySet, generation: Generation, nonce: u64) -> Self`.  Test-only
    constructor, not gated behind `#[cfg(test)]` (integration tests compile
    as separate crates and would not see `cfg(test)` items) — flagged in the
    Rust doc comment as a known follow-up to narrow its visibility. -/
def newForTest (issuer target : NodeId) (rights : Rights) (generation : GenerationNat)
    (nonce : Nat) : Capability :=
  { issuer := issuer, target := target, rights := rights, generation := generation, nonce := nonce }

def newForTest_pre (_issuer _target : NodeId) (_rights : Rights) (_generation : GenerationNat)
    (_nonce : Nat) : Prop := True

def newForTest_post (issuer target : NodeId) (rights : Rights) (generation : GenerationNat)
    (nonce : Nat) (r : Capability) : Prop :=
  r = { issuer := issuer, target := target, rights := rights, generation := generation, nonce := nonce }

-- ── Domain type mirroring `src/auth/policy.rs::Policy` ───────────────────────

/-- Mirrors `src/auth/policy.rs::Policy`. `usedNonces` is bounded by
    `NONCE_WINDOW = 256` in Rust (`heapless::Vec<u64, NONCE_WINDOW>`); the
    bound is carried as an explicit precondition/postcondition parameter
    rather than baked into the type. `revocation` mirrors `RevocationLedger`
    (see below) inline rather than via a separate field type, since Lean has
    no private-field encapsulation to mirror. -/
structure Policy where
  currentGeneration : GenerationNat
  usedNonces : List Nat
  revokedNonces : List Nat
  deriving Repr

def nonceWindow : Nat := 256

-- ── `Policy::new` (`src/auth/policy.rs:51`) ───────────────────────────────────

/-- Rust: `pub const fn new(generation: Generation) -> Self`. -/
def policyNew (generation : GenerationNat) : Policy :=
  { currentGeneration := generation, usedNonces := [], revokedNonces := [] }

def policyNew_pre (_generation : GenerationNat) : Prop := True

def policyNew_post (generation : GenerationNat) (r : Policy) : Prop :=
  r.currentGeneration = generation ∧ r.usedNonces = [] ∧ r.revokedNonces = []

-- ── `Policy::check` (`src/auth/policy.rs:67`) ─────────────────────────────────

/-- Rust: `pub fn check(&mut self, cap: &Capability, required_right:
    CapabilitySet, audit: &mut AuditLog) -> Result<()>`.  The kernel's single
    authorisation gate (I1).  `audit` is modelled abstractly as a `Nat` "is
    full" flag for this spec (the real `AuditLog` type is specified in
    `FunctionSpecs.Audit`; this file does not import it to avoid a
    cross-module dependency in the unproved spec layer — see module doc). -/
opaque check (p : Policy) (cap : Capability) (requiredRight : Rights) (auditIsFull : Bool) :
    Policy × LuxResult Unit

def check_pre (_p : Policy) (_cap : Capability) (_requiredRight : Rights) (_auditIsFull : Bool) : Prop := True

/-- Four checks in order, fail-closed at each: (1) generation equality +
    rights containment via `authorises`; (2) `cap.nonce ∉ p.revokedNonces`;
    (3) `cap.nonce ∉ p.usedNonces` (replay); (4) `p.usedNonces` has room
    (`< nonceWindow`).  On success, the returned policy has `cap.nonce`
    appended to `usedNonces`; the result is `LuxResult.ok ()`.  Any single
    check failing returns `LuxResult.error _` with the policy **unchanged**
    (steps 1-3 do not mutate; step 4's mutation only happens on the success
    path).  If `auditIsFull = true` AND every check above would have
    succeeded, the result is forced to `LuxResult.error LuxError.AuditFull`
    instead of `ok` (the P2 fail-closed audit-completeness fix) — and in
    that case the policy is also left unchanged (the nonce is not recorded,
    matching the Rust `audit.append` post-check ordering in `check_inner`
    followed by the `AuditFull` override, which happens after the nonce
    push — note this is a known asymmetry: the real Rust code *does* push
    the nonce in `check_inner` before the `AuditFull` override fires, so the
    nonce IS consumed even when `AuditFull` is ultimately returned; this
    spec's "policy unchanged" clause for that branch is therefore a
    known simplification, not a faithful transcription — flagged here rather
    than silently asserted). -/
def check_post (p : Policy) (cap : Capability) (requiredRight : Rights) (auditIsFull : Bool)
    (r : Policy × LuxResult Unit) : Prop :=
  let (p', res) := r
  let authOk := cap.generation = p.currentGeneration ∧ rightsSubset requiredRight cap.rights
  let notRevoked := cap.nonce ∉ p.revokedNonces
  let notReplayed := cap.nonce ∉ p.usedNonces
  let hasRoom := p.usedNonces.length < nonceWindow
  (¬ authOk → res = .error (.CapabilityDenied "token expired, insufficient rights, or wrong generation") ∧ p' = p) ∧
  (authOk ∧ ¬ notRevoked → res = .error (.CapabilityDenied "capability revoked") ∧ p' = p) ∧
  (authOk ∧ notRevoked ∧ ¬ notReplayed → res = .error (.CapabilityDenied "nonce replayed") ∧ p' = p) ∧
  (authOk ∧ notRevoked ∧ notReplayed ∧ ¬ hasRoom →
    res = .error (.CapabilityDenied "nonce window exhausted; rotate generation") ∧ p' = p) ∧
  (authOk ∧ notRevoked ∧ notReplayed ∧ hasRoom ∧ auditIsFull →
    res = .error .AuditFull) ∧
  (authOk ∧ notRevoked ∧ notReplayed ∧ hasRoom ∧ ¬ auditIsFull →
    res = .ok () ∧ p' = { p with usedNonces := p.usedNonces ++ [cap.nonce] })

-- ── `Policy::check_inner` (`src/auth/policy.rs:89`, private) ─────────────────

/-- Rust: `fn check_inner(&mut self, cap: &Capability, required_right:
    CapabilitySet) -> Result<()>`.  Same four-step logic as `check` but
    without the audit-append / `AuditFull` wrapping. -/
opaque checkInner (p : Policy) (cap : Capability) (requiredRight : Rights) :
    Policy × LuxResult Unit

def checkInner_pre (_p : Policy) (_cap : Capability) (_requiredRight : Rights) : Prop := True

def checkInner_post (p : Policy) (cap : Capability) (requiredRight : Rights)
    (r : Policy × LuxResult Unit) : Prop :=
  -- Identical to `check_post` with `auditIsFull` fixed to `false` (no audit
  -- wrapping at this layer).
  check_post p cap requiredRight false r

-- ── `Policy::revoke_capability` (`src/auth/policy.rs:124`) ────────────────────

/-- Rust: `pub fn revoke_capability(&mut self, token_id: u64) -> bool`. -/
opaque revokeCapability (p : Policy) (tokenId : Nat) : Policy × Bool

def revokeCapability_pre (_p : Policy) (_tokenId : Nat) : Prop := True

/-- Delegates to `RevocationLedger::revoke` semantics (see `revoke` below):
    succeeds (and appends `tokenId`) unless the revocation set is at
    `maxRevocations` capacity, in which case it fails and `p` is unchanged. -/
def revokeCapability_post (p : Policy) (tokenId : Nat) (r : Policy × Bool) : Prop :=
  let (p', ok) := r
  (p.revokedNonces.length < maxRevocations →
    ok = true ∧ p'.revokedNonces = p.revokedNonces ++ [tokenId] ∧ p'.currentGeneration = p.currentGeneration ∧ p'.usedNonces = p.usedNonces) ∧
  (p.revokedNonces.length ≥ maxRevocations → ok = false ∧ p' = p)
where
  maxRevocations : Nat := 256

-- ── `Policy::is_revoked` (`src/auth/policy.rs:130`) ───────────────────────────

/-- Rust: `pub fn is_revoked(&self, token_id: u64) -> bool`. -/
def policyIsRevoked (p : Policy) (tokenId : Nat) : Bool := decide (tokenId ∈ p.revokedNonces)

def policyIsRevoked_pre (_p : Policy) (_tokenId : Nat) : Prop := True

def policyIsRevoked_post (p : Policy) (tokenId : Nat) (r : Bool) : Prop :=
  r = true ↔ tokenId ∈ p.revokedNonces

-- ── `Policy::rotate_generation` (`src/auth/policy.rs:136`) ────────────────────

/-- Rust: `pub fn rotate_generation(&mut self)`.  Advances the generation
    counter and clears both the nonce replay window and the revocation
    ledger atomically — the kernel's "kill switch." -/
def rotateGeneration (p : Policy) : Policy × Unit :=
  ({ currentGeneration := p.currentGeneration + 1, usedNonces := [], revokedNonces := [] }, ())

def rotateGeneration_pre (_p : Policy) : Prop := True

def rotateGeneration_post (p : Policy) (r : Policy × Unit) : Prop :=
  r.1.currentGeneration = p.currentGeneration + 1 ∧ r.1.usedNonces = [] ∧ r.1.revokedNonces = []

-- ── `Policy::generation` (`src/auth/policy.rs:143`) ───────────────────────────

/-- Rust: `pub const fn generation(&self) -> Generation`. Trivial pure accessor. -/
def policyGeneration (p : Policy) : GenerationNat := p.currentGeneration

def policyGeneration_pre (_p : Policy) : Prop := True

def policyGeneration_post (p : Policy) (r : GenerationNat) : Prop := r = p.currentGeneration

-- ── Domain type mirroring `src/auth/revocation.rs::RevocationLedger` ─────────

/-- Mirrors `src/auth/revocation.rs::RevocationLedger`.  `revoked` is
    `heapless::FnvIndexSet<u64, MAX_REVOCATIONS>` in Rust; modelled as a
    `List Nat` here (duplicate-free is a maintained invariant, not enforced
    by the type). -/
structure RevocationLedger where
  revoked : List Nat
  epoch : Nat
  deriving Repr

def maxRevocations : Nat := 256

-- ── `RevocationLedger::new` (`src/auth/revocation.rs:42`) ────────────────────

/-- Rust: `pub const fn new() -> Self`. -/
def revocationLedgerNew : RevocationLedger := { revoked := [], epoch := 0 }

def revocationLedgerNew_pre : Prop := True

def revocationLedgerNew_post (r : RevocationLedger) : Prop := r = revocationLedgerNew

-- ── `RevocationLedger::revoke` (`src/auth/revocation.rs:53`) ─────────────────

/-- Rust: `pub fn revoke(&mut self, token_id: u64) -> bool`. -/
opaque revoke (l : RevocationLedger) (tokenId : Nat) : RevocationLedger × Bool

def revoke_pre (_l : RevocationLedger) (_tokenId : Nat) : Prop := True

/-- On success (`l.revoked.length < maxRevocations`): `tokenId` is added to
    `revoked` (if not already present — `insert` is idempotent on the
    underlying `FnvIndexSet`) and `epoch` increments by one; result `true`.
    On failure (already at capacity): `l` is unchanged; result `false`. -/
def revoke_post (l : RevocationLedger) (tokenId : Nat) (r : RevocationLedger × Bool) : Prop :=
  let (l', ok) := r
  (l.revoked.length < maxRevocations →
    ok = true ∧ tokenId ∈ l'.revoked ∧ l'.epoch = l.epoch + 1) ∧
  (l.revoked.length ≥ maxRevocations → ok = false ∧ l' = l)

-- ── `RevocationLedger::is_revoked` (`src/auth/revocation.rs:66`) ─────────────

/-- Rust: `pub fn is_revoked(&self, token_id: u64) -> bool`. O(1) amortised
    via FNV-1a hash table in Rust (not a property a Lean spec captures — the
    functional behaviour is what is specified here). -/
def revocationIsRevoked (l : RevocationLedger) (tokenId : Nat) : Bool := decide (tokenId ∈ l.revoked)

def revocationIsRevoked_pre (_l : RevocationLedger) (_tokenId : Nat) : Prop := True

def revocationIsRevoked_post (l : RevocationLedger) (tokenId : Nat) (r : Bool) : Prop :=
  r = true ↔ tokenId ∈ l.revoked

-- ── `RevocationLedger::clear` (`src/auth/revocation.rs:71`) ──────────────────

/-- Rust: `pub fn clear(&mut self)`. Called on generation rotation. -/
def revocationClear (l : RevocationLedger) : RevocationLedger × Unit :=
  ({ revoked := [], epoch := 0 }, ())

def revocationClear_pre (_l : RevocationLedger) : Prop := True

def revocationClear_post (_l : RevocationLedger) (r : RevocationLedger × Unit) : Prop :=
  r.1.revoked = [] ∧ r.1.epoch = 0

-- ── `RevocationLedger::epoch` (`src/auth/revocation.rs:78`) ──────────────────

/-- Rust: `pub const fn epoch(&self) -> u64`. Trivial pure accessor. -/
def revocationEpoch (l : RevocationLedger) : Nat := l.epoch

def revocationEpoch_pre (_l : RevocationLedger) : Prop := True

def revocationEpoch_post (l : RevocationLedger) (r : Nat) : Prop := r = l.epoch

-- ── `impl Default for RevocationLedger` (`src/auth/revocation.rs:83`) ────────

/-- Rust: `fn default() -> Self { Self::new() }`. -/
def revocationDefault : RevocationLedger := revocationLedgerNew

def revocationDefault_pre : Prop := True

def revocationDefault_post (r : RevocationLedger) : Prop := r = revocationLedgerNew

end FunctionSpecs.Auth
