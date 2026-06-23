/-!
# Capability-Signed Message — fork-only IPC formalization (UNVERIFIED)

**Verification status: NOT mechanically checked.** This file is written but
not type-checked or proved by `lake build` — it is intentionally outside the
`lean/` package (`lean/lakefile.lean`) and has no `lakefile.lean` of its own.
Do not cite this file as evidence of a verified property. See
`/FORK_CONTEXT.md` and `docs/ipc/DESIGN.md` for the fork's scope and status.

This file states, in Lean syntax, the safety properties that
`src/ipc/message.rs::SignedMessage` is *intended* to satisfy. The `sorry`
placeholders mark every claim that has not been (and is not yet claimed to
be) proved.

## Model

This mirrors the Rust implementation as built, not the first design draft:
the signature covers `issuer || recipient || body` only (not the
capability's rights/generation/nonce — see `docs/ipc/DESIGN.md` §2 for why
those `pub(crate)`, `hsm`-feature-gated accessors on `Capability` were out of
reach for this fork's scope). Verification additionally checks that the
message's addressing matches the capability's own `issuer`/`target`, then
defers to the existing `authorises` predicate. Cryptographic signing itself
is modeled as an opaque relation, not a concrete Ed25519 model (see
`docs/FORMAL_VERIFICATION.md` for why Ed25519 is not mechanically modeled
anywhere in this project).
-/

namespace Lux.Ipc

/-- A capability, mirroring the public surface of `Capability` in
`src/auth/capability.rs` (`issuer`, `target`, `authorises`). Rights/
generation/nonce are intentionally not modeled here because `SignedMessage`
does not depend on their raw representation. -/
structure Cap where
  issuer : Nat
  target : Nat
deriving DecidableEq, Repr

/-- The policy predicate this protocol delegates to. Modeled here only as an
opaque relation parameterised by `right` and `currentGen` — its internals
(strict generation equality, per `docs/SECURITY.md` V-03) are
`Capability::authorises`'s responsibility, not redefined here. -/
opaque Authorises : Cap → Nat → Nat → Prop

/-- A capability-signed message as actually implemented: addressing plus a
body, signed as one buffer. -/
structure SignedMessage where
  issuer    : Nat
  recipient : Nat
  body      : List Nat
deriving DecidableEq, Repr

/-- Opaque cryptographic binding predicate: `Sign m s` holds iff `s` is a
valid Ed25519 signature over `m.issuer || m.recipient || m.body`. Left
uninterpreted — this file does not model Ed25519 itself. -/
opaque Sign : SignedMessage → Nat → Prop

/-- Verification succeeds iff (1) the signature is valid, (2) the message's
addressing matches the capability's own issuer/target, and (3) the
capability authorises `right` at `currentGen`. Mirrors
`SignedMessage::verify` in `src/ipc/message.rs` exactly. -/
def Verifies (m : SignedMessage) (s : Nat) (c : Cap) (right currentGen : Nat) : Prop :=
  Sign m s ∧ m.issuer = c.issuer ∧ m.recipient = c.target ∧ Authorises c right currentGen

/-- **Body-substitution resistance (UNVERIFIED).**
If a message verifies, no message with the same signature, addressing, and
capability but a *different* body also verifies — the signature commits to
one body. This is the central safety claim motivating signing
`issuer || recipient || body` as a single buffer rather than signing
addressing and body separately. Stated here, not proved. -/
theorem body_substitution_resistant
    (m m' : SignedMessage) (s : Nat) (c : Cap) (right currentGen : Nat)
    (haddr : m.issuer = m'.issuer ∧ m.recipient = m'.recipient)
    (hbody : m.body ≠ m'.body)
    (hv : Verifies m s c right currentGen) :
    ¬ Verifies m' s c right currentGen := by
  sorry

/-- **Addressing-mismatch denial (UNVERIFIED).**
A message signed for one `(issuer, recipient)` pair does not verify against
a capability bound to a *different* pair, even with a valid signature. This
is the property `verify_rejects_addressing_mismatch` exercises as a unit
test in `src/ipc/message.rs`; it is restated here, not proved independently. -/
theorem addressing_mismatch_denied
    (m : SignedMessage) (s : Nat) (c : Cap) (right currentGen : Nat)
    (hmismatch : m.issuer ≠ c.issuer ∨ m.recipient ≠ c.target) :
    ¬ Verifies m s c right currentGen := by
  sorry

/-- **Known limitation, stated explicitly rather than hidden (UNVERIFIED /
not a target property).**
Two distinct capabilities sharing the same `(issuer, target)` pair are
indistinguishable to the addressing check in step 2 — only `Authorises`
(step 3) can tell them apart. This is `docs/ipc/DESIGN.md` §2's "known
limitation," restated formally so it is visible to anyone reading this file
rather than only in prose. No theorem resolves it; it is recorded as a
limitation, not proved or disproved. -/
theorem addressing_check_does_not_distinguish_same_pair_capabilities
    (c c' : Cap) (hsame : c.issuer = c'.issuer ∧ c.target = c'.target) (hne : c ≠ c') :
    True := by
  trivial

end Lux.Ipc
