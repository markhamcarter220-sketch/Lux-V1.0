# Capability-Signed Message — Design (Fork-Only, Draft)

**Status: Draft, fork-only, unaudited.** This document describes work in the
`claude/lux-kernel-demo-5pl5vc` IPC-formalization fork. It is not part of the
parent repository's audited surface. See `/FORK_CONTEXT.md` for scope.

---

## 1. Problem

Lux's existing primitives (`Capability`, `HsmProvider`, `Policy::check`)
authenticate and authorise *operations* on a single node. They do not define
a wire format for a message carrying data *between* nodes that is bound to a
specific capability. This protocol adds that binding without modifying any
existing invariant enforcement point.

## 2. Protocol

**Revised from the initial draft** (see §6): a `SignedMessage`
(`src/ipc/message.rs`) is signed by the sender's `HsmProvider` over:

```
issuer_le32 || recipient_le32 || body
```

The first draft of this protocol attempted to bind the message to a
`Capability`'s raw rights/generation/nonce bits (mirroring
`HsmSignedCapability::cap_payload` in `src/hsm/mod.rs`). That failed to build:
those accessors (`rights_bits`, `generation_raw`, `nonce_raw`) are
`#[cfg(feature = "hsm")]` and `pub(crate)` in `src/auth/capability.rs` — a
file outside this fork's approved scope (`src/ipc/`, `docs/ipc/`,
`formal/ipc/` only; see `/FORK_CONTEXT.md`), and depending on them would have
made this no_std-by-design protocol require the `hsm` feature (which pulls in
`std`) for no real benefit. The protocol now uses only `Capability`'s
unconditionally-public accessors: `issuer()`, `target()`, `authorises()`.

### Verification (fail-closed at each step)

1. Recompute `issuer || recipient || body` and check the Ed25519 signature
   via `HsmProvider::verify`. Any mismatch (wrong key, forged signature,
   tampered body) returns `Err(ManifestInvalid)`.
2. Check that the message's signed `issuer`/`recipient` equal the presented
   capability's own `issuer()`/`target()`. A message signed for one
   addressing pair cannot be verified against a capability bound to a
   different pair. Mismatch returns `Err(CapabilityDenied)`.
3. Call `Capability::authorises(required_right, current_generation)` —
   **unmodified**, strict generation equality, as documented in
   `docs/SECURITY.md` V-03. Any mismatch returns `Err(CapabilityDenied)`.

Any of the three failing denies the message. There is no path that accepts a
message with a valid signature but mismatched addressing or a stale
generation.

### Known limitation of this design

Because the signature only covers `issuer || recipient || body`, not the
capability's rights/generation/nonce, two different capabilities sharing the
same `(issuer, recipient)` pair are interchangeable for the purposes of step
2 — only step 3 (`authorises`) distinguishes them by generation and rights.
This is weaker than the original (non-building) cap-bound design and is an
open item, not a resolved property; see §6.

## 3. What this protocol does *not* change

- `Capability::authorises`, `Policy::check`, `Ledger::deduct`,
  `TopologyGraph::traverse` — the four I1–I4 enforcement points — are
  untouched. `SignedMessage::verify` calls `Capability::authorises` exactly
  as any other caller would; it does not duplicate or bypass policy logic.
- No new `Error` variant was added. `src/ipc/message.rs` reuses
  `Error::CapabilityDenied` and propagates `Error::ManifestInvalid` from
  `HsmProvider::verify` unchanged, so `error.rs`'s "new variant requires a
  `docs/SECURITY.md` entry" rule is not triggered.
- No new topology or ledger interaction. This is purely an authentication
  envelope; routing and quota accounting are out of scope for this draft.

## 4. Formal status

`formal/ipc/CapabilitySignedMessage.lean` states two candidate safety
properties (body-substitution resistance, cross-generation replay
resistance) as Lean `theorem`s with `sorry` bodies. **Neither is proved.**
The file has no `lakefile.lean` and is not reachable from
`lean/lakefile.lean`'s `lake build` — it cannot accidentally be reported as
part of the project's existing (also-bounded, see
`docs/FORMAL_VERIFICATION.md`) verification results.

## 5. Test status

`src/ipc/message.rs` has four unit tests covering: matching
body+capability accepted; wrong generation rejected; tampered body rejected;
missing right rejected. These are ordinary Rust unit tests, not a substitute
for the adversarial suite or TLA+ model checking applied to the rest of the
kernel. No adversarial-suite or TLA+ coverage exists for this protocol yet.

## 6. Open questions (not yet resolved)

- **Weak capability binding (see §2):** the signature does not cover the
  capability's rights/generation/nonce, so the cryptographic check (step 2)
  only enforces *addressing* equality, not full capability identity. Closing
  this without depending on `src/auth/capability.rs`'s `hsm`-gated accessors
  would require either (a) extending `Capability` with unconditional public
  accessors — a change to an out-of-scope file, not made in this fork — or
  (b) accepting `hsm` as a dependency of `ipc` — rejected to keep this
  protocol no_std and feature-independent. Left open.
- Nonce/replay-window integration: should `SignedMessage` consume the
  capability's nonce via `Policy`, or is that the caller's responsibility
  (as `Capability::delegate`'s nonce-uniqueness contract already is)? Not
  decided — this draft does not call `Policy::check`.
- Message size ceiling: `MAX_BODY = 256` bytes is a placeholder, not derived
  from any topology or transport constraint.
- Multi-hop routing (`issuer`/`target` are single nodes; no relay model yet).
