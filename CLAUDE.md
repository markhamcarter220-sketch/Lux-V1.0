# CLAUDE.md — Lux Kernel Development Contract for Claude Code

This file governs how Claude Code operates in this repository.
Read it in full before touching any file.

---

## Security Invariants (Non-Negotiable)

Every change must preserve all four:

| # | Invariant | Enforcement point |
|---|-----------|-------------------|
| I1 | **Fail-Closed** — ambiguity and errors produce denial, never access | `auth::policy::Policy::check` |
| I2 | **Capability-Gated** — no operation without a valid, scoped token | `auth::capability::Capability::authorises` |
| I3 | **Accountable Resources** — every allocation charged; over-quota rejected | `metabolism::ledger::Ledger::deduct` |
| I4 | **Topology-Bounded** — execution confined to boot-manifest graph | `topology::graph::OperationalGraph::traverse` |

A change that weakens any invariant is a P0 regression regardless of other merits.

---

## Friction Loop — Required Before Every Change

Map blast radius before touching any file:

1. **Who calls this?** — Find all call sites of the function being changed.
2. **What state does it own?** — Identify all mutable state the function touches.
3. **Which invariants does it enforce?** — Trace which of I1–I4 depend on it.
4. **What is the failure mode?** — For every error path, confirm it returns `Err` not `Ok`.
5. **Feature combinations** — Verify behaviour holds with `--no-default-features`, default features, and `--all-features`.

Do not proceed if any of these questions are unanswered.

---

## Audit Prompt Loop

After every change to a security-critical function, run this check mentally
(and document the result in the commit message):

> "Trace all call sites of `[function]` and verify it upholds I1–I4 in
> every feature combination.  Flag any `unwrap`, `expect`, or missing `?`."

Specific checks:
- **No silent swallowing**: `let _ = result` is only acceptable for
  `heapless::Vec::push` where capacity overflow is handled by the caller.
  Any other silenced result must be justified in a comment.
- **No default-permit paths**: A function that returns `Ok(())` on an
  unrecognised input violates I1.  Every unknown case must return `Err`.
- **No ambient authority**: Every operation that modifies kernel state must
  arrive through `Policy::check` → subsystem.  There is no trusted-caller path.
- **Checked arithmetic only**: Use `checked_sub`, `checked_add`, or
  `saturating_*` throughout `metabolism::`.  Wrapping arithmetic is banned.

---

## Commit Standards

- State intent before acting: one sentence describing what you are about to do.
- Every commit message must answer: "Which invariant does this change affect, and how?"
- Never force-push. Preserve full commit history.
- Never add `#[allow(deprecated)]` or compatibility shims.
- Never skip hooks (`--no-verify`).

---

## Project Origin Disclosure

Lux V1.0 was scaffolded with AI assistance (Claude Code) over approximately
four days.  The following manual verification items are outstanding and must
be completed before the external security audit:

- [ ] Independent re-implementation of `Capability::authorises` by a human
      reviewer to confirm generation + rights semantics
- [ ] End-to-end trace of `BootState::run_topology_consensus` happy path
      and denial path by a human reviewer
- [ ] All `Policy::check` call sites audited for I1–I4 compliance across
      all feature flag combinations (`no_std`, default, `--all-features`)
- [ ] `lake build` run in `lean/` to mechanically verify the Lean 4 proofs

Until this checklist is complete, treat the codebase as **internally reviewed
but not externally audited**.  Do not use in production.

---

## What Claude Must Never Do

- Add a code path that returns `Ok` when it should return `Err`.
- Add `unwrap()` or `expect()` in `src/` (only in `tests/` and `benches/`).
- Introduce heap allocation (`Box`, `Vec`, `String`) in `src/` without
  the `alloc` feature — the kernel is `no_std`.
- Modify the four invariant enforcement points without an explicit instruction
  and documented justification.
- Push to a branch other than the designated development branch without
  explicit permission.
- Create a pull request without being explicitly asked to.
