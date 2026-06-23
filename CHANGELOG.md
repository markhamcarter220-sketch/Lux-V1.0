# Changelog

All notable changes to Lux Kernel are documented here.  This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

40 commits on `claude/lux-kernel-repo-scaffold-fxKWb` since the `1.0.0` tag,
not yet cut into a release. Grouped by subsystem, not exhaustive — see
`git log` for the full commit-by-commit record.

### Security

- **Fixed a fail-open generation check in `Capability::authorises()`**
  (`>=` → `==`): a token minted with a future generation (e.g. `u64::MAX`)
  previously passed permanently, and because generation rotation also
  clears the revocation ledger, explicit revocation could not stop such a
  token — the kill switch failed. Strengthens I1 and I2.
- **Closed an audit-full fail-open gap at all three enforcement gates**:
  each gate previously discarded `audit.append()`'s boolean return, so an
  otherwise-permitted operation could proceed unlogged once the audit log
  reached `MAX_AUDIT_EVENTS`. An unloggable decision now produces denial,
  not silent access. Strengthens I1; does not touch I2–I4.

### Added

- `hsm` subsystem (Phase 1): `SoftwareKeyStore`, `KeyHandle`,
  `KeyManagement` trait, plus `PKCS11HsmProvider`/`YubiHsmProvider` stubs
  (no real FFI integration yet — see `docs/REFINEMENT_GAPS.md` §"Scope
  boundary: key management").
- `tpm` subsystem (Phase 2): `BootAttestation`, `verify_quote`,
  `SoftwareTpm`/`NullTpm`, `TssTpmProvider` stub.
- Lean 4 formal cost-model proof (Phase 3): 7 mechanically-stated ledger
  invariants in `lean/LuxCostModel.lean` (see `docs/FORMAL_COST_MODEL.md`;
  `lake build` has not been independently witnessed in this environment —
  no Lean/Lake toolchain is installed here).
- `wasm` subsystem (Phase 4): `wasmtime`-backed executor exposing the four
  enforcement points as guest-callable exports, `WasmFault` error variant.
- `consensus` subsystem (Phase 5): full Raft state machine, replacing the
  earlier single-round quorum-vote protocol (`docs/adr/0004` is now stale
  against this — see `docs/REFINEMENT_GAPS.md`).
- `lean/Refinement.lean`: I1/I2 system-level obligation theorems
  (`failClosed_generation`, `failClosed_revocation`, `failClosed_replay`,
  `capabilityGated_rightRequired`) closed (no `sorry`); I3/I4 obligations
  remain `sorry`-blocked.
- `lean/FunctionSpecs/*`: full-coverage signature+pre/post spec layer for
  all of `src/`, triaged into `INVARIANT-BOUNDARY`/`BELOW-BOUNDARY`/
  `SPEC-GAP` buckets (89 `REFINEMENT_GAP` flags; see
  `docs/REFINEMENT_GAPS.md`).
- `python` feature: `PyLuxGate`, a stateless `#[pyclass]` authorization
  gate enforcing I1–I4 as a pure function of CE event parameters.
- `src/auth/reservation.rs`: `ReservationLedger`/`Reservation`/
  `ExecutionGrant` — the RESERVE phase of the Capability-Signed Message
  IPC protocol (`docs/ipc/IPC-SPEC.md`). CHECK and EXECUTE remain
  specification-only; not wired into `Policy::check`.
- `lean/IpcReservation.lean`: Lean coverage for the IPC protocol's Claims
  Discipline items 1–5 and the halt-sequence ordering claims
  (`haltSequence_strictOrder`, `rollback_is_operation_property`,
  `auditWrite_mandatory_across_all_triggers`) — all `sorry`-blocked,
  specification coverage only, no mechanical verification claimed.
- `docs/REFINEMENT_GAPS.md`: ID-tagged register entries
  (`REFINEMENT_GAP-IPC-001`, `LEAN-IPC-001`) tracking the IPC checkpoint-
  authentication gap and the halt-sequence Lean statements above.
- README: directional Roadmap section (LangChain/LangGraph integration,
  IPC formalization, mechanical Lean verification) — explicitly no
  delivery dates and no production-readiness language.

### Changed

- `docs/REFINEMENT_GAPS.md`, `docs/FORMAL_VERIFICATION.md`, README, and
  related docs: reconciled several Lean/TLA+ verification-status claims,
  test/attack-vector counts, and a benchmark-figures pass to match what
  was actually run, after an internal documentation audit
  (`docs/CLAIMS_REGISTER.md`) found multiple overclaims.
- `docs/ipc/IPC-SPEC.md`: tightened halt-mechanism semantics into a
  strict, ordered 3-step sequence, and elevated the live revocation
  channel to a named "Protocol Primitives" subsection.

### Fixed

- All `--all-targets --all-features` clippy pedantic/cargo/nursery lint
  errors across test files; `cargo fmt --all` formatting drift.
- Two pre-existing CI script issues (`scripts/`).
- A scheduler I2 gap, a silent ledger-seed failure, and a stale O(1)
  complexity doc claim, found during an audit pass.
- Three HSM/`RevocationLedger` state-disagreement integration tests.

---

## [1.0.0] — 2026-Q2

### Summary

Initial stable release.  All Tier 1 security invariants are implemented and
verified by the adversarial test suite and TLA+ model checking.  Internal
security review is complete; third-party security audit has not yet been
performed — see [`AUDIT_ROADMAP.md`](AUDIT_ROADMAP.md) for the audit timeline.
Do not characterise this release as "audited."

### Added

- `auth` subsystem: object-capability model with generation-scoped tokens,
  bitflag rights, node binding, and strictly-reducing delegation.
- `auth::policy::Policy::check`: the kernel's single enforcement gate.
- `boot` subsystem: manifest parsing framework, atomic `BootState`
  initialisation (all-or-nothing).
- `topology` subsystem: directed execution graph derived from boot manifest,
  deny-by-default edge traversal.
- `metabolism` subsystem: per-node resource ledger with checked arithmetic
  and `QuotaEnforcer` enforcement point.
- `scheduler` subsystem: bounded priority work queue with capacity ceiling.
- `error` module: exhaustive, `#[non_exhaustive]` kernel error taxonomy.
- `types` module: `NodeId`, `Quota`, `Generation` domain primitives.
- Security test suite: invariant enforcement + privilege escalation paths.
- `deny.toml`: license allowlist and supply-chain policy.
- ADRs: 0001 (fail-closed design), 0002 (capability-based auth).

### Security

- All 13 vulnerability classes in the V1.0 threat model are structurally
  mitigated.  See `docs/SECURITY.md` for the full mapping.
- Open findings F-01 (manifest signature), F-02 (revocation ledger), and
  F-03 (audit log) are tracked for Tier 2 resolution.
