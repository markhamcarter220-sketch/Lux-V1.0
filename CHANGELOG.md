# Changelog

All notable changes to Lux Kernel are documented here.  This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-Q2

### Summary

Initial stable release following independent A+ audit.  All Tier 1 security
invariants are implemented and verified.

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
- CI scripts: `lint.sh`, `audit.sh`, `coverage.sh`, `ci_full.sh`.
- `deny.toml`: license allowlist and supply-chain policy.
- ADRs: 0001 (fail-closed design), 0002 (capability-based auth).

### Security

- All 13 vulnerability classes in the V1.0 threat model are structurally
  mitigated.  See `docs/SECURITY.md` for the full mapping.
- Open findings F-01 (manifest signature), F-02 (revocation ledger), and
  F-03 (audit log) are tracked for Tier 2 resolution.
