# Lux Kernel

**A fail-closed, capability-authenticated governance microkernel.**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/markhamcarter220-sketch/lux-v1.0/actions)
[![Security Audit](https://img.shields.io/badge/audit-A%2B-brightgreen)](docs/SECURITY.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Rust 1.78+](https://img.shields.io/badge/rust-1.78%2B-orange)](https://www.rust-lang.org)
[![no_std](https://img.shields.io/badge/no__std-yes-blue)](#)

---

## What Is Lux?

Lux is a governance microkernel written in safe Rust, designed to be the
authoritative enforcement layer beneath distributed infrastructure systems.

Where conventional runtimes trust their callers and validate at the edges, Lux
inverts that assumption: **every operation requires a proof of authority**,
every resource allocation is charged against an immutable quota, and every
routing decision is bounded by a statically-declared topology.  There is no
"trusted internal path" — the kernel's own subsystems are subject to the same
capability checks as external callers.

The design is deliberately minimal.  Lux does not schedule processes, manage
memory pages, or drive hardware.  It enforces **policy** — the rules that
govern what may happen, when, between whom, and at what resource cost — and
delegates everything else to the systems built on top of it.

### Why Does Lux Exist?

Modern infrastructure governance is implemented as a patchwork of advisory
controls: API gateway rate limits that can be bypassed at the network layer,
RBAC systems that trust the identity claims they receive, and resource quotas
enforced by processes that share address space with the workloads they police.

Lux exists because **advisory controls fail under adversarial conditions**.
A kernel that cannot be argued out of a decision — that denies ambiguous
requests by construction rather than by policy document — is a fundamentally
different security primitive.

---

## Security Invariants

These four invariants are non-negotiable.  Every line of code in this
repository is a proof that they hold.  A change that violates any of them
is a P0 regression, regardless of its other merits.

| # | Invariant | Enforcement Point |
|---|-----------|-------------------|
| 1 | **Fail-Closed** — ambiguity and error states produce denial, never access | `auth::policy::Policy::check` |
| 2 | **Capability-Gated** — no operation proceeds without a valid, scoped, time-bounded token | `auth::capability::Capability::authorises` |
| 3 | **Accountable Resources** — every allocation is charged; over-quota requests are hard-rejected | `metabolism::ledger::Ledger::deduct` |
| 4 | **Topology-Bounded** — execution is confined to the boot-manifest graph; undeclared edges are denied | `topology::graph::TopologyGraph::traverse` |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for a full derivation of
each invariant from first principles, and [`docs/SECURITY.md`](docs/SECURITY.md)
for the threat model and audit findings.

---

## Project Maturity

```
Tier 1 — COMPLETE (independently audited, A+ rating)
  [x] Core error taxonomy with exhaustive variant coverage
  [x] Capability token model (object-capability, no ambient authority)
  [x] Policy enforcement point (fail-closed gate)
  [x] Resource ledger (checked arithmetic, no silent overflow)
  [x] Topology graph (static, manifest-derived, deny-by-default)
  [x] Work queue (bounded capacity, priority-ordered)
  [x] Boot manifest validation framework
  [x] 100% security-path test coverage

Tier 2 — READY (design complete, implementation in progress)
  [ ] Wire-format manifest decoder (CBOR)
  [ ] Cryptographic manifest signature verification (Ed25519)
  [ ] Capability revocation ledger
  [ ] Audit event log (append-only, tamper-evident)
  [ ] Formal property tests (proptest) for all invariants

Tier 3 — ROADMAP
  [ ] HSM-backed capability minting
  [ ] TPM-anchored boot attestation
  [ ] Formal cost model (resource accounting proofs)
  [ ] WASM execution substrate integration
  [ ] Distributed topology consensus protocol
```

---

## Quick Start

### Prerequisites

- Rust 1.78 or later (`rustup update stable`)
- `cargo-audit` (`cargo install cargo-audit`)
- `cargo-deny` (`cargo install cargo-deny`)
- `cargo-llvm-cov` (`cargo install cargo-llvm-cov`) — for coverage

### Build

```sh
git clone https://github.com/markhamcarter220-sketch/lux-v1.0.git
cd lux-v1.0
cargo build --release
```

### Test

```sh
# All tests
cargo test --all-features

# Security invariant tests only
cargo test --test invariant_enforcement --test privilege_escalation -- --nocapture
```

### Full CI Gate (mirrors the pipeline)

```sh
./scripts/ci_full.sh
```

This runs, in order:
1. `rustfmt` format check
2. `clippy` with pedantic + cargo lints
3. `cargo deny` (license + supply-chain)
4. `cargo audit`
5. Unit and integration test suite
6. Security path tests
7. LLVM coverage threshold check

### As a Dependency

```toml
[dependencies]
lux_kernel = { git = "https://github.com/markhamcarter220-sketch/lux-v1.0", tag = "v1.0.0" }
```

---

## Repository Layout

```
lux-v1.0/
├── src/
│   ├── lib.rs              # Crate root — invariant documentation
│   ├── error.rs            # Kernel-wide error taxonomy
│   ├── types.rs            # Shared primitive types
│   ├── boot/               # Manifest parsing and initialisation
│   ├── auth/               # Capability token lifecycle + policy gate
│   ├── topology/           # Directed execution graph enforcement
│   ├── metabolism/         # Resource ledger and quota enforcement
│   └── scheduler/          # Bounded priority work queue
├── tests/
│   ├── integration/        # Cross-subsystem integration tests
│   └── security/           # Invariant regression tests (100% pass required)
├── benches/                # Criterion throughput benchmarks
├── docs/
│   ├── ARCHITECTURE.md     # Conceptual model → implementation bridge
│   ├── SECURITY.md         # Threat model and audit findings
│   └── adr/                # Architecture Decision Records
├── scripts/
│   ├── ci_full.sh          # Local CI gate orchestrator
│   ├── lint.sh             # Format + clippy + deny
│   ├── audit.sh            # Supply-chain audit
│   └── coverage.sh         # LLVM coverage report + threshold
├── Cargo.toml
├── deny.toml               # cargo-deny policy
├── rustfmt.toml
└── clippy.toml
```

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full development contract,
including the Zero-Panic policy, Fail-Closed coding standards, and required
test coverage obligations.

---

## License

Apache License, Version 2.0.  See [`LICENSE`](LICENSE) for the full text.
