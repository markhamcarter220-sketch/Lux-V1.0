# Lux Kernel v1.0 — Trusted Computing Base (TCB) Document

**Status:** Internally reviewed; not externally audited.  
**Kernel version:** 1.0.0 (`Cargo.toml` line 6)  
**Date:** 2026-06-12  
**Scope:** `src/` tree and `lean/` formal models only.  
This document does NOT cover deployment infrastructure, the host OS beyond the
stated assumptions, or any calling application above the kernel API boundary.

---

## 1. Overview

The Lux Kernel TCB is the minimal set of components that must operate correctly
for the kernel's four security invariants to hold: Fail-Closed (I1),
Capability-Gated (I2), Accountable Resources (I3), and Topology-Bounded (I4)
(stated in `src/lib.rs:3-11`).  Any component outside the TCB may misbehave
without violating these four invariants — provided the in-TCB components
correctly gate access at their enforcement boundaries.  The TCB spans five
layers: the hardware platform, the Rust toolchain and standard library, the
cryptographic primitives, the kernel source proper (`src/`), and the supply
chain controls that govern third-party dependencies.  This document enumerates
every trust assumption explicitly, cites the exact source location that enforces
or acknowledges each assumption, and flags claims that cannot be verified from
source alone.

---

## 2. In-TCB: Trusted Components

| Component | What Lux trusts | File / Line evidence | Risk if violated |
|-----------|-----------------|----------------------|-----------------|
| `auth::policy::Policy::check` | Single authorisation gate; checks generation, revocation, nonce replay in that order; fails closed at each step | `src/auth/policy.rs:1-16` | I1 broken: all capability gating bypassed |
| `auth::capability::Capability::authorises` | Rights bitmask and generation comparison; returns `false` on any unknown or expired token | `src/auth/capability.rs:59-80` | I2 broken: under-privileged tokens could gain elevated rights |
| `metabolism::ledger::Ledger::deduct` | Checked subtraction via `Quota::checked_sub`; returns `None` if balance insufficient; does not modify ledger on failure | `src/metabolism/ledger.rs:47-60`, `src/types.rs:56-60` | I3 broken: resource accounting bypassed; over-quota work permitted |
| `topology::graph::OperationalGraph::traverse` | O(1) bitwise check against sealed edge matrix; denies any edge not declared in the boot manifest | `src/topology/graph.rs:118-153` | I4 broken: execution escapes the declared graph |
| `boot::ManifestDecoder::decode` | Ed25519 signature verified BEFORE CBOR parse; definite-length arrays enforced; all-or-nothing boot contract | `src/boot/decode.rs:87-100` | Adversary can inject malformed manifests; I4 invariant poisoned at boot |
| `boot::BootingGraph::seal` | Consumes the mutable `BootingGraph` via move semantics; `activate` and `permit_edge` are structurally unreachable post-boot | `src/topology/graph.rs:90-99`, `src/boot/mod.rs:290` | Post-boot graph mutation; topology invariant silently widened |
| `audit::AuditLog::append` | Append-only; SHA-256 hash chain; capacity overflow loses new events, never overwrites old ones | `src/audit/log.rs:1-9`, `src/audit/log.rs:74` | Audit record corrupted or silently truncated |
| `auth::capability::Capability` (drop impl) | Zeroizes `rights`, `generation`, and `nonce` on drop | `src/auth/capability.rs:45-57` | Capability secret fields linger in memory after token destruction |
| `heapless` bounded collections | All kernel collections are statically sized; no heap allocator interaction in `no_std` builds | `src/types.rs:9-28`, `Cargo.toml:30` | Unbounded heap growth; denial-of-service via memory exhaustion |
| `scheduler::Scheduler::schedule` | `Policy::check(SCHEDULE)` called before any queue mutation; raw `WorkQueue::enqueue` is inaccessible on production paths | `src/scheduler/mod.rs:62-71` | I2 broken: unauthenticated work items injected into scheduler |
| `wasm::WasmShim` (capability handle table) | Capability tokens never serialised into WASM guest linear memory; guest holds opaque `u32` handles only | `src/wasm/mod.rs:24-28`, `src/wasm/mod.rs:46-54` | Capability token bytes exposed to and forgeable by guest |
| Build profile `overflow-checks = true` | Integer overflow causes a panic-abort rather than silent wrapping in both `dev` and `release` profiles | `Cargo.toml:72`, `Cargo.toml:76` | Silent integer wrap in resource arithmetic; I3 undermined |
| `#![deny(unsafe_code)]` (non-feature builds) | `unsafe` blocks structurally banned in `no_std` configurations | `src/lib.rs:32-35` | Memory-safety violations introducible without explicit `unsafe` keyword |

---

## 3. Layer-by-Layer Assumptions

### 3.1 Hardware

| Assumption | Source evidence | Status |
|------------|-----------------|--------|
| The CPU executes instructions as specified (no microcode side-channel that leaks kernel state across principals). | No Lux-level mitigation. | [UNVERIFIED ASSUMPTION] |
| An entropy source is available to `OsRng` when the `hsm` feature is enabled. | `src/hsm/keystore.rs:102-103` (uses `rand_core::OsRng`) | [UNVERIFIED ASSUMPTION] — correctness of `OsRng` depends on the OS |
| When the `tpm` feature is absent (default), no hardware TPM is assumed. `NullTpm` produces an all-zeros quote and provides no real attestation. | `src/tpm/attestation.rs:1-14`; `NullTpm` behaviour documented in `src/tpm/` | Explicitly documented limitation |
| When the `tpm` feature is enabled, a real TPM 2.0 device is trusted to produce correct PCR-bound quotes. | `src/tpm/attestation.rs` challenge-response protocol | [UNVERIFIED ASSUMPTION] — hardware and driver correctness out of scope |
| Stack size is sufficient for the worst-case frame (MAX_NODES=64 × 64-bit bitmask rows = 512 bytes for the edge matrix alone). | `src/types.rs:11`, `src/topology/graph.rs:113-115` | [UNVERIFIED ASSUMPTION] — no automated stack-depth analysis in CI |

### 3.2 Operating System

| Assumption | Source evidence | Status |
|------------|-----------------|--------|
| In `no_std` builds (default, `tpm`, `serde` features) the kernel makes no OS calls at all. | `src/lib.rs:17-20` — `no_std` enforced by `cfg_attr` | Verified in source |
| In `std` builds (`hsm`, `python`, `wasm` features), the OS `Mutex`, memory allocator, and dynamic linker are trusted to be correct and non-malicious. | `src/hsm/keystore.rs:8-9` (`std::sync::Mutex`, `std::collections::HashMap`) | [UNVERIFIED ASSUMPTION] |
| The OS does not share address-space memory between Lux kernel state and untrusted principals. | No Lux-level enforcement; responsibility of the host OS and deployment model. | [UNVERIFIED ASSUMPTION] |

### 3.3 Cryptography

| Assumption | Source evidence | Status |
|------------|-----------------|--------|
| Ed25519 signature verification (`verify_strict`) is computationally unforgeable. | `src/hsm/keystore.rs:134` — `ed25519-dalek v2.1` with `verify_strict` | Relies on correctness of `ed25519-dalek` crate |
| The manifest signature is checked before CBOR parsing — a malformed payload cannot reach the parser without first passing verification. | `src/boot/decode.rs:87-88` | Verified in source |
| CBOR parser (`minicbor v0.21`) rejects indefinite-length arrays, preventing parser-confusion attacks. | `src/boot/decode.rs:97-104`, `src/boot/decode.rs:132-133` | Verified in source — definite-length enforced by explicit `Some(n)` checks |
| SHA-256 (`sha2 v0.10`) is collision-resistant and one-way for the purposes of the audit hash chain. | `src/audit/log.rs:74` | Relies on correctness of `sha2` crate |
| The genesis hash (all-zeros) is a known, documented constant and does not constitute a secret. | `src/audit/log.rs:96-101` | Explicit design choice, not a vulnerability |
| Key material (signing key bytes) is zeroized on drop by both `ZeroizingSigningKey::drop` and `ed25519-dalek`'s own `ZeroizeOnDrop`. | `src/hsm/keystore.rs:24-33` | Verified in source |
| `SoftwareKeyStore` stores keys in heap memory protected only by a `Mutex`, not in dedicated hardware. This is a documented limitation, not a security claim. | `src/hsm/keystore.rs:49-53` | Explicitly documented limitation |

### 3.4 Memory Safety

| Assumption | Source evidence | Status |
|------------|-----------------|--------|
| The Rust compiler and `rustc` code generator produce code that upholds Rust's memory-safety guarantees for all safe code. | Global `deny(unsafe_code)` in non-feature builds (`src/lib.rs:32-35`). | Relies on Rust toolchain correctness |
| `unsafe` blocks in the `python`, `hsm`, and `wasm` features are audited and do not violate kernel object invariants. | `src/lib.rs:32-35` carve-out for those features | [UNVERIFIED ASSUMPTION] — human audit item per `CLAUDE.md` |
| `heapless` collections correctly enforce their declared capacity bounds and do not panic or access out-of-bounds memory. | Used throughout `src/` with constants from `src/types.rs` | Relies on `heapless v0.8` correctness |
| Integer overflow is detected and aborts in both dev and release builds. | `Cargo.toml:72` (`overflow-checks = true` in `[profile.release]`), `Cargo.toml:76` (`[profile.dev]`) | Verified in source — however, see §4 for the Lean modelling gap |
| `panic = "abort"` in both profiles eliminates unwinding as an attack surface. | `Cargo.toml:70`, `Cargo.toml:75` | Verified in source |
| `AuditLog` is structurally `!Send + !Sync` via `PhantomData<*mut ()>`, enforcing single-threaded use at compile time. | `src/audit/log.rs:87-93` | Verified in source |

### 3.5 Supply Chain

| Assumption | Source evidence | Status |
|------------|-----------------|--------|
| All direct dependencies are sourced exclusively from `crates.io`; unknown registries and unknown git sources are denied. | `deny.toml:27-30` | Verified in source |
| License compliance is enforced to the explicit allowlist; all others are denied. | `deny.toml:12-15` | Verified in source |
| The advisory database (`rustsec/advisory-db`) is checked for known vulnerabilities; no advisories are ignored. | `deny.toml:7-10` | Verified in source |
| `Cargo.lock` is pinned (version 3 format), preventing silent transitive dependency upgrades. | `Cargo.lock` (version 3) | Verified by lock file presence |
| Dependency versions are exact or tightly bounded; wildcard version constraints are denied. | `deny.toml:19` (`wildcards = "deny"`) | Verified in source |

### 3.6 Formal Verification

| Assumption | Source evidence | Status |
|------------|-----------------|--------|
| Lean 4 theorem `concreteDeductSpec` proves the `deduct` function satisfies `AbstractLedger.Spec` — balance monotonically decreases by exactly the requested amount, all other nodes unchanged. | `lean/LuxRefinement.lean:17-26` | Proof text present; `lake build` not yet run (see outstanding checklist in `CLAUDE.md`) |
| Lean 4 theorem `delegate_non_amplification` proves that delegation never produces a token with rights strictly exceeding the delegator's rights. | `lean/LuxRefinement.lean:28-36` | Proof text present; `lake build` not yet run |
| The Lean model uses `Nat` (unbounded), while the Rust implementation uses `u64`. Overflow at 2^64−1 is therefore **not formally modelled**. The `overflow-checks = true` runtime guard is the sole defence against this edge case. | `lean/LuxRefinement.lean` (no `UInt64` type used), `Cargo.toml:72` | Known gap — documented here as an explicit limitation |
| Kani proofs in `src/metabolism/ledger.rs` and `src/auth/capability.rs` close the gap between the Lean model and the compiled binary. | `lean/LuxRefinement.lean:10-14` | [UNVERIFIED ASSUMPTION] — Kani harness existence confirmed in comments but not independently executed |

---

## 4. Out-of-Scope Threats

| Threat | Why excluded | Mitigation notes |
|--------|-------------|-----------------|
| Physical hardware attacks (cold-boot, DMA, probing) | Lux is a software kernel; no hardware countermeasures are implemented. | Requires a platform TEE or HSM integration (`hsm` feature + `YubiHsmProvider` or `Pkcs11HsmProvider`, per `src/hsm/keystore.rs:55-57`) |
| Side-channel attacks (cache-timing, Spectre/Meltdown) | No constant-time code paths enforced outside Ed25519 library. | `verify_strict` in `ed25519-dalek` is constant-time for the signature check; other computations are not analysed for timing. [UNVERIFIED ASSUMPTION] |
| Kernel API caller misbehaviour (providing incorrect `timestamp` to `AuditLog::append`) | The kernel does not own a hardware clock; it cannot verify caller-supplied timestamps. | See §5 (Audit Log Assumptions). Callers are trusted to supply a monotonic counter. |
| Host OS compromise in `std` feature builds | Kernel state lives in OS-managed memory; a compromised OS can read or overwrite it. | Deploy in a TEE or on bare metal with `no_std` build when OS trust is not established. |
| Compiler/toolchain supply-chain attack (malicious `rustc`) | Toolchain is outside the Lux trust boundary. | Reproducible builds and toolchain pinning (`rust-version = "1.78"` in `Cargo.toml:8`) narrow the window; no further mitigations in-kernel. |
| Wasmtime sandbox escape | WASM isolation depends entirely on `wasmtime` v45 correctness. | Capability tokens are never serialised into guest memory (`src/wasm/mod.rs:24-28`), limiting blast radius. Wasmtime CVEs must be tracked and patched. |
| Denial of service via nonce exhaustion | Exhausting all 256 nonces in the current generation blocks further capability issuance until `rotate_generation` is called. | Callers are responsible for timely generation rotation. This is fail-closed (I1) behaviour by design (`src/types.rs:20-21`). |
| Denial of service via audit log saturation | When `MAX_AUDIT_EVENTS` (512) is reached, new events are silently discarded. | Old events are preserved (fail-closed), but the loss of new events is undetected by the kernel. Operators must drain or persist logs externally. |
| Multi-principal concurrent access | `AuditLog` is `!Send + !Sync`; the kernel assumes single-threaded execution. | `src/audit/log.rs:83-86` documents that multi-core support requires re-evaluation of this constraint. [UNVERIFIED ASSUMPTION] for multi-core deployments. |

---

## 5. Audit Log Assumptions

The audit log (`src/audit/log.rs`) is a security primitive used as evidence for
post-hoc accountability.  The following assumptions govern its security claims:

**What is guaranteed:**

- **Append-only structure:** No `clear`, `remove`, or mutation path exists for
  existing events at the API level (`src/audit/log.rs:1-9`).
- **Hash chain integrity:** Each event's `hash` field is
  `SHA-256(prev_hash || kind_u8 || actor_u32 || timestamp_u64 || outcome_u8)`,
  linking every event to its predecessor (`src/audit/log.rs:24-41`).
- **Genesis anchor:** The first event's predecessor hash is all-zeros, a
  documented constant (`src/audit/log.rs:96-101`).
- **Capacity overflow is fail-closed:** When the 512-event buffer is full,
  new events are dropped; old events are never overwritten (`src/audit/log.rs:8-9`).
- **Thread isolation:** `!Send + !Sync` prevents use across threads without
  `unsafe` (`src/audit/log.rs:87-93`).

**What is NOT guaranteed:**

- **Timestamp authenticity:** The `timestamp` field is caller-supplied
  (`src/audit/log.rs:113-116`). The kernel has no trusted clock.  A malicious
  or buggy caller can supply any value, including zero or a far-future timestamp.
  The hash chain guarantees ordering of recorded events but not their
  correspondence to real time.
- **Persistence:** The log is in-memory only. Power loss, process restart, or OS
  memory pressure destroys the log. External persistence is the caller's
  responsibility.
- **Completeness after overflow:** Once the 512-event cap is reached, subsequent
  security-relevant events are silently lost.  Operators must monitor log
  utilisation and drain the buffer before capacity is reached.
- **Cryptographic non-repudiation:** The hash chain detects in-memory tampering
  but does not produce a signed root.  An attacker with write access to kernel
  memory can reconstruct a valid chain over altered events.

---

## 6. What the TCB Does NOT Claim

The following properties are commonly expected of security kernels but are
explicitly NOT claimed for Lux v1.0:

| Non-claim | Explanation |
|-----------|-------------|
| Hardware-backed key isolation | Default `SoftwareKeyStore` stores Ed25519 keys in OS heap memory under a `Mutex`. Keys are zeroized on drop but are accessible to any code sharing the address space. (`src/hsm/keystore.rs:49-53`) |
| Real TPM attestation by default | Default `NullTpm` produces an all-zeros quote. Real TPM attestation requires the `tpm` feature and a physical TPM 2.0 device. (`src/tpm/attestation.rs:1-14`) |
| Trusted timestamps | No hardware clock. Timestamps in the audit log are caller-supplied. (`src/audit/log.rs:113-116`) |
| Formal proof of overflow safety at `u64` boundary | Lean proofs use unbounded `Nat`; the gap at 2^64−1 is only covered by the runtime `overflow-checks = true` flag. (`lean/LuxRefinement.lean`, `Cargo.toml:72`) |
| Mechanically verified Lean proofs | `lake build` has not been independently run. Lean proof text is present but not confirmed to compile. (`CLAUDE.md` outstanding checklist) |
| Externally audited security | The codebase is internally reviewed only. Three specific human-review items and the `lake build` check remain outstanding per `CLAUDE.md`. |
| Constant-time execution outside signature verification | Only `ed25519-dalek`'s `verify_strict` is documented as constant-time. Policy checks, nonce scans, and hash computation are not analysed for timing side-channels. |
| WASM sandbox correctness | The WASM execution path depends entirely on `wasmtime v45` being free of sandbox escapes. Lux provides only ABI-level isolation (opaque handles). (`src/wasm/mod.rs:1-54`) |
| Multi-core safety | The kernel is designed for single-threaded execution. `AuditLog` is `!Send + !Sync`. Adapting for multi-core execution requires architectural review. (`src/audit/log.rs:83-86`) |
| `unsafe` code in optional features is audited | The `#![deny(unsafe_code)]` carve-out for `python`, `hsm`, and `wasm` features means `unsafe` blocks in those modules have not been independently reviewed. (`src/lib.rs:32-35`, `CLAUDE.md`) |

---

## 7. Revision Checklist

When any assumption in this document changes, the following items MUST be
updated before the change is merged:

| If this changes... | Update these items |
|--------------------|-------------------|
| `src/auth/policy.rs::Policy::check` logic | §2 (trusted components table), §3.4 (memory safety), re-run the Audit Prompt Loop from `CLAUDE.md` for all I1–I4 call sites |
| `src/auth/capability.rs::Capability::authorises` | §2 (trusted components table), §3.3 (cryptography — generation and rights semantics), `CLAUDE.md` human-review checklist item 1 |
| `src/metabolism/ledger.rs::Ledger::deduct` | §2 (trusted components table), §3.6 (formal verification — `concreteDeductSpec` proof must be re-checked), Lean model in `lean/LuxRefinement.lean` |
| `src/topology/graph.rs::OperationalGraph::traverse` | §2 (trusted components table), §3.4 (memory safety — bitmask bounds), `CLAUDE.md` human-review checklist item 2 |
| `src/audit/log.rs` | §2 (trusted components table), §5 (Audit Log Assumptions) in full |
| `src/types.rs` constants (`MAX_*`, `NONCE_WINDOW`) | §2 (heapless row), §4 (nonce exhaustion and audit saturation rows), §3.4 (stack size assumption) |
| Any `Cargo.toml` dependency version bump | §3.5 (supply chain), §3.3 (cryptography — if `ed25519-dalek`, `sha2`, or `minicbor` change) |
| `Cargo.toml` profile settings (`overflow-checks`, `panic`, `lto`) | §3.4 (memory safety — all relevant rows) |
| Adding a new feature flag that enables `std` or `unsafe_code` | §3.2 (OS assumptions), §6 (non-claims — `unsafe` audit item) |
| `lean/LuxRefinement.lean` or any `lean/` file | §3.6 (formal verification) in full; run `lake build` and record result |
| `deny.toml` | §3.5 (supply chain) in full |
| `src/wasm/` | §4 (WASM sandbox escape row), §6 (WASM non-claim row), §2 (WasmShim row) |
| `src/hsm/keystore.rs` | §3.3 (key management assumptions), §6 (hardware-backed key isolation non-claim) |
| `src/tpm/` | §3.1 (hardware — TPM rows), §6 (TPM non-claim row) |
| Introducing multi-threaded execution | §3.4 (`!Send + !Sync` row), §4 (concurrent access row), §6 (multi-core non-claim row) must ALL be re-evaluated and this document re-issued before merge |
