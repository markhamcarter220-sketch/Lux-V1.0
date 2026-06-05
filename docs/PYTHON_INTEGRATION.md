# Python Integration — Lux Kernel PyO3 Bindings

**Status:** Implemented  
**Date:** 2026-Q2  
**Feature flag:** `python`  
**Files:** `src/python/mod.rs`, `src/python/audit.rs`, `src/python/policy.rs`  
**Python wrappers:** `hiring-audit/audit_log.py`, `hiring-audit/policy_gate.py`

---

## Purpose

Replaces the Python mock implementations of the policy gate and audit log in
`hiring-audit/` with real calls into the Lux Rust kernel via PyO3 Python
bindings.

The Python layer retains the original domain API used by `phase2.py` (no
changes to callers). The cryptographic hash chain, policy enforcement, and
fail-closed semantics are now enforced by the Rust kernel.

---

## Build

```sh
bash hiring-audit/build_lux.sh
```

This installs `maturin` and runs `maturin develop --features python` from the
project root. The `.so` extension is installed into the active virtual
environment.

To run the full hiring pipeline after building:

```sh
source .venv/bin/activate
cd hiring-audit
python3 main.py    # Phase 1: generate candidates, train model
python3 phase2.py  # Phase 2: policy gate, audit log, bias tests
```

---

## Architecture

```
phase2.py
├── PolicyGate.check(features_used)  →  PyPolicyGate.check(feature_names)  [Rust]
│                                        └── 3 invariants enforced in Rust
│                                        └── Returns: {allowed, reason, denial_class}
└── AuditLog.append(candidate_id, ...) →  PyAuditLog.append(kind, actor, ts, ...)  [Rust]
                                           └── SHA-256 hash-chain in Rust
                                           └── verify_chain() in Rust
```

The Python wrappers are thin translators. No enforcement logic lives in Python.

---

## Sharp Edges Identified and Resolved

### EDGE A — heapless capacity (MAX_AUDIT_EVENTS)

**Problem:** `AuditLog` is backed by `heapless::Vec<AuditEvent, MAX_AUDIT_EVENTS>`.
If capacity is exceeded, `append()` returns `false` (fail-closed, no overwrite).

**Check:** `MAX_AUDIT_EVENTS = 512` in `src/types.rs`. Python mock also used 512.
The hiring demo processes 100 candidates. **No change needed.**

---

### EDGE B — denial_reason is &'static str

**Problem:** The Rust kernel's `AuditLog::append` takes
`denial_reason: Option<(DenialClass, &'static str)>`. Python strings are
heap-allocated; they cannot be coerced to `&'static str` at runtime.

**Resolution:** Four canonical denial-reason strings are defined as `&'static str`
literals in `src/python/policy.rs`:

| String | Meaning |
|--------|---------|
| `"protected attribute in feature vector"` | Exact protected-attribute match (check 1) |
| `"aliased protected attribute in feature vector"` | Substring alias match (check 2) |
| `"unapproved feature in feature vector"` | Feature not in approved list (check 3) |
| `"all approved features; no protected attributes"` | ALLOW — no denial |
| `"policy violation"` | Fallback for unknown strings |

`src/python/audit.rs` contains a `KNOWN_REASONS` compile-time table.  Incoming
Python strings are matched against it; matches return the corresponding
`&'static str` literal. Unknown strings fall back to `"policy violation"`.

The `PyPolicyGate` emits exactly these strings as `reason` in its result dict.
The Python `AuditLog` wrapper passes `result["reason"]` directly into
`PyAuditLog.append()`. The round-trip is lossless.

**Constraint for Python callers:** Do not pass arbitrary denial-reason strings
to `PyAuditLog.append()`. Use `PyPolicyGate.check()` to generate reasons.
Unknown strings are silently mapped to `"policy violation"` (not rejected) to
avoid breaking the pipeline on novel strings.

---

### EDGE C — EventKind mapping

**Problem:** The kernel's `EventKind` enum had no variants for hiring-domain
events. Governance events and hiring decisions are distinct kinds.

**Resolution:** Added two new variants to `src/audit/event.rs`:

```rust
HiringDecision  = 5,  // "hiring_decision" in JSON export
PolicyGateCheck = 6,  // "policy_gate_check" in JSON export
```

These are legitimate kernel event categories — the kernel is a general
governance substrate, and governed AI decisions are a first-class use case.
`kind_str()` updated for both. Discriminants 5 and 6 appended (no renumbering
of existing variants).

---

### EDGE D — timestamp

**Problem:** The kernel takes `timestamp: u64` (caller-supplied monotonic
counter). Python uses `time.time_ns()` which returns nanoseconds since the Unix
epoch as an integer.

**Resolution:** `time.time_ns()` fits in u64 for ~292 years from epoch.
The Python wrapper passes `time.time_ns()` directly as the timestamp. The kernel
does not validate or interpret the value — it is stored verbatim for auditability.
Documented in the `PyAuditLog.append()` docstring.

---

### EDGE E — feature name checking is dynamic

**Problem:** The Python gate checks `dict` keys against known sets.  Rust cannot
accept arbitrary Python strings as `&'static str`.

**Resolution:** `PyPolicyGate.__init__()` validates every string in
`approved_features` and `blocked_attrs` against compile-time static tables
(`KNOWN_APPROVED`, `KNOWN_BLOCKED_SUBSTRINGS`) at **construction time**.

- Valid strings are mapped to their `&'static str` counterparts and stored in
  `heapless::Vec<&'static str, 16>`.
- **Unknown strings raise `ValueError` immediately** (fail-closed: unknown
  features are rejected at construction, not silently ignored at check time).

At `check()` time the gate compares feature names against the pre-validated
`&'static str` values — no heap allocation, no dynamic dispatch.

---

### EDGE F — allowlist capacity

**Problem:** `heapless::Vec<_, N>` has a fixed compile-time capacity.

**Resolution:** Capacity is 16 for both the approved list and the blocked list.
The hiring pipeline needs 6 approved features + 5 blocked substrings = 11 total
entries across both lists. Well within capacity. Documented in `PyPolicyGate`'s
docstring; exceeding capacity raises `ValueError`.

---

### EDGE G — AuditLog is !Send

**Problem:** `AuditLog` holds `PhantomData<*mut ()>`, making it `!Send + !Sync`.
PyO3's `#[pyclass]` requires `T: Send` unless `unsendable` is specified.

**Resolution:** `PyAuditLog` uses `#[pyclass(unsendable)]`. PyO3 enforces at
runtime that the object is only used from the Python thread that created it.
Attempting to use `PyAuditLog` from a different thread raises `RuntimeError` at
the Python layer.

For the single-threaded `hiring-audit` pipeline this is irrelevant. For
multi-threaded use cases, callers must create one `PyAuditLog` per thread.

---

### EDGE H — no_std + PyO3 incompatibility

**Problem:** The kernel is `#![no_std]`. PyO3 requires `std` (it links against
the Python C API which uses `libc`).

**Resolution:** `src/lib.rs` changed from `#![no_std]` to:

```rust
#![cfg_attr(not(feature = "python"), no_std)]
```

When the `python` feature is disabled (all non-Python builds), the crate is
fully `no_std`. When `python` is enabled, the crate uses `std`. All existing
kernel code is compatible with both modes (heapless, sha2, ed25519-dalek all
support std and no_std).

---

### EDGE H (sub) — unsafe_code lint

**Problem:** PyO3's `#[pymodule]` macro generates an
`unsafe extern "C" fn PyInit_lux_kernel()` entry point — required by the
Python C ABI. The crate has `#![deny(unsafe_code)]`.

**Resolution:** `src/python/mod.rs` adds `#![allow(unsafe_code)]` at the top.
In Rust, `#[allow]` at the module level overrides `#![deny]` at the crate level.
All enforcement logic in `audit.rs` and `policy.rs` is safe Rust — only the
C ABI entry point requires `unsafe`.

---

### EDGE I — AuditLog.append() API mismatch

**Problem:** `phase2.py` calls
`log.append(candidate_id, decision, confidence, policy_allowed, policy_reason)`.
The Rust kernel's `AuditLog::append` takes
`(kind, actor, timestamp, denial: Option<(DenialClass, &'static str)>)`.
These are different APIs.

**Resolution:** The Python `AuditLog` wrapper translates the domain API to the
kernel API internally:

| Python domain parameter | Kernel parameter |
|------------------------|-----------------|
| `candidate_id` (int) | `actor: u32` |
| `decision` ("HIRE"/"REJECT") | stored in Python parallel list only |
| `confidence` (float) | stored in Python parallel list only |
| `policy_allowed` (bool) | `denial = None` if True; `Some(("halt", reason))` if False |
| `policy_reason` (str) | `denial_reason` (mapped via EDGE B static table) |
| `time.time_ns()` | `timestamp: u64` |

Domain fields (`decision`, `confidence`) that have no kernel analog are stored
in a parallel Python list (`self._domain`) for use in `save_json()`/`save_csv()`.

---

### EDGE J — export format

**Problem:** The Python mock's `to_json()` output a custom format with
`prev_hash`, `entry_hash`, and hiring-specific fields. The Rust kernel's
`export_json()` outputs a different format (kernel governance fields + hash).

**Resolution:** The Python wrapper's `to_json()` produces a combined format:

- **Metadata section** (`audit_log`): `total_entries`, `chain_valid`,
  `head_hash`, `max_capacity`, `hash_format` — all from the Rust kernel.
- **Entry section** (`entries`): domain fields (from `self._domain`) augmented
  with `entry_hash` from the kernel's canonical SHA-256.

The `prev_hash` field is removed from per-entry exports. Chain integrity is
verified atomically by `verify_chain()` rather than per-entry. `hash_format`
is set to `"SHA-256/Lux-kernel-canonical"` to document the new format.

**Wire format change:** The kernel's hash chain uses the canonical wire format:
```
prev_hash(32) || kind_u8 || actor_le32 || seq_le64 || ts_le64
|| outcome_u8 || denial_class_u8 || denial_reason_bytes
```
The Python mock used a different format. Existing `audit_log.json` files
generated by the mock have hashes that will NOT verify with the kernel.
New files generated after migration use the kernel format and verify correctly.

---

### EDGE K — PolicyResult dataclass

**Problem:** `phase2.py` accesses `result.allowed` and `result.reason` as
dataclass attributes. `PyPolicyGate.check()` returns a Python dict.

**Resolution:** The Python `PolicyGate.check()` wrapper converts the dict to
a `PolicyResult` dataclass. The `violations` field is populated best-effort
(names not in `APPROVED_FEATURES` or containing protected substrings).

---

### EDGE L — PolicyGate.stats()

**Problem:** `phase2.py` calls `gate.stats()` which returns
`{"total_checks", "allowed", "denied"}`. The Rust gate is stateless.

**Resolution:** The Python `PolicyGate` wrapper tracks call counts
(`self._checks`, `self._denied`). This is **observability only**, not
enforcement logic. The Rust gate always enforces the same invariants regardless
of these counters.

---

## Constraints for Python Callers

1. `PyAuditLog` may only be used from the thread that created it (EDGE G).
2. `PyPolicyGate` approved and blocked lists are validated against compile-time
   tables; only documented feature names are accepted (EDGE E).
3. Denial reasons passed to `PyAuditLog.append()` should be from
   `PyPolicyGate.check()` result. Unknown strings map to `"policy violation"` (EDGE B).
4. Capacity: 512 audit events, 16 approved features, 16 blocked attrs (EDGE A, F).
5. The kernel does not own a clock. `timestamp` must be supplied by the caller
   (EDGE D).

---

## Critical Path Verification

After migration, the critical path is:

```
PolicyGate.check()
  └── PyPolicyGate.check()          [Rust — 3 invariants enforced]
        └── heapless approved/blocked lookup
        └── Returns: {allowed, reason, denial_class}

AuditLog.append()
  └── PyAuditLog.append()           [Rust — SHA-256 hash chain]
        └── AuditLog::append()      [kernel core — compute_hash()]
        └── Returns: bool

AuditLog.verify_chain()
  └── PyAuditLog.verify_chain()     [Rust — full chain recomputation]
        └── AuditLog::verify_chain()  [kernel core]
```

**No Python mock enforcement logic remains in this path.**

The Python layer handles only:
- Domain API translation (candidate_id → actor, etc.)
- Parallel domain entry storage for reporting (decision, confidence)
- Statistics tracking (total_checks, allowed, denied)
- JSON/CSV formatting of the combined report
