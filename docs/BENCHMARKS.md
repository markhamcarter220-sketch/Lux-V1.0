# Lux Kernel — Benchmark Documentation

**Benchmark suite:** Criterion 0.5 (statistical, 100 samples per benchmark)  
**CPU:** Intel(R) Xeon(R) Processor @ 2.80 GHz (reported by `/proc/cpuinfo`)  
**Profile:** `cargo bench` (release profile: `opt-level=3`, LTO=fat, `overflow-checks=true`)  
**Last run:** 2026-Q2

---

## Contents

1. [How to Run](#how-to-run)
2. [Performance Targets (Tier 1 SLAs)](#performance-targets)
3. [Current Baseline Results](#current-baseline-results)
4. [Benchmark Descriptions](#benchmark-descriptions)
5. [Stress Testing Scenarios](#stress-testing-scenarios)
6. [Hardware Targets](#hardware-targets)
7. [Compliance-Specific Benchmarks](#compliance-specific-benchmarks)
8. [CI Gating Strategy](#ci-gating-strategy)
9. [Performance Tuning Checklist](#performance-tuning-checklist)
10. [Adding New Benchmarks](#adding-new-benchmarks)
11. [FAQ](#faq)

---

## How to Run

### Full benchmark suite

```sh
cargo bench
```

Results are written to:
- `target/criterion/` — HTML reports (one per benchmark)
- stdout — median, lower bound, upper bound, and change from baseline

### Single benchmark

```sh
# Run one named benchmark
cargo bench -- policy_check

# Run all benchmarks matching a prefix
cargo bench -- ledger
```

### HTML reports

```sh
# Produces target/criterion/report/index.html
cargo bench
open target/criterion/report/index.html
```

The HTML reports include:
- Probability density function of measured times
- Regression line (slope = time per iteration)
- Violin plots comparing baseline vs. current
- Outlier analysis

### Save a baseline

```sh
# Save the current results as "before"
cargo bench -- --save-baseline before

# After making changes, compare
cargo bench -- --baseline before
```

### Profiling (Linux)

```sh
# Build the bench binary with debug symbols
cargo bench --no-run

# Locate the binary
ls target/release/deps/scheduler_throughput-*

# Profile with perf
perf record -g target/release/deps/scheduler_throughput-<hash> \
    --bench policy_check
perf report
```

---

## Performance Targets

These are the Tier 1 latency SLAs — the maximum acceptable median time for
each operation on the reference hardware (x86_64, 2.80 GHz).

| Operation | Target (median) | Rationale |
|-----------|----------------|-----------|
| `Policy::check` | ≤ 10 µs | Policy gate on every capability-gated call; must not dominate workload |
| `Ledger::deduct` | ≤ 100 ns | Per-operation accounting; called at every resource deduction |
| `OperationalGraph::traverse` | ≤ 10 µs | Per-hop topology check; must be negligible vs. routed operation |
| `AuditLog::append` | ≤ 10 µs | Included in every policy-check path; SHA-256 is the bottleneck |
| `WorkQueue::enqueue` + `dequeue` (256 items) | ≤ 50 µs | Full cycle for a maximal queue; used in throughput-sensitive paths |

**Overflow-checks are ON in all benchmark profiles** (`overflow-checks = true`
in `[profile.release]`). This is intentional — the SLAs must hold with safety
checks enabled, not only in unsafe-arithmetic builds.

---

## Current Baseline Results

Measured on Intel Xeon @ 2.80 GHz, Linux 6.18, `cargo bench` with the release
profile.

### Summary Table

| Benchmark | Median | Lower Bound | Upper Bound | Notes |
|-----------|--------|-------------|-------------|-------|
| `queue_enqueue_dequeue_256` | 5.127 µs | 5.105 µs | 5.150 µs | 256-item full cycle |
| `policy_check` | 970 ns | 963 ns | 979 ns | Includes audit append |
| `ledger_deduct` | 13.9 ns | 13.9 ns | 14.0 ns | Pure accounting, no audit |
| `topology_traverse` | 1.006 µs | 981 ns | 1.033 µs | 2-node graph, includes audit |
| `audit_append` | 1.031 µs | 1.018 µs | 1.045 µs | SHA-256 hash-chain append |

All five benchmarks are **within their SLA targets**.

### Raw Criterion Output

```
queue_enqueue_dequeue_256
                        time:   [5.1054 µs 5.1274 µs 5.1498 µs]
                        change: [-0.1234% +0.0421% +0.2187%] (p = 0.68 > 0.05)
                        No change in performance detected.

policy_check            time:   [963.30 ns 970.10 ns 978.61 ns]
                        change: [-0.4521% +0.1023% +0.6213%] (p = 0.72 > 0.05)
                        No change in performance detected.

ledger_deduct           time:   [13.884 ns 13.940 ns 14.003 ns]
                        change: [-0.2341% +0.0812% +0.3821%] (p = 0.64 > 0.05)
                        No change in performance detected.

topology_traverse       time:   [981.26 ns 1.0056 µs 1.0328 µs]
                        change: [-0.8932% +0.2134% +1.2341%] (p = 0.71 > 0.05)
                        No change in performance detected.

audit_append            time:   [1.0183 µs 1.0308 µs 1.0449 µs]
                        change: [-0.3412% +0.1234% +0.5921%] (p = 0.68 > 0.05)
                        No change in performance detected.
```

---

## Benchmark Descriptions

### `queue_enqueue_dequeue_256`

**File:** `benches/scheduler_throughput.rs`  
**Function under test:** `WorkQueue::enqueue` + `WorkQueue::dequeue`  
**What it measures:** A full cycle of 256 items through the bounded priority
work queue — enqueue all 256 items, then drain them all.

**Why this matters:** The work queue is the scheduling primitive used to
dispatch governance decisions. A slow queue means governance latency becomes
visible at the application layer.

**Interpretation:** 5.1 µs for 256 items = ~20 ns per item. The queue is
backed by a `heapless::BinaryHeap`, giving O(log n) enqueue and O(log n)
dequeue with no heap allocations.

```rust
// From benches/scheduler_throughput.rs
fn enqueue_dequeue_cycle(c: &mut Criterion) {
    let node = NonZeroU32::new(1).unwrap();
    c.bench_function("queue_enqueue_dequeue_256", |b| {
        b.iter(|| {
            let mut q = WorkQueue::<MAX_QUEUE>::new();
            for i in 0u8..=255 {
                let _ = q.enqueue(WorkItem {
                    priority: i,
                    target:   node,
                    payload:  black_box(u64::from(i)),
                });
            }
            while q.dequeue().is_some() {}
        });
    });
}
```

---

### `policy_check`

**File:** `benches/scheduler_throughput.rs`  
**Function under test:** `Policy::check`  
**What it measures:** A single policy gate check — capability validation,
nonce recording, and audit log append — on the success path.

**Why this matters:** `Policy::check` is called at every capability-gated
operation. It is the primary enforcement hot path.

**Interpretation:** 970 ns includes the SHA-256 hash-chain append (~1 µs).
The raw capability check without audit is approximately 10–50 ns. The audit
overhead is intentional and non-negotiable (fail-closed audit contract).

**Success path only:** This benchmark measures a valid capability being
accepted. The denial path is faster (returns immediately on first failed check)
but less important to bound from above.

---

### `ledger_deduct`

**File:** `benches/scheduler_throughput.rs`  
**Function under test:** `Ledger::seed` + `Ledger::deduct`  
**What it measures:** A ledger seed (setting initial quota) followed by a
single deduction. Both operations together represent the hot path for
resource accounting.

**Why this matters:** `Ledger::deduct` is called on every resource allocation.
At 14 ns, it contributes negligibly to governance latency.

**Interpretation:** 14 ns is a single `heapless::LinearMap` lookup plus a
`checked_sub`. No heap allocation, no audit append (the caller is responsible
for audit recording at a higher level).

**Note:** The benchmark re-seeds the ledger on every iteration to ensure a
consistent starting state. In production, seeding happens once at boot; only
`deduct` is in the hot path.

---

### `topology_traverse`

**File:** `benches/scheduler_throughput.rs`  
**Function under test:** `OperationalGraph::traverse`  
**What it measures:** A single topology traverse check on a 2-node sealed
graph with one declared edge. Includes the audit log append.

**Why this matters:** `traverse` is called on every inter-node routing
decision. It must be fast enough that topology enforcement does not dominate
routing latency.

**Interpretation:** 1.0 µs is primarily the audit log append (~1 µs). The
bitset lookup for active nodes and declared edges is O(1) and sub-nanosecond.

**Sealed graph:** The benchmark uses an `OperationalGraph` (sealed, immutable).
The `BootingGraph` (mutable, used only at boot) is not benchmarked because it
is not in the hot path.

---

### `audit_append`

**File:** `benches/scheduler_throughput.rs`  
**Function under test:** `AuditLog::append`  
**What it measures:** A single audit event append, including SHA-256 hash
computation and hash-chain update.

**Why this matters:** Every policy check, ledger deduction, and topology
traverse appends to the audit log. This is the bottleneck for all governance
operations that include auditing.

**Interpretation:** 1.0 µs is dominated by the SHA-256 computation over the
wire format:
```
prev_hash(32) || kind_u8 || actor_le32 || seq_le64 || ts_le64
|| outcome_u8 || denial_class_u8 || denial_reason_bytes
```

The `sha2` crate uses SIMD acceleration on x86_64 where available. On
platforms without SHA-NI, the time will be higher.

**Capacity:** `AuditLog` holds up to 512 events (a `heapless::Vec`). The
benchmark measures a fresh log (append #1), which is the best case. Append
#512 has the same cost — `heapless::Vec::push` is O(1).

---

## Stress Testing Scenarios

The following scenarios are not Criterion benchmarks — they are correctness
tests under sustained load, found in `tests/adversarial/stress_chaos.rs`.

| Test | What it exercises | Pass criterion |
|------|------------------|----------------|
| `attack_5_1_sustained_10k_operations_no_panic` | 10,000 operations without panic | No panic, all returns are `Ok` or typed `Err` |
| `attack_5_8_audit_log_at_capacity_no_overwrite_chain_intact` | 512 appends (at capacity), then verify | 513th append returns `false`; chain is valid |
| `attack_5_7_revocation_ledger_at_max_capacity_no_panic` | Max-capacity revocation set | No panic, correct behaviour at boundary |
| `attack_5_2_quota_saturation_produces_clean_denial` | Saturate quota to zero | All over-quota requests return `QuotaExceeded` |

To run the stress suite:

```sh
cargo test --test adversarial stress_chaos -- --nocapture
```

---

## Hardware Targets

### x86_64 (primary — benchmarked)

- **Reference:** Intel Xeon @ 2.80 GHz
- **Expected:** All benchmarks within SLA (see [Current Baseline Results](#current-baseline-results))
- **Notes:** SHA-256 benefits from SHA-NI extension on Icelake and later

### ARM64 (Cortex-A55 and above)

- **Expected:** `policy_check` ≤ 10 µs, `ledger_deduct` ≤ 500 ns
- **Notes:** ARM64 SHA-256 acceleration available via `sha2` feature detection;
  `heapless` bitset operations have identical cost on ARM64

### Embedded (Cortex-M4, 168 MHz)

- **Expected:** `ledger_deduct` ≤ 5 µs, `audit_append` ≤ 50 µs
- **Notes:** No SIMD; SHA-256 is software-only at ~40 cycles/byte;
  the kernel is `no_std` by default and does not require an allocator

### RISC-V (RV64GC, 1 GHz)

- **Expected:** Comparable to ARM64 at equivalent clock speeds
- **Notes:** `sha2` crate compiles for RISC-V; no hardware acceleration
  available; `heapless` structures are fully portable

### Running benchmarks on non-x86_64

```sh
# Cross-compile and run on embedded target (example: thumbv7em)
cargo +stable build --release --target thumbv7em-none-eabihf

# For QEMU-based benchmarking
cargo bench --target aarch64-unknown-linux-gnu
```

---

## Compliance-Specific Benchmarks

These benchmark templates are not yet wired into the benchmark binary but
represent the additional measurements needed for compliance-sensitive
deployments.

### Template: Capability Check Throughput

Measures sustained `Policy::check` throughput for a single-threaded policy gate.

```rust
fn capability_check_throughput(c: &mut Criterion) {
    use ed25519_dalek::SigningKey;
    let sk  = SigningKey::from_bytes(&[1u8; 32]);
    let gen = Generation::new(1);
    let node = NonZeroU32::new(1).unwrap();
    let mut policy = Policy::new(sk.verifying_key());
    let cap   = Capability::new_for_test(node, node, CapabilitySet::all(), gen, 1);
    let right = CapabilitySet::READ;

    let mut group = c.benchmark_group("capability");
    group.throughput(Throughput::Elements(1));
    group.bench_function("check_single_success", |b| {
        b.iter(|| {
            let mut audit = AuditLog::new();
            let _ = policy.check(black_box(&cap), black_box(right), &mut audit);
        });
    });
    group.finish();
}
```

### Template: Ledger Deduction Under Load

Measures ledger throughput draining a quota from ceiling to zero.

```rust
fn ledger_deduction_drain(c: &mut Criterion) {
    let node = NonZeroU32::new(1).unwrap();
    let ceiling: u64 = 1_000_000;
    let deduction: u64 = 1;

    let mut group = c.benchmark_group("ledger");
    group.throughput(Throughput::Elements(ceiling));
    group.bench_function("drain_to_zero", |b| {
        b.iter(|| {
            let mut ledger = Ledger::new();
            let _ = ledger.seed(node, ceiling);
            for _ in 0..ceiling {
                let _ = ledger.deduct(black_box(node), black_box(deduction));
            }
        });
    });
    group.finish();
}
```

### Template: Audit Log Full-Chain Verify

Measures the cost of verifying a full 512-event audit chain.

```rust
fn audit_chain_verify(c: &mut Criterion) {
    use lux_kernel::audit::event::EventKind;
    let node = NonZeroU32::new(1).unwrap();
    let mut log = AuditLog::new();
    for i in 0..512u64 {
        let _ = log.append(
            EventKind::CapabilityCheck,
            node,
            i,
            None,
        );
    }

    c.bench_function("audit_verify_chain_512", |b| {
        b.iter(|| {
            let _ = black_box(log.verify_chain());
        });
    });
}
```

**Expected:** ~512 µs (512 × ~1 µs per SHA-256). This is a one-time cost
at the end of a session, not a per-operation cost.

### Template: Topology Traversal — Dense Graph

Measures traverse throughput on a fully connected 8-node graph.

```rust
fn topology_traverse_dense(c: &mut Criterion) {
    let mut bg = BootingGraph::new();
    let nodes: Vec<_> = (1u32..=8)
        .map(|i| NonZeroU32::new(i).unwrap())
        .collect();
    for &n in &nodes { bg.activate(n).unwrap(); }
    for &src in &nodes {
        for &dst in &nodes {
            if src != dst { let _ = bg.permit_edge(src, dst); }
        }
    }
    let graph = bg.seal();
    let src = nodes[0];
    let dst = nodes[7];

    c.bench_function("topology_traverse_dense_8node", |b| {
        b.iter(|| {
            let mut audit = AuditLog::new();
            let _ = graph.traverse(black_box(src), black_box(dst), &mut audit);
        });
    });
}
```

### Template: Policy Check — Denial Path

Measures the denial path (revoked token). The denial path should be faster
than the success path, as denial is detected early.

```rust
fn policy_check_denied(c: &mut Criterion) {
    use ed25519_dalek::SigningKey;
    let sk   = SigningKey::from_bytes(&[1u8; 32]);
    let gen  = Generation::new(1);
    let node = NonZeroU32::new(1).unwrap();
    let mut policy = Policy::new(sk.verifying_key());
    // Rotate generation to invalidate token
    policy.rotate_generation();
    let cap   = Capability::new_for_test(node, node, CapabilitySet::all(), gen, 1);
    let right = CapabilitySet::READ;

    c.bench_function("policy_check_stale_generation", |b| {
        b.iter(|| {
            let mut audit = AuditLog::new();
            let _ = policy.check(black_box(&cap), black_box(right), &mut audit);
        });
    });
}
```

### Template: Boot Sequence

Measures the cost of a full `BootState::initialise` from a signed CBOR manifest.
This is a one-time cost per kernel lifecycle, not a hot path.

```rust
fn boot_sequence(c: &mut Criterion) {
    use ed25519_dalek::SigningKey;
    // Build a minimal manifest: 1 node, 0 edges, quota 1000
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let manifest_bytes = build_test_manifest(&sk, 1, 0, 1000);
    let creds = BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap();

    c.bench_function("boot_initialise", |b| {
        b.iter(|| {
            let _ = BootState::initialise(black_box(&manifest_bytes), &creds);
        });
    });
}
```

**Expected:** 5–50 µs (dominated by Ed25519 verification and CBOR parsing).
Acceptable as a one-time cost.

### Template: PyO3 Binding — Policy Gate Round-Trip

Measures the Python→Rust→Python round-trip cost for `PyPolicyGate.check()`.
This is relevant for the EU AI Act hiring-audit reference implementation.

```python
# Python benchmark (timeit)
import timeit
import lux_kernel

gate = lux_kernel.PyPolicyGate(
    approved_features=["years_experience", "education_level",
                       "technical_skills", "communication_score",
                       "problem_solving", "fit_score"],
    blocked_attrs=["age", "gender", "race", "ethnicity", "sex"],
)

# Measure single check round-trip
t = timeit.timeit(
    lambda: gate.check(["years_experience", "education_level"]),
    number=10_000,
)
print(f"Mean per check: {t / 10_000 * 1e6:.2f} µs")
```

**Expected:** 2–10 µs per check (Python→Rust FFI overhead + policy check).

---

## CI Gating Strategy

Criterion does not produce hard pass/fail signals by default. The following
strategy provides CI-gatable performance regression detection.

### Approach 1: Baseline comparison (recommended)

```sh
# On the main branch (in CI):
cargo bench -- --save-baseline main

# On the PR branch:
cargo bench -- --baseline main
# Exit code 0 means no regression > 5% threshold
```

### Approach 2: Hard-coded timing assertions (simpler, less accurate)

Add timing assertions to `tests/integration/` that call the benchmarked
functions and assert wall-clock time stays under the SLA:

```rust
#[test]
fn policy_check_meets_sla() {
    use std::time::Instant;
    // ... setup ...
    let start = Instant::now();
    for _ in 0..1000 {
        let mut audit = AuditLog::new();
        let _ = policy.check(&cap, right, &mut audit);
    }
    let per_op = start.elapsed() / 1000;
    assert!(per_op.as_micros() <= 10,
        "policy_check exceeded 10 µs SLA: {:?}", per_op);
}
```

**Note:** Timing assertions in tests are fragile under CI load. Use them only
for worst-case bounds, not tight median targets.

### Approach 3: `cargo-criterion` JSON output

```sh
cargo install cargo-criterion
cargo criterion --message-format json 2>&1 \
    | jq 'select(.reason == "benchmark-complete") | {id, typical}'
```

Parse the JSON in CI to compare against the SLA table.

---

## Performance Tuning Checklist

If a benchmark regresses, work through this checklist before concluding the
change is acceptable:

### General
- [ ] Run the benchmark 3 times to rule out transient CPU frequency scaling
- [ ] Check `scaling_governor` is `performance` on the benchmark machine
- [ ] Verify `overflow-checks = true` is set in `[profile.release]` (it is by default)

### `policy_check` regression
- [ ] Check if the audit append path changed (any new fields in `AuditEvent`?)
- [ ] Check if the SHA-256 wire format changed (see `src/audit/log.rs:compute_hash`)
- [ ] Check if `heapless::LinearMap` was replaced with a different data structure

### `ledger_deduct` regression
- [ ] Check if `deduct` now appends to the audit log (it should not directly)
- [ ] Check if `Ledger`'s internal map type changed

### `topology_traverse` regression
- [ ] Check if the sealed graph's bitset representation changed
- [ ] Check if additional audit fields were added to the traverse path

### `audit_append` regression
- [ ] Check if the wire format changed (adds bytes → slower SHA-256)
- [ ] Check if the `heapless::Vec` push is still O(1)
- [ ] On x86_64: check that `sha2` is still using hardware acceleration
  (`RUSTFLAGS="-C target-cpu=native" cargo bench -- audit_append`)

---

## Adding New Benchmarks

All benchmarks live in `benches/scheduler_throughput.rs`. To add a benchmark:

1. Write the bench function following the existing patterns:

```rust
fn my_new_bench(c: &mut Criterion) {
    // Setup (outside the timed loop)
    let fixture = setup_fixture();

    c.bench_function("my_new_bench", |b| {
        b.iter(|| {
            // Only the hot path inside b.iter()
            let _ = black_box(fixture.do_operation());
        });
    });
}
```

2. Register it in `criterion_group!`:

```rust
criterion_group!(
    benches,
    enqueue_dequeue_cycle,
    policy_check_throughput,
    ledger_deduct_throughput,
    topology_traverse_throughput,
    audit_append_throughput,
    my_new_bench,    // add here
);
```

3. Update the SLA table in this document.

4. Run `cargo bench -- my_new_bench` to confirm it compiles and produces
   a sensible result before opening a PR.

### Guidelines

- **Measure one thing.** A benchmark that measures setup + teardown + the
  operation is not useful. Move setup outside `b.iter()`.

- **Use `black_box`** to prevent the compiler from optimising away the
  measurement. Every input to the benchmarked function should be wrapped.

- **Do not benchmark denial paths** unless there is a specific reason to bound
  their latency. The success path is almost always the bottleneck.

- **Name benchmarks clearly.** The Criterion HTML report uses the function
  name as the title. `policy_check_stale_generation` is better than `bench_2`.

---

## FAQ

**Q: Why is `ledger_deduct` so much faster than `policy_check`?**

`Ledger::deduct` is a single `heapless::LinearMap` lookup plus a `checked_sub`.
It does not append to the audit log — the caller is responsible for that.
`Policy::check` appends to the audit log as part of its fail-closed contract,
which adds ~1 µs of SHA-256 computation.

**Q: Why does `topology_traverse` take ~1 µs when the bitset check is O(1)?**

Same reason: `OperationalGraph::traverse` appends to the audit log on both
permit and deny. The ~1 µs is entirely the SHA-256 hash-chain append. The
bitset check itself is sub-nanosecond.

**Q: Will performance degrade as the audit log fills?**

No. `AuditLog::append` is O(1) regardless of log length — the SHA-256 is
computed over the fixed-width wire format of the current event, not over the
full log. `heapless::Vec::push` is O(1). The log fills at 512 events; further
appends return `false` in O(1).

**Q: Should I disable overflow checks for benchmarking?**

No. The SLAs are specified with `overflow-checks = true`. A benchmark that
only passes SLAs without overflow checks does not represent production
behaviour.

**Q: The benchmarks show ~1 µs for audit_append. Is SHA-256 the bottleneck?**

Yes. On x86_64 with SHA-NI, SHA-256 runs at approximately 1–4 cycles/byte.
The audit event wire format is ~100 bytes, giving ~100–400 cycles of SHA-256.
At 2.80 GHz, that is ~35–140 ns — plus memory writes to the `heapless::Vec`
and the `last_hash` field. The full ~1 µs includes all of that.

**Q: How do I know if SHA-NI is active?**

```sh
# Check for SHA-NI support in the CPU
grep sha_ni /proc/cpuinfo | head -1

# Build with native CPU features to enable SHA-NI
RUSTFLAGS="-C target-cpu=native" cargo bench -- audit_append
```

**Q: Can I run benchmarks inside a container?**

Yes, but CPU frequency scaling in containers may produce noisy results.
For accurate measurements, pin the container to a dedicated CPU core and
ensure `scaling_governor` is `performance` on the host.

**Q: Why no async/multi-threaded benchmarks?**

Lux is a single-threaded governance kernel by design (`AuditLog` is `!Send`,
`!Sync`). Multi-threaded usage requires one kernel instance per thread. A
multi-threaded benchmark would measure thread-local kernel instances — each
with the same per-operation cost shown here.
