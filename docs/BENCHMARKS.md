# Lux Kernel — Benchmark Results

**Benchmark suite:** Criterion 0.5 (statistical, 100 samples per bench)  
**CPU:** Intel(R) Xeon(R) Processor @ 2.80GHz  
**Profile:** `cargo bench` (release with LTO)

---

## How to Run

```sh
# Full benchmark suite
cargo bench

# Single benchmark
cargo bench -- <benchmark_name>

# Output HTML report to target/criterion/
cargo bench --features html_reports
```

---

## Results (2026-Q2 baseline)

| Benchmark | Function Under Test | Time (median) | Notes |
|-----------|--------------------|--------------:|-------|
| `queue_enqueue_dequeue_256` | `WorkQueue::enqueue` + `dequeue` × 256 | ~5.1 µs | Bounded 256-item queue, full cycle |
| `policy_check` | `Policy::check` (single cap, success path) | ~970 ns | Includes nonce record + audit append |
| `ledger_deduct` | `Ledger::seed` + `Ledger::deduct` | ~14 ns | Single-node deduction, O(1) linear map |
| `topology_traverse` | `OperationalGraph::traverse` | ~1.0 µs | Two-node graph, declared edge, includes audit |
| `audit_append` | `AuditLog::append` | ~1.0 µs | SHA-256 hash-chain append, one event |

### Raw Criterion Output

```
queue_enqueue_dequeue_256  time: [5.1054 µs  5.1274 µs  5.1498 µs]
policy_check               time: [963.30 ns  970.10 ns  978.61 ns]
ledger_deduct              time: [13.884 ns   13.940 ns  14.003 ns]
topology_traverse          time: [981.26 ns    1.0056 µs  1.0328 µs]
audit_append               time: [1.0183 µs   1.0308 µs  1.0449 µs]
```

---

## Design Notes

### Why `policy_check` includes audit overhead

`Policy::check` calls `AuditLog::append` internally (fail-closed audit contract).
The benchmark therefore measures the total cost of a policy gate including the
SHA-256 hash-chain append (~1 µs).  The raw capability check without audit is
approximately 10–50 ns.

### Why `ledger_deduct` is much faster than `policy_check`

`Ledger::deduct` is a single `heapless::LinearMap` lookup + `checked_sub`.
It does not append to the audit log directly; the caller (e.g., `QuotaEnforcer`)
is responsible for audit recording.  The ~14 ns figure is the pure accounting cost.

### Throughput at system scale

| Scenario | Throughput (est.) |
|----------|-------------------|
| Policy gate decisions (single thread) | ~1M checks/second |
| Ledger deductions (single thread) | ~70M deductions/second |
| Topology traversals (single thread) | ~1M traversals/second |
| Audit log appends to capacity (512 events) | ~0.5 ms total |

These figures are indicative baselines for single-threaded, in-process use.
Real-world throughput depends on caller overhead, cache state, and concurrency model.
