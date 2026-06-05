//! Integration tests: Wasmtime-backed WASM executor (Phase 4, Tier 3).
//!
//! Exercises [`WasmExecutor`] end-to-end: WAT modules call the three Lux host
//! functions through the real Wasmtime runtime, and the tests verify that all
//! four kernel invariants are enforced correctly.
#![cfg(feature = "wasm")]

use core::num::NonZeroU32;

use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    metabolism::ledger::Ledger,
    topology::graph::{BootingGraph, OperationalGraph},
    types::Generation,
    wasm::{WasmExecutor, WasmShim},
    Error,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal shim: nodes 1 and 2 active, edge 1→2 permitted, node 1 has quota 1000.
fn make_shim() -> WasmShim {
    let node1 = NonZeroU32::new(1).unwrap();
    let node2 = NonZeroU32::new(2).unwrap();

    let mut booting = BootingGraph::new();
    booting.activate(node1).unwrap();
    booting.activate(node2).unwrap();
    booting.permit_edge(node1, node2).unwrap();
    let graph: OperationalGraph = booting.seal();

    let mut ledger = Ledger::new();
    ledger.seed(node1, lux_kernel::types::Quota::new(1000));

    let policy = Policy::new(Generation(0));
    WasmShim::from_parts(policy, ledger, graph)
}

/// Build a capability for node 1, with ALLOC_RESOURCE | SCHEDULE rights, generation 0.
fn make_cap() -> Capability {
    let issuer = NonZeroU32::new(1).unwrap();
    let target = NonZeroU32::new(1).unwrap();
    Capability::new_for_test(
        issuer,
        target,
        CapabilitySet::ALLOC_RESOURCE | CapabilitySet::SCHEDULE,
        Generation(0),
        42,
    )
}

// ── I2: Capability-gated ─────────────────────────────────────────────────────

/// WAT: calls lux_policy_check(0, ALLOC_RESOURCE_bits) → should return 0.
#[test]
fn executor_policy_check_permitted() -> lux_kernel::Result<()> {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim)?;
    let handle = exec
        .shim_mut()
        .register_cap(make_cap())
        .expect("table not full");
    assert_eq!(handle, 0, "first registered cap must get handle 0");

    let right_bits = CapabilitySet::ALLOC_RESOURCE.bits();
    let wat = format!(
        r#"(module
  (import "lux" "lux_policy_check" (func $check (param i32 i32) (result i32)))
  (func (export "run") (result i32)
    i32.const 0
    i32.const {right_bits}
    call $check
  )
)"#
    );
    let result = exec.call_nullary(wat.as_bytes(), "run")?;
    assert_eq!(result, 0, "valid cap with matching rights must return 0");
    Ok(())
}

/// WAT: calls lux_policy_check(99, 2) — handle 99 was never registered → -1.
#[test]
fn executor_policy_check_invalid_handle() -> lux_kernel::Result<()> {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim)?;

    let wat = br#"(module
  (import "lux" "lux_policy_check" (func $check (param i32 i32) (result i32)))
  (func (export "run") (result i32)
    i32.const 99
    i32.const 2
    call $check
  )
)"#;
    let result = exec.call_nullary(wat, "run")?;
    assert_eq!(result, -1, "invalid handle must return -1");
    Ok(())
}

// ── I3: Accountable Resources ─────────────────────────────────────────────────

/// WAT: deducts 100 from node 1 (balance 1000) → 0.
#[test]
fn executor_ledger_deduct_success() -> lux_kernel::Result<()> {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim)?;

    let wat = br#"(module
  (import "lux" "lux_ledger_deduct" (func $deduct (param i32 i64) (result i32)))
  (func (export "run") (result i32)
    i32.const 1
    i64.const 100
    call $deduct
  )
)"#;
    let result = exec.call_nullary(wat, "run")?;
    assert_eq!(result, 0, "deduction within quota must return 0");
    Ok(())
}

/// WAT: tries to deduct 2000 from node 1 (balance 1000) → 2 (quota exceeded).
#[test]
fn executor_ledger_deduct_quota_exceeded() -> lux_kernel::Result<()> {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim)?;

    let wat = br#"(module
  (import "lux" "lux_ledger_deduct" (func $deduct (param i32 i64) (result i32)))
  (func (export "run") (result i32)
    i32.const 1
    i64.const 2000
    call $deduct
  )
)"#;
    let result = exec.call_nullary(wat, "run")?;
    assert_eq!(
        result, 2,
        "over-quota deduction must return 2 (RC_QUOTA_EXCEEDED)"
    );
    Ok(())
}

/// WAT: deducts from node 99 (never seeded — no balance) → 2 (quota exceeded /
/// unknown-node treated as zero balance by the current ABI).
#[test]
fn executor_ledger_deduct_unknown_node() -> lux_kernel::Result<()> {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim)?;

    let wat = br#"(module
  (import "lux" "lux_ledger_deduct" (func $deduct (param i32 i64) (result i32)))
  (func (export "run") (result i32)
    i32.const 99
    i64.const 1
    call $deduct
  )
)"#;
    // Unknown nodes have no quota ≡ zero balance → quota exceeded (2).
    let result = exec.call_nullary(wat, "run")?;
    assert_eq!(
        result, 2,
        "unknown node (no quota) must return 2 (RC_QUOTA_EXCEEDED)"
    );
    Ok(())
}

// ── I4: Topology-Bounded ──────────────────────────────────────────────────────

/// WAT: traverses declared edge 1→2 → 0.
#[test]
fn executor_topology_traverse_permitted() -> lux_kernel::Result<()> {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim)?;

    let wat = br#"(module
  (import "lux" "lux_topology_traverse" (func $topo (param i32 i32) (result i32)))
  (func (export "run") (result i32)
    i32.const 1
    i32.const 2
    call $topo
  )
)"#;
    let result = exec.call_nullary(wat, "run")?;
    assert_eq!(result, 0, "declared edge 1→2 must return 0");
    Ok(())
}

/// WAT: traverses undeclared reverse edge 2→1 → 3 (topology violation).
#[test]
fn executor_topology_traverse_denied() -> lux_kernel::Result<()> {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim)?;

    let wat = br#"(module
  (import "lux" "lux_topology_traverse" (func $topo (param i32 i32) (result i32)))
  (func (export "run") (result i32)
    i32.const 2
    i32.const 1
    call $topo
  )
)"#;
    let result = exec.call_nullary(wat, "run")?;
    assert_eq!(
        result, 3,
        "undeclared reverse edge 2→1 must return 3 (RC_TOPO_VIOLATION)"
    );
    Ok(())
}

/// WAT: traverses from node 0 (invalid — NonZeroU32 sentinel) → -1.
#[test]
fn executor_topology_invalid_node() -> lux_kernel::Result<()> {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim)?;

    let wat = br#"(module
  (import "lux" "lux_topology_traverse" (func $topo (param i32 i32) (result i32)))
  (func (export "run") (result i32)
    i32.const 0
    i32.const 1
    call $topo
  )
)"#;
    let result = exec.call_nullary(wat, "run")?;
    assert_eq!(
        result, -1,
        "node ID 0 is invalid (NonZeroU32 sentinel) → must return -1"
    );
    Ok(())
}

// ── State persistence ─────────────────────────────────────────────────────────

/// The shim state (ledger balances) persists between `call_nullary` invocations.
///
/// Call the same WAT three times (each deducts 500 from a 1000-balance node):
/// - 1st call: 1000 → 500, returns 0
/// - 2nd call: 500 → 0, returns 0
/// - 3rd call: 0 − 500 underflow, returns 2
#[test]
fn executor_state_persists_across_calls() -> lux_kernel::Result<()> {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim)?;

    let wat = br#"(module
  (import "lux" "lux_ledger_deduct" (func $deduct (param i32 i64) (result i32)))
  (func (export "run") (result i32)
    i32.const 1
    i64.const 500
    call $deduct
  )
)"#;
    let r1 = exec.call_nullary(wat, "run")?;
    assert_eq!(r1, 0, "first call (1000→500) must succeed");

    let r2 = exec.call_nullary(wat, "run")?;
    assert_eq!(r2, 0, "second call (500→0) must succeed");

    let r3 = exec.call_nullary(wat, "run")?;
    assert_eq!(
        r3, 2,
        "third call (0−500 underflow) must return 2 (quota exceeded)"
    );
    Ok(())
}

// ── Error paths ───────────────────────────────────────────────────────────────

/// A guest `unreachable` instruction causes a trap, which is returned as
/// `Err(Error::WasmFault { .. })`.
#[test]
fn executor_guest_trap_returns_wasm_fault() {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim).expect("executor creation must succeed");

    let wat = br#"(module
  (func (export "run") (result i32)
    unreachable
  )
)"#;
    let result = exec.call_nullary(wat, "run");
    assert!(
        matches!(result, Err(Error::WasmFault { .. })),
        "guest trap must return Err(WasmFault), got: {result:?}"
    );
}

/// Binary garbage is rejected at compile time with `Err(WasmFault)`.
#[test]
fn executor_invalid_wasm_bytes_rejected() {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim).expect("executor creation must succeed");

    let result = exec.call_nullary(b"not wasm bytes at all", "run");
    assert!(
        matches!(result, Err(Error::WasmFault { .. })),
        "invalid bytes must return Err(WasmFault), got: {result:?}"
    );
}

/// Calling a function that does not exist in the module returns `Err(WasmFault)`.
#[test]
fn executor_missing_function_rejected() {
    let shim = make_shim();
    let mut exec = WasmExecutor::new(shim).expect("executor creation must succeed");

    // Module exports "other", not "run".
    let wat = br#"(module
  (func (export "other") (result i32)
    i32.const 0
  )
)"#;
    let result = exec.call_nullary(wat, "run");
    assert!(
        matches!(result, Err(Error::WasmFault { .. })),
        "missing function must return Err(WasmFault), got: {result:?}"
    );
}
