//! Integration tests: WASM execution substrate (Item 4, Tier 3).
//!
//! These tests exercise [`WasmShim`] and the three host ABI functions
//! ([`host::lux_policy_check`], [`host::lux_ledger_deduct`],
//! [`host::lux_topology_traverse`]) against each of the four kernel invariants:
//!
//! - I1 (Fail-Closed):          invalid handles always return -1.
//! - I2 (Capability-Gated):     `lux_policy_check` gates on `Policy::check`.
//! - I3 (Accountable Resources):`lux_ledger_deduct` gates on `QuotaEnforcer::deduct`.
//! - I4 (Topology-Bounded):     `lux_topology_traverse` gates on `OperationalGraph::traverse`.

#![cfg(feature = "wasm")]

use core::num::NonZeroU32;
use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    metabolism::ledger::Ledger,
    topology::BootingGraph,
    types::{Generation, Quota},
    wasm::{host, WasmShim},
};

fn node(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

/// Build a minimal [`WasmShim`] with one edge (1→2) and one quota (node 1).
fn make_shim() -> WasmShim {
    let mut booting = BootingGraph::new();
    booting.activate(node(1)).unwrap();
    booting.activate(node(2)).unwrap();
    booting.permit_edge(node(1), node(2)).unwrap();
    let graph = booting.seal();

    let mut ledger = Ledger::new();
    ledger.seed(node(1), Quota::new(1_000)).expect("test node count within MAX_NODES");

    let policy = Policy::new(Generation(0));

    WasmShim::from_parts(policy, ledger, graph)
}

/// Mint a capability for `target` with `rights` at generation 0.
fn make_cap(target: u32, rights: CapabilitySet) -> Capability {
    Capability::new_for_test(node(1), node(target), rights, Generation(0), 1)
}

// ── I1: Fail-Closed — invalid handles ────────────────────────────────────────

#[test]
fn policy_check_invalid_handle_returns_minus_one() {
    let mut shim = make_shim();
    // No caps registered yet — any handle is invalid.
    assert_eq!(host::lux_policy_check(&mut shim, 0, 0xFF), -1);
}

#[test]
fn ledger_deduct_node_zero_returns_minus_one() {
    let mut shim = make_shim();
    // Node ID 0 is always invalid (NonZeroU32 sentinel).
    assert_eq!(host::lux_ledger_deduct(&mut shim, 0, 10), -1);
}

#[test]
fn topology_traverse_src_zero_returns_minus_one() {
    let mut shim = make_shim();
    assert_eq!(host::lux_topology_traverse(&mut shim, 0, 2), -1);
}

#[test]
fn topology_traverse_dst_zero_returns_minus_one() {
    let mut shim = make_shim();
    assert_eq!(host::lux_topology_traverse(&mut shim, 1, 0), -1);
}

// ── I2: Capability-Gated ─────────────────────────────────────────────────────

#[test]
fn policy_check_valid_cap_correct_rights_returns_zero() {
    let mut shim = make_shim();
    let cap = make_cap(2, CapabilitySet::SCHEDULE);
    let handle = shim.register_cap(cap).expect("table must not be full");
    let rc = host::lux_policy_check(&mut shim, handle, CapabilitySet::SCHEDULE.bits());
    assert_eq!(
        rc, 0,
        "valid capability with matching rights must be permitted"
    );
}

#[test]
fn policy_check_insufficient_rights_returns_one() {
    let mut shim = make_shim();
    // Cap only has SCHEDULE; request ALLOC_RESOURCE → denied.
    let cap = make_cap(2, CapabilitySet::SCHEDULE);
    let handle = shim.register_cap(cap).unwrap();
    let rc = host::lux_policy_check(&mut shim, handle, CapabilitySet::ALLOC_RESOURCE.bits());
    assert_eq!(rc, 1, "insufficient rights must return RC_CAP_DENIED");
}

#[test]
fn policy_check_out_of_range_handle_returns_minus_one() {
    let mut shim = make_shim();
    let cap = make_cap(2, CapabilitySet::SCHEDULE);
    shim.register_cap(cap).unwrap(); // handle 0
                                     // Handle 99 is out of range.
    assert_eq!(
        host::lux_policy_check(&mut shim, 99, CapabilitySet::SCHEDULE.bits()),
        -1
    );
}

// ── I3: Accountable Resources ─────────────────────────────────────────────────

#[test]
fn ledger_deduct_within_quota_returns_zero() {
    let mut shim = make_shim();
    let rc = host::lux_ledger_deduct(&mut shim, 1, 100);
    assert_eq!(rc, 0, "deduction within quota must be permitted");
}

#[test]
fn ledger_deduct_exceeds_quota_returns_two() {
    let mut shim = make_shim();
    let rc = host::lux_ledger_deduct(&mut shim, 1, 1_001); // quota is 1_000
    assert_eq!(rc, 2, "over-quota deduction must return RC_QUOTA_EXCEEDED");
}

#[test]
fn ledger_deduct_exact_quota_returns_zero_then_next_returns_two() {
    let mut shim = make_shim();
    assert_eq!(host::lux_ledger_deduct(&mut shim, 1, 1_000), 0);
    assert_eq!(
        host::lux_ledger_deduct(&mut shim, 1, 1),
        2,
        "exhausted quota must reject further deductions"
    );
}

#[test]
fn ledger_deduct_unknown_node_returns_two() {
    let mut shim = make_shim();
    // Node 99 was never seeded — no quota ≡ zero balance → quota exceeded.
    let rc = host::lux_ledger_deduct(&mut shim, 99, 1);
    assert_eq!(
        rc, 2,
        "unknown node returns quota-exceeded (no quota ≡ 0 quota)"
    );
}

// ── I4: Topology-Bounded ─────────────────────────────────────────────────────

#[test]
fn topology_traverse_declared_edge_returns_zero() {
    let mut shim = make_shim();
    let rc = host::lux_topology_traverse(&mut shim, 1, 2);
    assert_eq!(rc, 0, "declared edge must be permitted");
}

#[test]
fn topology_traverse_undeclared_edge_returns_three() {
    let mut shim = make_shim();
    // Only 1→2 was declared; 2→1 is not.
    let rc = host::lux_topology_traverse(&mut shim, 2, 1);
    assert_eq!(rc, 3, "undeclared edge must return RC_TOPO_VIOLATION");
}

#[test]
fn topology_traverse_unknown_node_returns_three() {
    let mut shim = make_shim();
    // Node 99 was never activated.
    let rc = host::lux_topology_traverse(&mut shim, 1, 99);
    assert_eq!(rc, 3, "unknown node must return RC_TOPO_VIOLATION");
}

// ── Audit log wiring ─────────────────────────────────────────────────────────

#[test]
fn each_host_call_appends_to_audit_log() {
    let mut shim = make_shim();
    let cap = make_cap(2, CapabilitySet::SCHEDULE);
    let handle = shim.register_cap(cap).unwrap();

    let _ = host::lux_policy_check(&mut shim, handle, CapabilitySet::SCHEDULE.bits());
    let _ = host::lux_ledger_deduct(&mut shim, 1, 10);
    let _ = host::lux_topology_traverse(&mut shim, 1, 2);

    let count = shim.audit().len();
    assert_eq!(count, 3, "each host call must append one audit event");
}
