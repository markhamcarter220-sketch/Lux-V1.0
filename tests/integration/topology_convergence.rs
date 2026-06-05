//! Integration tests: topology graph edge enforcement.
//!
//! These tests exercise the typestate API directly: a `BootingGraph` is
//! constructed, seeded, and sealed into an `OperationalGraph`.  They verify
//! that the adjacency-matrix traversal correctly enforces the declared edges.

use lux_kernel::{
    audit::AuditLog,
    error::Error,
    topology::{BootingGraph, OperationalGraph},
};
use core::num::NonZeroU32;

fn node(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

#[test]
fn undeclared_edge_is_denied_on_sealed_graph() {
    let booting = BootingGraph::new();
    let graph: OperationalGraph = booting.seal();

    // No edges declared → all traversals must fail.
    let result = graph.traverse(node(1), node(2), &mut AuditLog::new());
    assert_eq!(
        result,
        Err(Error::TopologyViolation { src: 1, dst: 2 }),
        "undeclared edge must be denied"
    );
}

#[test]
fn declared_edge_between_active_nodes_is_permitted() {
    let mut booting = BootingGraph::new();
    booting.activate(node(1)).unwrap();
    booting.activate(node(2)).unwrap();
    booting.permit_edge(node(1), node(2)).unwrap();
    let graph = booting.seal();

    assert!(graph.traverse(node(1), node(2), &mut AuditLog::new()).is_ok(), "declared edge must be permitted");
}

#[test]
fn reverse_edge_is_denied_when_undeclared() {
    let mut booting = BootingGraph::new();
    booting.activate(node(1)).unwrap();
    booting.activate(node(2)).unwrap();
    booting.permit_edge(node(1), node(2)).unwrap(); // only 1→2
    let graph = booting.seal();

    assert!(
        graph.traverse(node(2), node(1), &mut AuditLog::new()).is_err(),
        "undeclared reverse edge must be denied"
    );
}

#[test]
fn inactive_node_blocks_traversal() {
    let mut booting = BootingGraph::new();
    booting.activate(node(1)).unwrap();
    // node(2) intentionally not activated — permit_edge must be denied at
    // declaration time (fail-closed: no ghost edges).
    assert!(
        booting.permit_edge(node(1), node(2)).is_err(),
        "permit_edge to inactive dst must be denied at declaration time"
    );
    let graph = booting.seal();

    assert!(
        graph.traverse(node(1), node(2), &mut AuditLog::new()).is_err(),
        "inactive destination must block traversal after seal"
    );
}

#[test]
fn activate_is_unreachable_on_operational_graph() {
    // This test is a compile-time proof: `OperationalGraph` has no
    // `activate` method.  The following line would not compile:
    //   graph.activate(node(1));
    // We assert the structural property here as documentation.
    let graph = BootingGraph::new().seal();
    assert!(!graph.is_active(node(1)), "freshly-sealed graph has no active nodes");
}
