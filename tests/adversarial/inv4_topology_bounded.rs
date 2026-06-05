//! Adversarial tests — Invariant 4: Topology-Bounded.
//!
//! 12 attack vectors proving that execution is confined to the boot-manifest
//! graph; every undeclared edge is denied.

use core::num::NonZeroU32;
use lux_kernel::audit::AuditLog;
use lux_kernel::{
    auth::{
        capability::{Capability, CapabilitySet},
        policy::Policy,
    },
    topology::BootingGraph,
    types::{Generation, MAX_NODES},
};

fn nz(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

// ── Attack 4.1 ────────────────────────────────────────────────────────────────
// Traversal to an undeclared node: D not in manifest → denied from any source.

#[test]
fn attack_4_1_traversal_to_undeclared_node_denied() {
    let mut g = BootingGraph::new();
    for i in 1u32..=3 {
        g.activate(nz(i)).unwrap();
    }
    g.permit_edge(nz(1), nz(2)).unwrap();
    g.permit_edge(nz(2), nz(3)).unwrap();
    let op = g.seal();

    // Node 4 was never activated.
    assert!(
        op.traverse(nz(1), nz(4), &mut AuditLog::new()).is_err(),
        "traversal to undeclared node must be denied"
    );
    assert!(
        op.traverse(nz(4), nz(1), &mut AuditLog::new()).is_err(),
        "traversal from undeclared node must be denied"
    );
    assert!(
        op.traverse(nz(4), nz(4), &mut AuditLog::new()).is_err(),
        "self-traversal on undeclared node must be denied"
    );
}

// ── Attack 4.2 ────────────────────────────────────────────────────────────────
// Undeclared edge between active nodes: both nodes active, but no edge → denied.

#[test]
fn attack_4_2_undeclared_edge_denied_even_if_both_nodes_active() {
    let mut g = BootingGraph::new();
    g.activate(nz(1)).unwrap();
    g.activate(nz(2)).unwrap();
    g.activate(nz(3)).unwrap();
    g.permit_edge(nz(1), nz(2)).unwrap(); // only 1→2 declared
    let op = g.seal();

    assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
    assert!(
        op.traverse(nz(1), nz(3), &mut AuditLog::new()).is_err(),
        "1→3 undeclared must be denied"
    );
    assert!(
        op.traverse(nz(2), nz(3), &mut AuditLog::new()).is_err(),
        "2→3 undeclared must be denied"
    );
    assert!(
        op.traverse(nz(3), nz(1), &mut AuditLog::new()).is_err(),
        "3→1 undeclared must be denied"
    );
}

// ── Attack 4.3 ────────────────────────────────────────────────────────────────
// Transitive-closure bypass: A→B→C declared; direct A→C shortcut denied.
// The kernel does not implement transitive closure — only declared edges are permitted.

#[test]
fn attack_4_3_transitive_shortcut_is_denied() {
    let mut g = BootingGraph::new();
    g.activate(nz(1)).unwrap(); // A
    g.activate(nz(2)).unwrap(); // B
    g.activate(nz(3)).unwrap(); // C
    g.permit_edge(nz(1), nz(2)).unwrap(); // A→B
    g.permit_edge(nz(2), nz(3)).unwrap(); // B→C
    let op = g.seal();

    assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok()); // A→B: ok
    assert!(op.traverse(nz(2), nz(3), &mut AuditLog::new()).is_ok()); // B→C: ok
    assert!(
        op.traverse(nz(1), nz(3), &mut AuditLog::new()).is_err(),
        "A→C shortcut must be denied: transitive closure is not automatic"
    );
}

// ── Attack 4.4 ────────────────────────────────────────────────────────────────
// Reverse edge traversal: directed graph — (A→B) does not imply (B→A).

#[test]
fn attack_4_4_reverse_edge_traversal_denied() {
    let mut g = BootingGraph::new();
    g.activate(nz(10)).unwrap();
    g.activate(nz(20)).unwrap();
    g.permit_edge(nz(10), nz(20)).unwrap(); // 10→20 only
    let op = g.seal();

    assert!(
        op.traverse(nz(10), nz(20), &mut AuditLog::new()).is_ok(),
        "declared direction must be permitted"
    );
    assert!(
        op.traverse(nz(20), nz(10), &mut AuditLog::new()).is_err(),
        "reverse of directed edge must be denied"
    );
}

// ── Attack 4.5 ────────────────────────────────────────────────────────────────
// Self-loop: only permitted if explicitly declared; undeclared self-loops denied.

#[test]
fn attack_4_5_self_loop_requires_explicit_declaration() {
    // With declared self-loop.
    let mut g_with = BootingGraph::new();
    g_with.activate(nz(5)).unwrap();
    g_with.permit_edge(nz(5), nz(5)).unwrap();
    let op_with = g_with.seal();
    assert!(
        op_with.traverse(nz(5), nz(5), &mut AuditLog::new()).is_ok(),
        "declared self-loop must be permitted"
    );

    // Without declared self-loop.
    let mut g_without = BootingGraph::new();
    g_without.activate(nz(5)).unwrap();
    let op_without = g_without.seal();
    assert!(
        op_without
            .traverse(nz(5), nz(5), &mut AuditLog::new())
            .is_err(),
        "undeclared self-loop must be denied"
    );
}

// ── Attack 4.6 ────────────────────────────────────────────────────────────────
// Cycle traversal: A→B→C→A declared. Each single hop is O(1); no infinite loop.
// The kernel's single-hop check model prevents unbounded traversal.

#[test]
fn attack_4_6_cyclic_topology_single_hop_only_no_infinite_traversal() {
    let mut g = BootingGraph::new();
    g.activate(nz(1)).unwrap();
    g.activate(nz(2)).unwrap();
    g.activate(nz(3)).unwrap();
    g.permit_edge(nz(1), nz(2)).unwrap();
    g.permit_edge(nz(2), nz(3)).unwrap();
    g.permit_edge(nz(3), nz(1)).unwrap();
    let op = g.seal();

    // Each declared hop is permitted.
    assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
    assert!(op.traverse(nz(2), nz(3), &mut AuditLog::new()).is_ok());
    assert!(op.traverse(nz(3), nz(1), &mut AuditLog::new()).is_ok());

    // Skip edges (not declared) denied — no free path through the cycle.
    assert!(
        op.traverse(nz(1), nz(3), &mut AuditLog::new()).is_err(),
        "skip A→C in cycle must be denied"
    );
    assert!(
        op.traverse(nz(2), nz(1), &mut AuditLog::new()).is_err(),
        "reverse 2→1 in cycle must be denied"
    );
}

// ── Attack 4.7 ────────────────────────────────────────────────────────────────
// Disconnected graph: no path between components [1,2] and [3,4].

#[test]
fn attack_4_7_disconnected_components_cannot_communicate() {
    let mut g = BootingGraph::new();
    // Component 1: 1 → 2.
    g.activate(nz(1)).unwrap();
    g.activate(nz(2)).unwrap();
    g.permit_edge(nz(1), nz(2)).unwrap();
    // Component 2: 3 → 4.
    g.activate(nz(3)).unwrap();
    g.activate(nz(4)).unwrap();
    g.permit_edge(nz(3), nz(4)).unwrap();
    let op = g.seal();

    // Within-component traversals: ok.
    assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
    assert!(op.traverse(nz(3), nz(4), &mut AuditLog::new()).is_ok());

    // Cross-component traversals: all denied.
    for (s, d) in [
        (1, 3),
        (1, 4),
        (2, 3),
        (2, 4),
        (3, 1),
        (3, 2),
        (4, 1),
        (4, 2),
    ] {
        assert!(
            op.traverse(nz(s), nz(d), &mut AuditLog::new()).is_err(),
            "cross-component ({s}→{d}) must be denied"
        );
    }
}

// ── Attack 4.8 ────────────────────────────────────────────────────────────────
// Sealed graph is structurally immutable: the type system prevents any mutation
// after seal().  OperationalGraph has no activate() or permit_edge() methods.

#[test]
fn attack_4_8_sealed_graph_is_structurally_immutable() {
    let mut booting = BootingGraph::new();
    booting.activate(nz(1)).unwrap();
    booting.activate(nz(2)).unwrap();
    booting.permit_edge(nz(1), nz(2)).unwrap();
    let op = booting.seal(); // booting consumed — compile error to use it again

    // State is exactly what was committed at seal time.
    assert!(op.is_active(nz(1)));
    assert!(op.is_active(nz(2)));
    assert!(!op.is_active(nz(3)));
    assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
    assert!(op.traverse(nz(2), nz(1), &mut AuditLog::new()).is_err()); // reverse not committed
}

// ── Attack 4.9 ────────────────────────────────────────────────────────────────
// Out-of-bounds node IDs (> 64) denied at O(1) boundary check.

#[test]
fn attack_4_9_out_of_bounds_node_ids_always_denied() {
    let op = BootingGraph::new().seal();

    for id in [65u32, 100, 1000, u32::MAX] {
        let n = NonZeroU32::new(id).unwrap();
        assert!(
            op.traverse(nz(1), n, &mut AuditLog::new()).is_err(),
            "dst={id} out-of-bounds must be denied"
        );
        assert!(
            op.traverse(n, nz(1), &mut AuditLog::new()).is_err(),
            "src={id} out-of-bounds must be denied"
        );
        assert!(!op.is_active(n), "out-of-bounds node must report inactive");
    }
}

// ── Attack 4.10 ───────────────────────────────────────────────────────────────
// All 64 nodes active; only ring edges declared — every other edge denied.

#[test]
fn attack_4_10_full_node_set_only_declared_ring_edges_work() {
    let mut g = BootingGraph::new();
    for i in 1u32..=u32::try_from(MAX_NODES).expect("constant fits in u32") {
        g.activate(nz(i)).unwrap();
    }
    // Ring: 1→2→3→4→1.
    g.permit_edge(nz(1), nz(2)).unwrap();
    g.permit_edge(nz(2), nz(3)).unwrap();
    g.permit_edge(nz(3), nz(4)).unwrap();
    g.permit_edge(nz(4), nz(1)).unwrap();
    let op = g.seal();

    // Ring edges pass.
    assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
    assert!(op.traverse(nz(2), nz(3), &mut AuditLog::new()).is_ok());
    assert!(op.traverse(nz(3), nz(4), &mut AuditLog::new()).is_ok());
    assert!(op.traverse(nz(4), nz(1), &mut AuditLog::new()).is_ok());

    // Non-ring edges denied even though all nodes are active.
    assert!(op.traverse(nz(1), nz(3), &mut AuditLog::new()).is_err()); // skip
    assert!(op.traverse(nz(2), nz(4), &mut AuditLog::new()).is_err()); // skip
    assert!(op.traverse(nz(5), nz(1), &mut AuditLog::new()).is_err()); // undeclared
    assert!(op.traverse(nz(63), nz(64), &mut AuditLog::new()).is_err()); // undeclared
}

// ── Attack 4.11 ───────────────────────────────────────────────────────────────
// permit_edge to inactive node denied at declaration time (fail-closed guard).
// Ghost edges — silently non-traversable entries — are prevented at source.

#[test]
fn attack_4_11_permit_edge_to_inactive_node_denied_at_declaration_time() {
    let mut g = BootingGraph::new();
    g.activate(nz(1)).unwrap();
    // nz(2) never activated.

    assert!(
        g.permit_edge(nz(1), nz(2)).is_err(),
        "permit_edge to inactive dst must be denied at declaration time"
    );
    // The ghost edge was never stored; traversal is also denied.
    let op = g.seal();
    assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_err());
}

// ── Attack 4.12 ───────────────────────────────────────────────────────────────
// Topology check and capability check are independent layered defences.
// Both must pass for an operation to proceed; either layer can catch the attack.

#[test]
fn attack_4_12_topology_and_capability_are_independent_defence_layers() {
    let mut g = BootingGraph::new();
    g.activate(nz(1)).unwrap();
    g.activate(nz(2)).unwrap();
    g.permit_edge(nz(1), nz(2)).unwrap();
    let op = g.seal();

    let gen = Generation(0);
    let mut policy = Policy::new(gen);

    // Layer 1 (capability) passes, Layer 2 (topology) catches undeclared edge.
    let cap_ok = Capability::new_for_test(nz(1), nz(3), CapabilitySet::READ_TOPOLOGY, gen, 1);
    assert!(policy
        .check(&cap_ok, CapabilitySet::READ_TOPOLOGY, &mut AuditLog::new())
        .is_ok()); // cap: ok
    assert!(
        op.traverse(nz(1), nz(3), &mut AuditLog::new()).is_err(),
        "topology layer must catch undeclared edge"
    );

    // Layer 1 (capability) catches wrong right before topology even checked.
    let cap_bad = Capability::new_for_test(nz(1), nz(2), CapabilitySet::empty(), gen, 2);
    assert!(
        policy
            .check(&cap_bad, CapabilitySet::READ_TOPOLOGY, &mut AuditLog::new())
            .is_err(),
        "capability layer must catch empty rights"
    );
    // (Topology is still valid — it is the cap layer that fires.)
    assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok()); // topology itself is fine

    // Both layers satisfied: operation proceeds.
    let cap_valid = Capability::new_for_test(nz(1), nz(2), CapabilitySet::READ_TOPOLOGY, gen, 3);
    assert!(policy
        .check(
            &cap_valid,
            CapabilitySet::READ_TOPOLOGY,
            &mut AuditLog::new()
        )
        .is_ok());
    assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
}
