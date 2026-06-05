//! Topology graph — typestate-enforced, O(1) bitmask implementation.
//!
//! ## Typestate design
//!
//! The graph exists in exactly two states:
//!
//! - `BootingGraph` — mutable.  Topology edges and active nodes may be
//!   declared.  Only accessible during the boot sequence.
//! - `OperationalGraph` — sealed.  Only `traverse` is available; no mutation
//!   is possible.  `BootingGraph::seal` produces this type and consumes the
//!   mutable graph, making it impossible to call `activate` or `permit_edge`
//!   after the kernel enters the operational phase.
//!
//! ## Adjacency matrix
//!
//! Edges are stored as a 64×64 bitmask: `edge_matrix[src_idx]` is a `u64`
//! where bit `dst_idx` is set iff the edge (src → dst) is declared.
//! Both existence and active-state checks are therefore O(1) bitwise ops.

use crate::{
    audit::{AuditLog, EventKind},
    error::Error,
    types::{NodeId, MAX_NODES},
    Result,
};

/// Mutable topology graph.  Only available during the boot window.
///
/// Consuming `seal()` converts this into an immutable `OperationalGraph`.
#[derive(Debug)]
pub struct BootingGraph {
    /// Bitmask of active node IDs.  Bit `i` is set iff node `i + 1` is active.
    active_nodes: u64,
    /// Adjacency matrix.  `edge_matrix[src_idx]` has bit `dst_idx` set iff
    /// the directed edge (src → dst) is declared.
    edge_matrix: [u64; MAX_NODES],
}

impl BootingGraph {
    /// Construct an empty booting graph with no nodes or edges.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active_nodes: 0,
            edge_matrix: [0u64; MAX_NODES],
        }
    }

    /// Declare `id` as an active node.
    ///
    /// Returns `Err(TopologyViolation)` if the node ID exceeds `MAX_NODES`.
    ///
    /// # Errors
    /// Returns `Err(TopologyViolation)` if the node ID is out of range.
    pub fn activate(&mut self, id: NodeId) -> Result<()> {
        let idx = node_idx(id)?;
        self.active_nodes |= 1u64 << idx;
        Ok(())
    }

    /// Declare the directed edge src → dst as permitted.
    ///
    /// Returns `Err(TopologyViolation)` if either ID exceeds `MAX_NODES` **or**
    /// if either endpoint has not yet been activated.  Requiring pre-activation
    /// prevents ghost edges — undeclared-inactive edges that would be silently
    /// non-traversable with no diagnostic at declaration time (fail-closed).
    ///
    /// # Errors
    /// Returns `Err(TopologyViolation)` if either node ID is out of range or not yet activated.
    pub fn permit_edge(&mut self, src: NodeId, dst: NodeId) -> Result<()> {
        let si = node_idx(src)?;
        let di = node_idx(dst)?;
        // Both endpoints must be active before an edge between them is recorded.
        if (self.active_nodes >> si) & 1 == 0 {
            return Err(Error::TopologyViolation {
                src: src.get(),
                dst: dst.get(),
            });
        }
        if (self.active_nodes >> di) & 1 == 0 {
            return Err(Error::TopologyViolation {
                src: src.get(),
                dst: dst.get(),
            });
        }
        self.edge_matrix[si] |= 1u64 << di;
        Ok(())
    }

    /// Seal the graph, consuming the booting state and returning an
    /// immutable `OperationalGraph`.  After this call, `activate` and
    /// `permit_edge` are no longer reachable — enforced by the type system.
    #[must_use]
    pub const fn seal(self) -> OperationalGraph {
        OperationalGraph {
            active_nodes: self.active_nodes,
            edge_matrix: self.edge_matrix,
        }
    }
}

impl Default for BootingGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Sealed, immutable topology graph.  Only `traverse` is available.
///
/// This type is produced exclusively by `BootingGraph::seal` and cannot be
/// constructed or mutated by any other path.
#[derive(Debug)]
pub struct OperationalGraph {
    active_nodes: u64,
    edge_matrix: [u64; MAX_NODES],
}

impl OperationalGraph {
    /// Attempt to traverse the directed edge src → dst.
    ///
    /// O(1) — all checks are bitwise operations on fixed-size bitmasks.
    ///
    /// Fails if:
    /// - either node ID exceeds `MAX_NODES`
    /// - either node is not active
    /// - the edge is not declared in the manifest
    ///
    /// An audit event is always emitted to `audit` regardless of outcome.
    ///
    /// # Errors
    /// Returns `Err(TopologyViolation)` if either node is inactive, out of range, or the edge is undeclared.
    pub fn traverse(&self, src: NodeId, dst: NodeId, audit: &mut AuditLog) -> Result<()> {
        let actor = src.get();
        let result = self.traverse_inner(src, dst);
        let denial = result
            .as_ref()
            .err()
            .map(|e| (e.denial_class(), e.denial_reason_str()));
        audit.append(EventKind::TopologyTraverse, actor, 0, denial);
        result
    }

    fn traverse_inner(&self, src: NodeId, dst: NodeId) -> Result<()> {
        let si = node_idx(src)?;
        let di = node_idx(dst)?;

        let src_active = (self.active_nodes >> si) & 1 == 1;
        let dst_active = (self.active_nodes >> di) & 1 == 1;
        if !src_active || !dst_active {
            return Err(Error::TopologyViolation {
                src: src.get(),
                dst: dst.get(),
            });
        }

        let edge_present = (self.edge_matrix[si] >> di) & 1 == 1;
        if !edge_present {
            return Err(Error::TopologyViolation {
                src: src.get(),
                dst: dst.get(),
            });
        }

        Ok(())
    }

    /// Returns `true` if `id` was declared active before sealing.
    #[must_use]
    pub fn is_active(&self, id: NodeId) -> bool {
        node_idx(id).is_ok_and(|i| (self.active_nodes >> i) & 1 == 1)
    }
}

// ── Internal helper ───────────────────────────────────────────────────────────

/// Converts a `NodeId` to a zero-based array index, or returns
/// `TopologyViolation` if the ID is out of bounds.
#[inline]
const fn node_idx(id: NodeId) -> Result<usize> {
    let idx = (id.get() as usize).saturating_sub(1);
    if idx >= MAX_NODES {
        Err(Error::TopologyViolation {
            src: id.get(),
            dst: 0,
        })
    } else {
        Ok(idx)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{BootingGraph, OperationalGraph};
    use crate::{audit::AuditLog, error::Error, types::MAX_NODES};
    use core::num::NonZeroU32;

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).expect("test NodeId must be non-zero")
    }

    /// Build a sealed graph with exactly one declared edge between two active nodes.
    fn single_edge(src: u32, dst: u32) -> OperationalGraph {
        let mut g = BootingGraph::new();
        g.activate(nz(src)).unwrap();
        g.activate(nz(dst)).unwrap();
        g.permit_edge(nz(src), nz(dst)).unwrap();
        g.seal()
    }

    // ── 1. node_idx boundary validation (via activate) ────────────────────────

    #[test]
    fn activate_node_id_1_is_valid() {
        assert!(BootingGraph::new().activate(nz(1)).is_ok());
    }

    #[test]
    fn activate_node_id_64_is_valid() {
        assert!(BootingGraph::new().activate(nz(64)).is_ok());
    }

    #[test]
    fn activate_node_id_65_is_denied() {
        assert!(matches!(
            BootingGraph::new().activate(nz(65)),
            Err(Error::TopologyViolation { src: 65, .. })
        ));
    }

    #[test]
    fn activate_max_nonzero_u32_is_denied() {
        assert!(matches!(
            BootingGraph::new().activate(nz(u32::MAX)),
            Err(Error::TopologyViolation { src: u32::MAX, .. })
        ));
    }

    // ── 2. BootingGraph::activate — lifecycle semantics ───────────────────────

    #[test]
    fn activated_node_is_active_after_seal() {
        let mut g = BootingGraph::new();
        g.activate(nz(5)).unwrap();
        assert!(g.seal().is_active(nz(5)));
    }

    #[test]
    fn unactivated_node_is_not_active_after_seal() {
        assert!(!BootingGraph::new().seal().is_active(nz(1)));
    }

    #[test]
    fn activate_is_idempotent() {
        let mut g = BootingGraph::new();
        assert!(g.activate(nz(7)).is_ok());
        assert!(g.activate(nz(7)).is_ok()); // second call: same result, no error
        assert!(g.seal().is_active(nz(7)));
    }

    #[test]
    fn all_64_nodes_can_be_activated() {
        let mut g = BootingGraph::new();
        for i in 1u32..=(u32::try_from(MAX_NODES).expect("MAX_NODES=64 fits in u32")) {
            assert!(g.activate(nz(i)).is_ok(), "node {i} must be activatable");
        }
        let op = g.seal();
        for i in 1u32..=(u32::try_from(MAX_NODES).expect("MAX_NODES=64 fits in u32")) {
            assert!(
                op.is_active(nz(i)),
                "node {i} must be active after full activation"
            );
        }
    }

    // ── 3. BootingGraph::permit_edge — fail-closed pre-activation guard ───────
    //
    // Logic gap (now patched): the original implementation stored edges for
    // inactive endpoints, producing ghost edges — silently non-traversable
    // entries in the adjacency matrix with no diagnostic at declaration time.
    //
    // The guard added to permit_edge forces "activate first, then permit":
    // any attempt to declare an edge before activating both endpoints is
    // rejected with TopologyViolation.

    #[test]
    fn permit_edge_between_two_active_nodes_ok() {
        let mut g = BootingGraph::new();
        g.activate(nz(1)).unwrap();
        g.activate(nz(2)).unwrap();
        assert!(g.permit_edge(nz(1), nz(2)).is_ok());
    }

    #[test]
    fn permit_edge_from_inactive_src_is_denied() {
        let mut g = BootingGraph::new();
        g.activate(nz(2)).unwrap(); // dst active, src NOT active
        assert!(matches!(
            g.permit_edge(nz(1), nz(2)),
            Err(Error::TopologyViolation { .. })
        ));
    }

    #[test]
    fn permit_edge_to_inactive_dst_is_denied() {
        let mut g = BootingGraph::new();
        g.activate(nz(1)).unwrap(); // src active, dst NOT active
        assert!(matches!(
            g.permit_edge(nz(1), nz(2)),
            Err(Error::TopologyViolation { .. })
        ));
    }

    #[test]
    fn permit_edge_both_endpoints_inactive_is_denied() {
        // Neither node has been activated.
        assert!(matches!(
            BootingGraph::new().permit_edge(nz(1), nz(2)),
            Err(Error::TopologyViolation { .. })
        ));
    }

    #[test]
    fn permit_edge_src_out_of_range_is_denied() {
        let mut g = BootingGraph::new();
        g.activate(nz(1)).unwrap();
        assert!(matches!(
            g.permit_edge(nz(65), nz(1)),
            Err(Error::TopologyViolation { src: 65, .. })
        ));
    }

    #[test]
    fn permit_edge_dst_out_of_range_is_denied() {
        let mut g = BootingGraph::new();
        g.activate(nz(1)).unwrap();
        assert!(matches!(
            g.permit_edge(nz(1), nz(65)),
            Err(Error::TopologyViolation { .. })
        ));
    }

    #[test]
    fn permit_edge_is_idempotent() {
        let mut g = BootingGraph::new();
        g.activate(nz(3)).unwrap();
        g.activate(nz(4)).unwrap();
        g.permit_edge(nz(3), nz(4)).unwrap();
        assert!(g.permit_edge(nz(3), nz(4)).is_ok()); // duplicate: no error
    }

    #[test]
    fn permit_self_loop_on_active_node_ok() {
        let mut g = BootingGraph::new();
        g.activate(nz(5)).unwrap();
        assert!(g.permit_edge(nz(5), nz(5)).is_ok());
    }

    // ── 4. Typestate sealing ──────────────────────────────────────────────────
    //
    // Calling activate/permit_edge after seal() is a compile-time error —
    // seal() consumes BootingGraph.  These tests cover the runtime state
    // captured at seal time.

    #[test]
    fn empty_booting_graph_seals_successfully() {
        let _ = BootingGraph::new().seal(); // no panic
    }

    #[test]
    fn default_booting_graph_equals_new() {
        // Default::default() must produce the same empty sealed state as new().
        let op_new = BootingGraph::new().seal();
        let op_def = BootingGraph::default().seal();
        for i in 1u32..=(u32::try_from(MAX_NODES).expect("MAX_NODES=64 fits in u32")) {
            assert_eq!(
                op_new.is_active(nz(i)),
                op_def.is_active(nz(i)),
                "default and new must agree on node {i}"
            );
        }
    }

    // ── 5. OperationalGraph::traverse — fail-closed invariants ───────────────

    #[test]
    fn traverse_declared_active_edge_is_permitted() {
        assert!(single_edge(1, 2)
            .traverse(nz(1), nz(2), &mut AuditLog::new())
            .is_ok());
    }

    #[test]
    fn traverse_inactive_src_is_denied() {
        // Only dst activated; no edge can be declared for inactive src.
        let mut g = BootingGraph::new();
        g.activate(nz(2)).unwrap();
        let op = g.seal();
        assert!(matches!(
            op.traverse(nz(1), nz(2), &mut AuditLog::new()),
            Err(Error::TopologyViolation { src: 1, dst: 2 })
        ));
    }

    #[test]
    fn traverse_inactive_dst_is_denied() {
        // Only src activated; no edge can be declared for inactive dst.
        let mut g = BootingGraph::new();
        g.activate(nz(1)).unwrap();
        let op = g.seal();
        assert!(matches!(
            op.traverse(nz(1), nz(2), &mut AuditLog::new()),
            Err(Error::TopologyViolation { src: 1, dst: 2 })
        ));
    }

    #[test]
    fn traverse_both_nodes_inactive_is_denied() {
        let op = BootingGraph::new().seal();
        assert!(matches!(
            op.traverse(nz(1), nz(2), &mut AuditLog::new()),
            Err(Error::TopologyViolation { src: 1, dst: 2 })
        ));
    }

    #[test]
    fn traverse_undeclared_edge_denied_even_if_both_active() {
        let mut g = BootingGraph::new();
        g.activate(nz(10)).unwrap();
        g.activate(nz(20)).unwrap();
        // Both active, but no permit_edge — traversal must still be denied.
        let op = g.seal();
        assert!(matches!(
            op.traverse(nz(10), nz(20), &mut AuditLog::new()),
            Err(Error::TopologyViolation { src: 10, dst: 20 })
        ));
    }

    #[test]
    fn traverse_reverse_of_declared_edge_is_denied() {
        // Declare (1 → 2); the reverse (2 → 1) must not be implicitly permitted.
        let op = single_edge(1, 2);
        assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
        assert!(matches!(
            op.traverse(nz(2), nz(1), &mut AuditLog::new()),
            Err(Error::TopologyViolation { src: 2, dst: 1 })
        ));
    }

    #[test]
    fn traverse_src_out_of_range_is_denied() {
        let op = BootingGraph::new().seal();
        assert!(matches!(
            op.traverse(nz(65), nz(1), &mut AuditLog::new()),
            Err(Error::TopologyViolation { src: 65, .. })
        ));
    }

    #[test]
    fn traverse_dst_out_of_range_is_denied() {
        let op = BootingGraph::new().seal();
        assert!(matches!(
            op.traverse(nz(1), nz(65), &mut AuditLog::new()),
            Err(Error::TopologyViolation { .. })
        ));
    }

    #[test]
    fn traverse_self_loop_permitted_when_declared() {
        let mut g = BootingGraph::new();
        g.activate(nz(7)).unwrap();
        g.permit_edge(nz(7), nz(7)).unwrap();
        let op = g.seal();
        assert!(op.traverse(nz(7), nz(7), &mut AuditLog::new()).is_ok());
    }

    #[test]
    fn traverse_self_loop_denied_when_not_declared() {
        let mut g = BootingGraph::new();
        g.activate(nz(7)).unwrap();
        let op = g.seal();
        assert!(matches!(
            op.traverse(nz(7), nz(7), &mut AuditLog::new()),
            Err(Error::TopologyViolation { src: 7, dst: 7 })
        ));
    }

    #[test]
    fn traverse_empty_sealed_graph_denies_all() {
        let op = BootingGraph::new().seal();
        for i in 1u32..=5 {
            for j in 1u32..=5 {
                assert!(
                    op.traverse(nz(i), nz(j), &mut AuditLog::new()).is_err(),
                    "empty graph must deny edge ({i} → {j})"
                );
            }
        }
    }

    #[test]
    fn traverse_only_declared_edges_pass_among_active_nodes() {
        let mut g = BootingGraph::new();
        for i in 1u32..=4 {
            g.activate(nz(i)).unwrap();
        }
        g.permit_edge(nz(1), nz(2)).unwrap();
        g.permit_edge(nz(3), nz(4)).unwrap();
        let op = g.seal();

        assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
        assert!(op.traverse(nz(3), nz(4), &mut AuditLog::new()).is_ok());
        // All other pairs among {1,2,3,4} must be denied.
        for (s, d) in [
            (1, 3),
            (1, 4),
            (2, 1),
            (2, 3),
            (2, 4),
            (3, 1),
            (3, 2),
            (4, 1),
            (4, 2),
            (4, 3),
        ] {
            assert!(
                op.traverse(nz(s), nz(d), &mut AuditLog::new()).is_err(),
                "undeclared edge ({s} → {d}) must be denied"
            );
        }
    }

    #[test]
    fn traverse_error_fields_carry_exact_src_and_dst() {
        let op = BootingGraph::new().seal();
        let err = op
            .traverse(nz(11), nz(22), &mut AuditLog::new())
            .unwrap_err();
        assert_eq!(err, Error::TopologyViolation { src: 11, dst: 22 });
    }

    // ── 6. OperationalGraph::is_active ────────────────────────────────────────

    #[test]
    fn is_active_true_for_activated_node() {
        let mut g = BootingGraph::new();
        g.activate(nz(42)).unwrap();
        assert!(g.seal().is_active(nz(42)));
    }

    #[test]
    fn is_active_false_for_unactivated_node() {
        assert!(!BootingGraph::new().seal().is_active(nz(1)));
    }

    #[test]
    fn is_active_false_for_out_of_range_nodes() {
        let op = BootingGraph::new().seal();
        assert!(!op.is_active(nz(65)));
        assert!(!op.is_active(nz(u32::MAX)));
    }

    #[test]
    fn is_active_at_node_64_boundary() {
        let mut g = BootingGraph::new();
        g.activate(nz(64)).unwrap();
        let op = g.seal();
        assert!(op.is_active(nz(64)));
        assert!(!op.is_active(nz(63))); // only 64 was activated
    }

    // ── 7. Composite fail-closed scenarios ────────────────────────────────────

    #[test]
    fn fully_populated_graph_only_permits_declared_edges() {
        let mut g = BootingGraph::new();
        for i in 1u32..=(u32::try_from(MAX_NODES).expect("MAX_NODES=64 fits in u32")) {
            g.activate(nz(i)).unwrap();
        }
        // Declare a ring: 1→2→3→4→1.
        g.permit_edge(nz(1), nz(2)).unwrap();
        g.permit_edge(nz(2), nz(3)).unwrap();
        g.permit_edge(nz(3), nz(4)).unwrap();
        g.permit_edge(nz(4), nz(1)).unwrap();
        let op = g.seal();

        assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
        assert!(op.traverse(nz(2), nz(3), &mut AuditLog::new()).is_ok());
        assert!(op.traverse(nz(3), nz(4), &mut AuditLog::new()).is_ok());
        assert!(op.traverse(nz(4), nz(1), &mut AuditLog::new()).is_ok());
        // Non-ring edges must be denied even though all 64 nodes are active.
        assert!(op.traverse(nz(1), nz(3), &mut AuditLog::new()).is_err());
        assert!(op.traverse(nz(2), nz(4), &mut AuditLog::new()).is_err());
        assert!(op.traverse(nz(5), nz(1), &mut AuditLog::new()).is_err());
    }

    #[test]
    fn sealed_graph_captures_state_at_seal_time() {
        let mut g = BootingGraph::new();
        g.activate(nz(1)).unwrap();
        g.activate(nz(2)).unwrap();
        g.permit_edge(nz(1), nz(2)).unwrap();
        let op = g.seal(); // g consumed here — no further mutations possible

        assert!(op.is_active(nz(1)));
        assert!(op.is_active(nz(2)));
        assert!(!op.is_active(nz(3)));
        assert!(op.traverse(nz(1), nz(2), &mut AuditLog::new()).is_ok());
    }
}
