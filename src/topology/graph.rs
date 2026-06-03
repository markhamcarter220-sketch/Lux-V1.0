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
    pub fn new() -> Self {
        Self {
            active_nodes: 0,
            edge_matrix:  [0u64; MAX_NODES],
        }
    }

    /// Declare `id` as an active node.
    ///
    /// Returns `Err(TopologyViolation)` if the node ID exceeds `MAX_NODES`.
    pub fn activate(&mut self, id: NodeId) -> Result<()> {
        let idx = node_idx(id)?;
        self.active_nodes |= 1u64 << idx;
        Ok(())
    }

    /// Declare the directed edge src → dst as permitted.
    ///
    /// Returns `Err(TopologyViolation)` if either ID exceeds `MAX_NODES`.
    pub fn permit_edge(&mut self, src: NodeId, dst: NodeId) -> Result<()> {
        let si = node_idx(src)?;
        let di = node_idx(dst)?;
        self.edge_matrix[si] |= 1u64 << di;
        Ok(())
    }

    /// Seal the graph, consuming the booting state and returning an
    /// immutable `OperationalGraph`.  After this call, `activate` and
    /// `permit_edge` are no longer reachable — enforced by the type system.
    #[must_use]
    pub fn seal(self) -> OperationalGraph {
        OperationalGraph {
            active_nodes: self.active_nodes,
            edge_matrix:  self.edge_matrix,
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
    edge_matrix:  [u64; MAX_NODES],
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
    pub fn traverse(&self, src: NodeId, dst: NodeId) -> Result<()> {
        let si = node_idx(src)?;
        let di = node_idx(dst)?;

        let src_active = (self.active_nodes >> si) & 1 == 1;
        let dst_active = (self.active_nodes >> di) & 1 == 1;
        if !src_active || !dst_active {
            return Err(Error::TopologyViolation { src: src.get(), dst: dst.get() });
        }

        let edge_present = (self.edge_matrix[si] >> di) & 1 == 1;
        if !edge_present {
            return Err(Error::TopologyViolation { src: src.get(), dst: dst.get() });
        }

        Ok(())
    }

    /// Returns `true` if `id` was declared active before sealing.
    #[must_use]
    pub fn is_active(&self, id: NodeId) -> bool {
        node_idx(id).map_or(false, |i| (self.active_nodes >> i) & 1 == 1)
    }
}

// ── Internal helper ───────────────────────────────────────────────────────────

/// Converts a `NodeId` to a zero-based array index, or returns
/// `TopologyViolation` if the ID is out of bounds.
#[inline]
fn node_idx(id: NodeId) -> Result<usize> {
    let idx = (id.get() as usize).saturating_sub(1);
    if idx >= MAX_NODES {
        Err(Error::TopologyViolation { src: id.get(), dst: 0 })
    } else {
        Ok(idx)
    }
}
