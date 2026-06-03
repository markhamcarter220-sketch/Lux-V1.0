//! Topology graph — the enforcing wrapper around the manifest edge table.

use alloc::vec::Vec;

use crate::{
    boot::manifest::Manifest,
    error::Error,
    topology::node::{Node, NodeState},
    types::NodeId,
    Result,
};

/// The live topology graph, initialised from the boot manifest.
#[derive(Debug)]
pub struct TopologyGraph {
    nodes:    Vec<Node>,
    manifest: Manifest,
}

impl TopologyGraph {
    /// Construct a graph from the sealed manifest.
    #[must_use]
    pub fn from_manifest(manifest: Manifest) -> Self {
        Self {
            nodes: alloc::vec![],
            manifest,
        }
    }

    /// Attempt to traverse the directed edge src → dst.
    ///
    /// Fails if:
    /// - either node is not `Active`
    /// - the edge is not declared in the manifest
    pub fn traverse(&self, src: NodeId, dst: NodeId) -> Result<()> {
        let src_node = self.get(src).ok_or(Error::TopologyViolation { src: src.get(), dst: dst.get() })?;
        let dst_node = self.get(dst).ok_or(Error::TopologyViolation { src: src.get(), dst: dst.get() })?;

        if !src_node.is_routable() || !dst_node.is_routable() {
            return Err(Error::TopologyViolation { src: src.get(), dst: dst.get() });
        }
        if !self.manifest.permits_edge(src, dst) {
            return Err(Error::TopologyViolation { src: src.get(), dst: dst.get() });
        }
        Ok(())
    }

    fn get(&self, id: NodeId) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Register a node as `Active`.  Only valid during the boot window.
    pub(crate) fn activate(&mut self, id: NodeId) {
        if let Some(n) = self.nodes.iter_mut().find(|n| n.id == id) {
            n.state = NodeState::Active;
        } else {
            self.nodes.push(Node { id, state: NodeState::Active });
        }
    }
}
