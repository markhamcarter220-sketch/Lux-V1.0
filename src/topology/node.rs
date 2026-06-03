//! Node descriptor within the topology graph.

use crate::types::NodeId;

/// The lifecycle state of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Node has been declared in the manifest but not yet activated.
    Dormant,
    /// Node is active and may participate in topology traversal.
    Active,
    /// Node has been administratively shut down and will not be reactivated.
    Terminated,
}

/// A single vertex in the execution graph.
#[derive(Debug)]
pub struct Node {
    pub id:    NodeId,
    pub state: NodeState,
}

impl Node {
    /// Returns `true` if the node can participate in an edge traversal.
    #[must_use]
    pub fn is_routable(&self) -> bool {
        self.state == NodeState::Active
    }
}
