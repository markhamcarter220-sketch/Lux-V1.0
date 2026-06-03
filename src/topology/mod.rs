//! Topology subsystem — directed execution graph enforcement.
//!
//! The topology is a **static**, manifest-derived directed graph.
//! No edge may be traversed that was not declared at boot.  This confines
//! lateral movement within the kernel's node space.

pub mod graph;
pub mod node;

pub use graph::TopologyGraph;
pub use node::Node;
