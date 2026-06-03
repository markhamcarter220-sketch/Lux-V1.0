//! Topology subsystem — typestate-enforced directed execution graph.
//!
//! The graph transitions through exactly two states:
//! 1. `BootingGraph` — mutable; edges and nodes are declared here.
//! 2. `OperationalGraph` — sealed; only `traverse` is available.
//!
//! The typestate pattern ensures that `activate` and `permit_edge` are
//! unreachable after the kernel enters the operational phase.

pub mod graph;

pub use graph::{BootingGraph, OperationalGraph};
