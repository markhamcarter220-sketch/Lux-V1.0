//! Boot subsystem — manifest parsing and kernel initialisation sequence.
//!
//! The boot sequence is the **only** path through which topology edges,
//! capability seeds, and resource quotas may be established.  It follows an
//! atomic, all-or-nothing contract:
//!
//! 1. Parse and cryptographically verify the manifest.
//! 2. Seed a `BootingGraph` with all declared edges and active nodes.
//! 3. Seed a `Ledger` with per-node quotas.
//! 4. **Seal** the graph — `BootingGraph::seal()` consumes the mutable graph
//!    and returns an `OperationalGraph`, making it structurally impossible to
//!    call `activate` or `permit_edge` ever again.
//! 5. Initialise the `Policy` enforcement point.
//!
//! If any step fails, `Err` is returned and **no partial state is retained**.
//! The caller receives either a fully initialised `BootState` or nothing.

pub mod manifest;

pub use manifest::Manifest;

use crate::{
    auth::policy::Policy,
    metabolism::ledger::Ledger,
    topology::graph::{BootingGraph, OperationalGraph},
    types::Generation,
    Result,
};

/// Sealed, immutable kernel state produced by a successful boot sequence.
///
/// All three components are initialised atomically — they cannot be obtained
/// individually or in a partially-initialised form.
#[derive(Debug)]
pub struct BootState {
    pub(crate) graph:  OperationalGraph,
    pub(crate) ledger: Ledger,
    pub(crate) policy: Policy,
}

impl BootState {
    /// Returns a shared reference to the sealed topology graph.
    #[must_use]
    pub fn graph(&self) -> &OperationalGraph {
        &self.graph
    }

    /// Returns a shared reference to the resource ledger.
    #[must_use]
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Returns a mutable reference to the policy enforcement point.
    #[must_use]
    pub fn policy_mut(&mut self) -> &mut Policy {
        &mut self.policy
    }

    /// Validate `raw` bytes, run the full boot sequence, and seal the kernel.
    ///
    /// Steps performed (all-or-nothing):
    ///  1. Parse + verify manifest
    ///  2. Seed topology graph edges
    ///  3. Seed resource ledger
    ///  4. Seal the graph (typestate transition: Booting → Operational)
    ///  5. Construct the policy enforcement point
    pub fn initialise(raw: &[u8]) -> Result<Self> {
        let manifest = Manifest::parse_and_verify(raw)?;

        let mut booting = BootingGraph::new();
        let mut ledger  = Ledger::new();

        for edge in &manifest.edges {
            booting.permit_edge(edge.src, edge.dst)?;
            booting.activate(edge.src)?;
            booting.activate(edge.dst)?;
        }

        for q in &manifest.quotas {
            ledger.seed(q.node, q.ceiling);
        }

        let graph  = booting.seal();
        let policy = Policy::new(Generation(0));

        Ok(Self { graph, ledger, policy })
    }
}
