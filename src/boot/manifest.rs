//! Manifest — the authoritative, read-only boot contract.
//!
//! A `Manifest` encodes the complete initial policy for one kernel instance:
//! - declared topology (permitted edges)
//! - capability seed table
//! - per-node resource quotas
//!
//! All collections are `heapless::Vec`: the manifest is bounded by `MAX_EDGES`
//! and `MAX_NODES` at compile time, eliminating allocator interaction during
//! the boot sequence.  Parsing is fail-closed — any unknown field, truncated
//! record, or integrity failure returns `ManifestInvalid`.

use heapless::Vec as HVec;

use crate::{
    error::Error,
    types::{NodeId, Quota, MAX_EDGES, MAX_NODES},
    Result,
};

/// One row in the manifest's topology table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeDecl {
    /// Source node of the directed edge.
    pub src: NodeId,
    /// Destination node of the directed edge.
    pub dst: NodeId,
}

/// One row in the manifest's quota table.
#[derive(Debug, Clone, Copy)]
pub struct QuotaDecl {
    /// The node to which this quota applies.
    pub node: NodeId,
    /// Resource ceiling for the node.
    pub ceiling: Quota,
}

/// The sealed, validated boot manifest.
#[derive(Debug)]
pub struct Manifest {
    pub(crate) edges: HVec<EdgeDecl, MAX_EDGES>,
    pub(crate) quotas: HVec<QuotaDecl, MAX_NODES>,
    pub(crate) version: u32,
}

impl Manifest {
    /// Parse `bytes` and verify structural integrity.
    ///
    /// In production this step also verifies a cryptographic signature over
    /// the manifest body.  The signature backend is a Tier 2 deliverable.
    ///
    /// # Errors
    /// Returns `Err(ManifestInvalid)` if `bytes` is empty or the parser stub rejects it.
    pub const fn parse_and_verify(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::ManifestInvalid {
                detail: "zero-length manifest",
            });
        }
        // Placeholder — replace with wire-format decoder (CBOR/protobuf).
        let _ = bytes;
        Err(Error::ManifestInvalid {
            detail: "parser not yet wired (stub)",
        })
    }

    /// Returns `true` if the directed edge (src → dst) is declared.
    #[must_use]
    pub fn permits_edge(&self, src: NodeId, dst: NodeId) -> bool {
        self.edges.iter().any(|e| e.src == src && e.dst == dst)
    }

    /// Returns the resource ceiling for `node`, or `None` if undeclared.
    #[must_use]
    pub fn quota_for(&self, node: NodeId) -> Option<Quota> {
        self.quotas
            .iter()
            .find(|q| q.node == node)
            .map(|q| q.ceiling)
    }

    /// Wire-format version of this manifest.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}
