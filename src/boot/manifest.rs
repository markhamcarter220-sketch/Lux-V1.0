//! Manifest — the authoritative, read-only boot contract.
//!
//! A `Manifest` encodes the complete initial policy for one kernel instance:
//! - declared topology (permitted edges)
//! - capability seed table
//! - per-node resource quotas
//!
//! Parsing is intentionally strict and fail-closed: any unknown field, any
//! truncated record, or any integrity failure returns `ManifestInvalid`.

use alloc::vec::Vec;

use crate::{
    error::Error,
    types::{NodeId, Quota},
    Result,
};

/// One row in the manifest's topology table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeDecl {
    pub src: NodeId,
    pub dst: NodeId,
}

/// One row in the manifest's quota table.
#[derive(Debug, Clone)]
pub struct QuotaDecl {
    pub node: NodeId,
    pub ceiling: Quota,
}

/// The sealed, validated boot manifest.
#[derive(Debug)]
pub struct Manifest {
    pub(crate) edges:  Vec<EdgeDecl>,
    pub(crate) quotas: Vec<QuotaDecl>,
    pub(crate) version: u32,
}

impl Manifest {
    /// Parse `bytes` and verify structural integrity.
    ///
    /// In production this step also verifies a cryptographic signature over
    /// the manifest.  The signature backend is injected via the `auth` feature
    /// to maintain subsystem isolation.
    pub fn parse_and_verify(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::ManifestInvalid { detail: "zero-length manifest" });
        }
        // Placeholder — replace with wire-format decoder (e.g. CBOR/protobuf).
        let _ = bytes;
        Err(Error::ManifestInvalid { detail: "parser not yet wired (stub)" })
    }

    /// Returns `true` if the directed edge (src → dst) is declared.
    #[must_use]
    pub fn permits_edge(&self, src: NodeId, dst: NodeId) -> bool {
        self.edges.iter().any(|e| e.src == src && e.dst == dst)
    }

    /// Returns the resource ceiling for `node`, or `None` if undeclared.
    #[must_use]
    pub fn quota_for(&self, node: NodeId) -> Option<Quota> {
        self.quotas.iter().find(|q| q.node == node).map(|q| q.ceiling)
    }
}
