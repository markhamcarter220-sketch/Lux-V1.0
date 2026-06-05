//! Peer set for distributed topology consensus (Item 5).
//!
//! The peer set is derived from the boot manifest and is sealed along with the
//! topology graph.  Peers cannot be added or removed at runtime.

use crate::{error::Error, types::NodeId, Result};

/// Maximum number of peers the set can hold.
pub const MAX_PEERS: usize = 16;

/// The set of peers that participate in distributed topology consensus.
///
/// A `PeerSet` is constructed during boot from the list of declared peer nodes.
/// In a single-node deployment use [`PeerSet::new`] (empty set) — the consensus
/// protocol degenerates to a local-only check.
///
/// The quorum threshold is `⌊N/2⌋ + 1` where `N` is the number of *other*
/// peers.  For an empty set the threshold is `0` (auto-commit).
#[derive(Debug)]
pub struct PeerSet {
    peers: heapless::Vec<NodeId, MAX_PEERS>,
}

impl PeerSet {
    /// Construct an empty peer set (single-node deployment).
    #[must_use]
    pub const fn new() -> Self {
        Self { peers: heapless::Vec::new() }
    }

    /// Add a peer to the set.
    ///
    /// Returns `Err(ManifestInvalid)` if the set is already at capacity
    /// (`MAX_PEERS` = 16).
    ///
    /// # Errors
    /// Returns `Err(ManifestInvalid)` if the peer set is already at capacity (16 peers).
    pub fn add(&mut self, peer: NodeId) -> Result<()> {
        self.peers
            .push(peer)
            .map_err(|_| Error::ManifestInvalid { detail: "consensus peer set is full (max 16)" })
    }

    /// Returns the declared peers (not including the local node).
    #[must_use]
    pub fn peers(&self) -> &[NodeId] {
        &self.peers
    }

    /// Returns the number of declared peers (not counting the local node).
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Returns `true` if no peers are declared (single-node deployment).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Returns the minimum number of accepting votes (including the local
    /// node's vote) required to commit a proposal.
    ///
    /// Formula: `⌊N/2⌋ + 1` where `N` is the number of *other* peers.
    /// For an empty peer set returns `0` — single-node always commits.
    #[must_use]
    pub fn quorum_threshold(&self) -> usize {
        if self.peers.is_empty() {
            0
        } else {
            self.peers.len() / 2 + 1
        }
    }
}

impl Default for PeerSet {
    fn default() -> Self {
        Self::new()
    }
}
