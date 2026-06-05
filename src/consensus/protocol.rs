//! Consensus message types for the distributed topology protocol (Item 5).
//!
//! Messages are `Copy` and fixed-size so they work in `no_std` without heap
//! allocation.  The transport layer is responsible for serialisation.

/// A single message in the distributed topology consensus protocol.
///
/// Messages flow as: `Propose` → `Vote` (per peer) → `Commit` or `Abort`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusMessage {
    /// Proposer broadcasts a candidate topology traversal to all peers.
    ///
    /// Each peer independently checks whether `(src, dst)` is permitted in
    /// its own sealed graph and responds with a `Vote`.
    Propose {
        /// Monotonically increasing round identifier.
        round_id: u64,
        /// Source node ID of the proposed traversal.
        src: u32,
        /// Destination node ID of the proposed traversal.
        dst: u32,
    },

    /// A peer's response to a `Propose` message.
    ///
    /// `attestation` carries the peer's TPM quote so the proposer can verify
    /// the peer booted from an attested image.  Peers with a null attestation
    /// (all-zeros) still vote but their vote is informational only — the
    /// proposer may choose to exclude them from quorum.
    Vote {
        /// Must match the `round_id` of the corresponding `Propose`.
        round_id: u64,
        /// `true` if the peer's local graph permits `(src, dst)`.
        accept: bool,
        /// 64-byte TPM quote from the voting peer's boot sequence.
        attestation: [u8; 64],
    },

    /// Proposer notifies all peers that a quorum of accepts was received.
    Commit {
        /// Identifies the round being committed.
        round_id: u64,
    },

    /// Proposer notifies all peers that quorum was not reached (or timed out).
    Abort {
        /// Identifies the round being aborted.
        round_id: u64,
    },
}
