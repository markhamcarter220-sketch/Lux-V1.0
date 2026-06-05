//! Distributed topology consensus protocol (Tier 3, Item 5).
//!
//! Implements the single-round quorum vote described in
//! `docs/adr/0004-distributed-topology-consensus.md`.
//!
//! # Protocol summary
//!
//! 1. The proposer broadcasts a `Propose { round_id, src, dst }` to all peers.
//! 2. Each peer checks its own sealed graph and returns `Vote { accept, attestation }`.
//! 3. The proposer tallies votes (including its own local verdict).
//! 4. If `accepts ≥ quorum_threshold`, it broadcasts `Commit` and returns `Ok(())`.
//! 5. Otherwise it broadcasts `Abort` and returns `Err(TopologyViolation)`.
//!
//! # Fail-closed guarantee
//!
//! Any communication failure (send error, missing vote, timeout) counts as a
//! non-accepting vote.  A partitioned minority can never commit.
//!
//! # Single-node deployments
//!
//! When `PeerSet::peers()` is empty the round degenerates to a local check:
//! the proposal is committed iff the local verdict is `accept = true`.
//!
//! # Transport
//!
//! The kernel is transport-agnostic.  Callers provide a [`Transport`]
//! implementation that maps `NodeId → network address`.

pub mod peer;
pub mod protocol;

pub use peer::PeerSet;
pub use protocol::ConsensusMessage;

use crate::{
    audit::{AuditLog, EventKind},
    error::{DenialClass, Error},
    types::NodeId,
    Result,
};

/// Proposal parameters for a single consensus round.
///
/// Groups the per-round arguments to [`run_consensus_proposal`], reducing the
/// number of positional parameters below the `too_many_arguments` threshold.
#[derive(Debug)]
pub struct ConsensusProposal {
    /// Monotonic round counter (caller-managed).
    pub round_id: u64,
    /// Source node of the proposed topology traversal.
    pub src: NodeId,
    /// Destination node of the proposed topology traversal.
    pub dst: NodeId,
    /// Whether the local sealed graph permits `(src, dst)`.
    pub local_accept: bool,
    /// The local node's TPM boot quote bytes.
    pub local_attestation: [u8; 64],
}

/// Transport abstraction for consensus message exchange.
///
/// Implementations are responsible for serialisation, addressing, and
/// delivery.  All transport errors are treated as non-votes (fail-closed).
pub trait Transport {
    /// Send `msg` to `peer`.
    ///
    /// A send failure is **not** propagated — the proposer treats it as a
    /// non-accepting vote for that peer, maintaining fail-closed behaviour.
    fn send(&mut self, peer: NodeId, msg: ConsensusMessage);

    /// Receive the next vote from any peer.
    ///
    /// Returns `Some((peer_id, accept, attestation_bytes))` when a vote is
    /// available, or `None` when the receive window is exhausted (timeout /
    /// no more peers).
    fn recv_vote(&mut self) -> Option<(NodeId, bool, [u8; 64])>;
}

/// Run one consensus round as the proposer.
///
/// Broadcasts `Propose` to all declared peers, collects `Vote` responses,
/// and commits or aborts based on quorum.
///
/// The local node's verdict (`proposal.local_accept`) and attestation
/// (`proposal.local_attestation`) count toward the tally alongside peer votes.
///
/// # Fail-closed semantics
///
/// Any of the following conditions cause the round to abort with
/// `Err(TopologyViolation { src, dst })`:
/// - The local verdict is `false` and peer votes don't compensate.
/// - Fewer than `peer_set.quorum_threshold()` accepting votes are collected.
/// - A peer vote is not received within the transport's window.
///
/// An audit event is always emitted — `EventKind::TopologyChange` with the
/// appropriate `DenialClass` for failures.
///
/// # Parameters
///
/// - `peer_set`  — declared peers (from boot manifest).
/// - `proposal`  — per-round parameters (see [`ConsensusProposal`]).
/// - `transport` — send/recv implementation.
/// - `audit`     — audit log to append the outcome event.
///
/// # Errors
/// Returns `Err(TopologyViolation)` when the traversal is denied by quorum or the local graph.
pub fn run_consensus_proposal<T: Transport>(
    peer_set:  &PeerSet,
    proposal:  &ConsensusProposal,
    transport: &mut T,
    audit:     &mut AuditLog,
) -> Result<()> {
    let round_id     = proposal.round_id;
    let src          = proposal.src;
    let dst          = proposal.dst;
    let local_accept = proposal.local_accept;

    let threshold = peer_set.quorum_threshold();

    // ── Single-node fast path ─────────────────────────────────────────────────
    // When no peers are declared (PeerSet::new() / single-node deployment),
    // threshold = 0 so the local verdict is the only input.
    if peer_set.is_empty() {
        let denial = (!local_accept).then_some((DenialClass::Halt, "edge not in boot manifest"));
        audit.append(EventKind::TopologyChange, src.get(), 0, denial);
        return if local_accept {
            Ok(())
        } else {
            Err(Error::TopologyViolation { src: src.get(), dst: dst.get() })
        };
    }

    // ── Broadcast Propose to all peers ────────────────────────────────────────
    let propose = ConsensusMessage::Propose { round_id, src: src.get(), dst: dst.get() };
    for &peer in peer_set.peers() {
        transport.send(peer, propose);
    }

    // ── Collect votes ─────────────────────────────────────────────────────────
    // Seed with the local vote.  The local attestation is held in memory; only
    // peer attestations arrive over the transport.
    let mut accepts = usize::from(local_accept);
    let peer_count   = peer_set.peers().len();
    let total_voters = peer_count + 1; // peers + self
    let mut votes_received = 1usize;

    // Track whether we can early-exit (quorum decided regardless of remaining
    // votes).
    while votes_received < total_voters {
        match transport.recv_vote() {
            Some((_peer, accept, _attest)) => {
                votes_received += 1;
                if accept { accepts += 1; }
                // Early-exit: quorum reached → no need to wait for remaining votes.
                if accepts >= threshold { break; }
                // Early-exit: quorum impossible even if all remaining votes accept.
                let remaining = total_voters - votes_received;
                if accepts + remaining < threshold { break; }
            }
            None => break, // Transport exhausted (timeout / no more peers).
        }
    }

    let committed = accepts >= threshold;

    // ── Broadcast outcome ─────────────────────────────────────────────────────
    let outcome_msg = if committed {
        ConsensusMessage::Commit { round_id }
    } else {
        ConsensusMessage::Abort { round_id }
    };
    for &peer in peer_set.peers() {
        transport.send(peer, outcome_msg);
    }

    // ── Emit audit event ──────────────────────────────────────────────────────
    let denial = (!committed).then_some((DenialClass::Halt, "topology consensus not reached"));
    audit.append(EventKind::TopologyChange, src.get(), 0, denial);

    // The local_attestation field would be included in the Propose message in a
    // production implementation so peers can verify the proposer's attestation
    // before voting.
    let _ = proposal.local_attestation;

    if committed {
        Ok(())
    } else {
        Err(Error::TopologyViolation { src: src.get(), dst: dst.get() })
    }
}
