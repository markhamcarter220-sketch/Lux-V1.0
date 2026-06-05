//! Raft consensus message types (Phase 5, Tier 3).
//!
//! `AppendEntries` carries a bounded list of [`LogEntry`] values, so this
//! enum is not `Copy`.  All other variants contain only scalar fields and
//! may be cloned cheaply.

use heapless::Vec;

use crate::types::NodeId;

use super::log::LogEntry;

/// A Raft protocol message.
///
/// Message flow: `RequestVote` → `RequestVoteReply` (election phase);
/// `AppendEntries` → `AppendEntriesReply` (log-replication phase).
///
/// `AppendEntries` carries up to 16 [`LogEntry`] values on the stack; this is
/// intentional in a `no_std` environment where heap allocation is unavailable.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaftMessage {
    /// Candidate requests a vote from a peer during leader election.
    RequestVote {
        /// Candidate's current term.
        term: u64,
        /// ID of the candidate requesting the vote.
        candidate_id: NodeId,
        /// 1-based index of the last entry in the candidate's log.
        last_log_index: u64,
        /// Term of the last entry in the candidate's log.
        last_log_term: u64,
    },

    /// A peer's response to a [`RaftMessage::RequestVote`] message.
    RequestVoteReply {
        /// Peer's current term (allows candidates to update stale terms).
        term: u64,
        /// `true` iff the peer granted its vote.
        vote_granted: bool,
    },

    /// Leader replicates log entries to followers (also serves as heartbeat
    /// when `entries` is empty).
    AppendEntries {
        /// Leader's current term.
        term: u64,
        /// ID of the leader sending this message.
        leader_id: NodeId,
        /// 1-based index of the log entry immediately preceding the new ones.
        prev_log_index: u64,
        /// Term of `prev_log_index` (`0` when `prev_log_index` is `0`).
        prev_log_term: u64,
        /// Log entries to append (capped at 16 per RPC).
        entries: Vec<LogEntry, 16>,
        /// Highest log index the leader has committed.
        leader_commit: u64,
    },

    /// Follower's response to an [`RaftMessage::AppendEntries`] message.
    AppendEntriesReply {
        /// Follower's current term.
        term: u64,
        /// `true` iff the follower accepted and appended all entries.
        success: bool,
        /// Highest log index now matched on the follower (valid when `success`).
        match_index: u64,
    },
}
