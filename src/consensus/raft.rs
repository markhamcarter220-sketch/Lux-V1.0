//! Raft consensus state machine (Phase 5, Tier 3).
//!
//! [`RaftNode`] is a synchronous, zero-allocation Raft state machine.  It has
//! no internal timers or threads; the caller drives it by:
//!
//! 1. Calling [`RaftNode::start_election`] — single-node clusters become
//!    leader immediately; multi-node clusters broadcast `RequestVote`.
//! 2. Feeding incoming messages through [`RaftNode::step`] until
//!    [`RaftNode::is_leader`] is `true`.
//! 3. Calling [`RaftNode::propose`] with the desired topology traversal.
//! 4. Continuing to feed messages through [`RaftNode::step`] until it returns
//!    `Some(entry)` — the entry has been committed by a quorum.
//!
//! # Fail-closed semantics
//!
//! If the transport is exhausted before a quorum is reached, every `step`
//! call returns `None` and the caller must abort the operation.

use heapless::Vec;

use crate::{error::Error, types::NodeId, Result};

use super::{
    log::{LogEntry, RaftLog},
    peer::MAX_PEERS,
    protocol::RaftMessage,
    PeerSet,
};

/// Transport abstraction for Raft message exchange.
///
/// Implementations are responsible for serialisation, addressing, and
/// delivery.  Send failures must be silently absorbed.
pub trait RaftTransport {
    /// Send `msg` to `peer`.
    fn send(&mut self, peer: NodeId, msg: RaftMessage);

    /// Receive the next message from any peer.
    ///
    /// Returns `Some((from, msg))` while messages are available, `None` when
    /// the receive window is exhausted (timeout or no more buffered messages).
    fn recv(&mut self) -> Option<(NodeId, RaftMessage)>;
}

/// The role a [`RaftNode`] currently occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaftRole {
    /// Accepts log entries from the current leader.
    Follower,
    /// Has started an election and is collecting votes.
    Candidate,
    /// Has won an election and coordinates log replication.
    Leader,
}

/// Bundled parameters for an `AppendEntries` RPC, kept internal to reduce the
/// argument count of [`RaftNode::on_append_entries`].
#[derive(Debug)]
struct AeParams {
    term:           u64,
    prev_log_index: u64,
    prev_log_term:  u64,
    entries:        Vec<LogEntry, 16>,
    leader_commit:  u64,
}

/// Bundled parameters for a `RequestVote` RPC, kept internal to reduce the
/// argument count of [`RaftNode::on_request_vote`].
#[derive(Debug, Clone, Copy)]
struct RvParams {
    term:           u64,
    candidate_id:   NodeId,
    last_log_index: u64,
    last_log_term:  u64,
}

/// Raft consensus state machine for distributed topology validation.
///
/// See the [module documentation](self) for the caller contract.
#[derive(Debug)]
pub struct RaftNode {
    id:           NodeId,
    role:         RaftRole,
    current_term: u64,
    voted_for:    Option<NodeId>,
    log:          RaftLog,
    commit_index: u64,
    votes_granted: usize,
    peers:        Vec<NodeId, MAX_PEERS>,
    next_index:   [u64; MAX_PEERS],
    match_index:  [u64; MAX_PEERS],
}

impl RaftNode {
    /// Construct a new `RaftNode` as a Follower in term 0.
    ///
    /// `id` is this node's identity; `peer_set` enumerates the other nodes.
    #[must_use]
    pub fn new(id: NodeId, peer_set: &PeerSet) -> Self {
        let mut peers = Vec::new();
        for &p in peer_set.peers() {
            let _ = peers.push(p);
        }
        Self {
            id,
            role:          RaftRole::Follower,
            current_term:  0,
            voted_for:     None,
            log:           RaftLog::new(),
            commit_index:  0,
            votes_granted: 0,
            peers,
            next_index:    [1u64; MAX_PEERS],
            match_index:   [0u64; MAX_PEERS],
        }
    }

    /// Returns the node's current [`RaftRole`].
    #[must_use]
    pub const fn role(&self) -> RaftRole {
        self.role
    }

    /// Returns `true` if this node is the current cluster leader.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.role == RaftRole::Leader
    }

    /// Returns the highest log index known to be committed on this node.
    #[must_use]
    pub const fn commit_index(&self) -> u64 {
        self.commit_index
    }

    /// Returns the number of log entries held by this node.
    #[must_use]
    pub fn log_len(&self) -> u64 {
        self.log.len()
    }

    /// Start a leader election by incrementing the term and soliciting votes.
    ///
    /// For a single-node cluster the node becomes leader immediately without
    /// any transport interaction.
    pub fn start_election(&mut self, transport: &mut impl RaftTransport) {
        self.current_term += 1;
        self.role = RaftRole::Candidate;
        self.voted_for = Some(self.id);
        self.votes_granted = 1;

        if self.peers.is_empty() {
            self.become_leader(transport);
            return;
        }

        let msg = RaftMessage::RequestVote {
            term:           self.current_term,
            candidate_id:   self.id,
            last_log_index: self.log.last_index(),
            last_log_term:  self.log.last_term(),
        };
        for &peer in &self.peers {
            transport.send(peer, msg.clone());
        }
    }

    /// Propose a topology traversal as a new Raft log entry (leader only).
    ///
    /// Appends `LogEntry { term, src, dst }` and replicates it to all peers.
    /// For a single-node cluster the entry is committed immediately.
    ///
    /// # Errors
    ///
    /// - [`Error::UndefinedState`] if this node is not the leader.
    /// - [`Error::QuotaExceeded`] if the log is at capacity (256 entries).
    pub fn propose(
        &mut self,
        src: NodeId,
        dst: NodeId,
        transport: &mut impl RaftTransport,
    ) -> Result<()> {
        if self.role != RaftRole::Leader {
            return Err(Error::UndefinedState { context: "raft: cannot propose — not leader" });
        }
        let entry = LogEntry { term: self.current_term, src, dst };
        if !self.log.append(entry) {
            return Err(Error::QuotaExceeded { resource: "raft log at capacity" });
        }
        let entry_index = self.log.last_index();
        if self.peers.is_empty() {
            self.commit_index = entry_index;
            return Ok(());
        }
        for idx in 0..self.peers.len() {
            self.send_ae_to(idx, transport);
        }
        Ok(())
    }

    /// Process a message from `from` and advance the state machine.
    ///
    /// Returns `Some(entry)` when a new log entry is committed as a result,
    /// `None` otherwise.
    #[must_use]
    pub fn step(
        &mut self,
        from: NodeId,
        msg: RaftMessage,
        transport: &mut impl RaftTransport,
    ) -> Option<LogEntry> {
        match msg {
            RaftMessage::RequestVote {
                term,
                candidate_id,
                last_log_index,
                last_log_term,
            } => {
                self.on_request_vote(
                    from,
                    RvParams { term, candidate_id, last_log_index, last_log_term },
                    transport,
                );
                None
            }
            RaftMessage::RequestVoteReply { term, vote_granted } => {
                self.on_vote_reply(term, vote_granted, transport)
            }
            RaftMessage::AppendEntries {
                term,
                leader_id: _,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            } => {
                self.on_append_entries(
                    from,
                    &AeParams { term, prev_log_index, prev_log_term, entries, leader_commit },
                    transport,
                );
                None
            }
            RaftMessage::AppendEntriesReply { term, success, match_index } => {
                self.on_ae_reply(from, term, success, match_index)
            }
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn become_leader(&mut self, _transport: &mut impl RaftTransport) {
        self.role = RaftRole::Leader;
        let next = self.log.last_index() + 1;
        for i in 0..self.peers.len() {
            self.next_index[i] = next;
            self.match_index[i] = 0;
        }
    }

    fn quorum(&self) -> usize {
        self.peers.len().div_ceil(2) + 1
    }

    fn peer_index(&self, peer: NodeId) -> Option<usize> {
        self.peers.iter().position(|&p| p == peer)
    }

    fn step_down(&mut self, term: u64) {
        self.current_term = term;
        self.role = RaftRole::Follower;
        self.voted_for = None;
    }

    fn log_up_to_date_for(&self, last_log_index: u64, last_log_term: u64) -> bool {
        last_log_term > self.log.last_term()
            || (last_log_term == self.log.last_term()
                && last_log_index >= self.log.last_index())
    }

    fn send_ae_to(&self, peer_idx: usize, transport: &mut impl RaftTransport) {
        if peer_idx >= self.peers.len() {
            return;
        }
        let peer       = self.peers[peer_idx];
        let next       = self.next_index[peer_idx];
        let prev_index = next.saturating_sub(1);
        let prev_term  = if prev_index == 0 {
            0
        } else {
            self.log.term_at(prev_index).unwrap_or(0)
        };

        let mut entries: Vec<LogEntry, 16> = Vec::new();
        let mut idx = next;
        while let Some(&entry) = self.log.get(idx) {
            if entries.push(entry).is_err() {
                break;
            }
            idx += 1;
        }

        transport.send(
            peer,
            RaftMessage::AppendEntries {
                term:           self.current_term,
                leader_id:      self.id,
                prev_log_index: prev_index,
                prev_log_term:  prev_term,
                entries,
                leader_commit:  self.commit_index,
            },
        );
    }

    fn on_request_vote(
        &mut self,
        from: NodeId,
        rv: RvParams,
        transport: &mut impl RaftTransport,
    ) {
        if rv.term > self.current_term {
            self.step_down(rv.term);
        }
        let log_ok   = self.log_up_to_date_for(rv.last_log_index, rv.last_log_term);
        let can_vote = self.voted_for.map_or(true, |v| v == rv.candidate_id);
        let vote_granted = rv.term >= self.current_term && log_ok && can_vote;
        if vote_granted {
            self.voted_for = Some(rv.candidate_id);
        }
        transport.send(
            from,
            RaftMessage::RequestVoteReply { term: self.current_term, vote_granted },
        );
    }

    fn on_vote_reply(
        &mut self,
        term: u64,
        vote_granted: bool,
        transport: &mut impl RaftTransport,
    ) -> Option<LogEntry> {
        if term > self.current_term {
            self.step_down(term);
            return None;
        }
        if self.role != RaftRole::Candidate || term != self.current_term {
            return None;
        }
        if vote_granted {
            self.votes_granted += 1;
        }
        if self.votes_granted >= self.quorum() {
            self.become_leader(transport);
        }
        None
    }

    fn on_append_entries(
        &mut self,
        from: NodeId,
        ae: &AeParams,
        transport: &mut impl RaftTransport,
    ) {
        if ae.term < self.current_term {
            transport.send(
                from,
                RaftMessage::AppendEntriesReply {
                    term: self.current_term,
                    success: false,
                    match_index: 0,
                },
            );
            return;
        }
        if ae.term > self.current_term {
            self.step_down(ae.term);
        } else {
            self.role = RaftRole::Follower;
        }
        let prev_ok = ae.prev_log_index == 0
            || self.log.term_at(ae.prev_log_index) == Some(ae.prev_log_term);
        if !prev_ok {
            transport.send(
                from,
                RaftMessage::AppendEntriesReply {
                    term: self.current_term,
                    success: false,
                    match_index: 0,
                },
            );
            return;
        }
        let match_index = self.append_log_entries(ae.prev_log_index, &ae.entries);
        if ae.leader_commit > self.commit_index {
            self.commit_index = ae.leader_commit.min(self.log.last_index());
        }
        transport.send(
            from,
            RaftMessage::AppendEntriesReply {
                term: self.current_term,
                success: true,
                match_index,
            },
        );
    }

    fn append_log_entries(&mut self, prev_log_index: u64, entries: &[LogEntry]) -> u64 {
        let mut log_idx = prev_log_index + 1;
        for &entry in entries {
            if let Some(existing_term) = self.log.term_at(log_idx) {
                if existing_term != entry.term {
                    self.log.truncate_from(log_idx);
                }
            }
            if self.log.get(log_idx).is_none() {
                let _ = self.log.append(entry);
            }
            log_idx += 1;
        }
        prev_log_index + entries.len() as u64
    }

    fn on_ae_reply(
        &mut self,
        from: NodeId,
        term: u64,
        success: bool,
        match_index: u64,
    ) -> Option<LogEntry> {
        if term > self.current_term {
            self.step_down(term);
            return None;
        }
        if self.role != RaftRole::Leader || term != self.current_term {
            return None;
        }
        let peer_idx = self.peer_index(from)?;
        if success {
            self.next_index[peer_idx]  = match_index + 1;
            self.match_index[peer_idx] = match_index;
        } else if self.next_index[peer_idx] > 1 {
            self.next_index[peer_idx] -= 1;
        }
        if success && self.advance_commit_index() {
            return self.log.get(self.commit_index).copied();
        }
        None
    }

    fn advance_commit_index(&mut self) -> bool {
        let old     = self.commit_index;
        let n_peers = self.peers.len();
        let log_len = self.log.last_index();
        for n in (self.commit_index + 1..=log_len).rev() {
            if self.log.term_at(n) != Some(self.current_term) {
                continue;
            }
            let acked = 1
                + self.match_index[..n_peers]
                    .iter()
                    .filter(|&&m| m >= n)
                    .count();
            if acked >= self.quorum() {
                self.commit_index = n;
                break;
            }
        }
        self.commit_index > old
    }
}
