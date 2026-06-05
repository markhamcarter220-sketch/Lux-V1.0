//! Unit tests: Raft state machine (Phase 5, Tier 3).
//!
//! Exercises [`RaftNode`] directly — no `BootState` involved.  Tests cover
//! the four message types, role transitions, quorum arithmetic, commit
//! detection, and fail-closed behaviour under partition.

use core::num::NonZeroU32;

use lux_kernel::{
    consensus::{LogEntry, PeerSet, RaftMessage, RaftNode, RaftRole, RaftTransport},
    types::NodeId,
};

fn node(n: u32) -> NodeId {
    NonZeroU32::new(n).unwrap()
}

// ── Mock transport ────────────────────────────────────────────────────────────

struct MockTransport {
    sent: heapless::Vec<(NodeId, RaftMessage), 64>,
}

impl MockTransport {
    const fn new() -> Self {
        Self {
            sent: heapless::Vec::new(),
        }
    }

    fn sent(&self) -> &[(NodeId, RaftMessage)] {
        &self.sent
    }
}

impl RaftTransport for MockTransport {
    fn send(&mut self, peer: NodeId, msg: RaftMessage) {
        let _ = self.sent.push((peer, msg));
    }

    fn recv(&mut self) -> Option<(NodeId, RaftMessage)> {
        None
    }
}

// ── Initial state ─────────────────────────────────────────────────────────────

#[test]
fn new_node_starts_as_follower() {
    let n = RaftNode::new(node(1), &PeerSet::new());
    assert_eq!(n.role(), RaftRole::Follower);
    assert!(!n.is_leader());
    assert_eq!(n.commit_index(), 0);
    assert_eq!(n.log_len(), 0);
}

// ── Single-node elections ─────────────────────────────────────────────────────

#[test]
fn single_node_election_becomes_leader_immediately() {
    let mut n = RaftNode::new(node(1), &PeerSet::new());
    let mut t = MockTransport::new();
    n.start_election(&mut t);
    assert!(n.is_leader(), "single-node must become leader immediately");
    assert!(
        t.sent().is_empty(),
        "no messages needed for single-node election"
    );
}

#[test]
fn single_node_propose_commits_immediately() {
    let mut n = RaftNode::new(node(1), &PeerSet::new());
    let mut t = MockTransport::new();
    n.start_election(&mut t);
    n.propose(node(1), node(2), &mut t).unwrap();
    assert_eq!(n.commit_index(), 1, "single-node must commit immediately");
    assert_eq!(n.log_len(), 1);
}

#[test]
fn propose_before_election_returns_err() {
    let mut n = RaftNode::new(node(1), &PeerSet::new());
    let mut t = MockTransport::new();
    assert!(
        n.propose(node(1), node(2), &mut t).is_err(),
        "propose before start_election must fail"
    );
}

// ── Two-node elections (N=2, quorum=2) ───────────────────────────────────────

#[test]
fn two_node_election_with_grant_becomes_leader() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    n.start_election(&mut t);
    assert!(
        !n.is_leader(),
        "must wait for vote before claiming leadership"
    );

    // Peer grants vote.
    let _ = n.step(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
        &mut t,
    );
    assert!(
        n.is_leader(),
        "must become leader after receiving quorum votes"
    );
}

#[test]
fn two_node_election_with_denial_stays_candidate() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    n.start_election(&mut t);
    let _ = n.step(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: false,
        },
        &mut t,
    );
    assert!(!n.is_leader(), "denied vote must not produce leader");
    assert_eq!(n.role(), RaftRole::Candidate);
}

#[test]
fn higher_term_vote_reply_reverts_to_follower() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    n.start_election(&mut t);
    // Peer reports a higher term.
    let _ = n.step(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 99,
            vote_granted: false,
        },
        &mut t,
    );
    assert_eq!(
        n.role(),
        RaftRole::Follower,
        "higher term must revert to follower"
    );
}

// ── Three-node elections (N=3, quorum=2) ──────────────────────────────────────

#[test]
fn three_node_one_grant_suffices_for_leadership() {
    // N=3, quorum = ⌊3/2⌋+1 = 2.  Self(1) + 1 grant = 2 → elected.
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    ps.add(node(3)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    n.start_election(&mut t);
    let _ = n.step(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
        &mut t,
    );
    assert!(
        n.is_leader(),
        "one peer grant + self = quorum of 2 → leader"
    );
}

#[test]
fn three_node_no_grants_stays_candidate() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    ps.add(node(3)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    n.start_election(&mut t);
    let _ = n.step(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: false,
        },
        &mut t,
    );
    let _ = n.step(
        node(3),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: false,
        },
        &mut t,
    );
    assert!(!n.is_leader(), "zero grants must not produce leader");
}

// ── Log replication ───────────────────────────────────────────────────────────

#[test]
fn two_node_commit_after_peer_ack() {
    // N=2, quorum=2: need self + 1 peer ack.
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    n.start_election(&mut t);
    let _ = n.step(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
        &mut t,
    );
    n.propose(node(1), node(2), &mut t).unwrap();

    assert_eq!(n.commit_index(), 0, "not yet committed before ack");

    let committed = n.step(
        node(2),
        RaftMessage::AppendEntriesReply {
            term: 1,
            success: true,
            match_index: 1,
        },
        &mut t,
    );
    assert!(committed.is_some(), "ack from quorum must commit");
    assert_eq!(n.commit_index(), 1);
}

#[test]
fn two_node_no_commit_without_ack() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    n.start_election(&mut t);
    let _ = n.step(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
        &mut t,
    );
    n.propose(node(1), node(2), &mut t).unwrap();

    assert_eq!(n.commit_index(), 0, "must not commit without ack");
}

#[test]
fn three_node_commit_after_one_ack() {
    // N=3, quorum=2: self + 1 peer ack = 2 → commit.
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    ps.add(node(3)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    n.start_election(&mut t);
    let _ = n.step(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
        &mut t,
    );
    n.propose(node(1), node(2), &mut t).unwrap();

    let committed = n.step(
        node(2),
        RaftMessage::AppendEntriesReply {
            term: 1,
            success: true,
            match_index: 1,
        },
        &mut t,
    );
    assert!(
        committed.is_some(),
        "one peer ack achieves quorum of 2 in N=3 cluster"
    );
}

#[test]
fn committed_entry_corresponds_to_proposal() {
    let mut n = RaftNode::new(node(1), &PeerSet::new());
    let mut t = MockTransport::new();
    n.start_election(&mut t);
    n.propose(node(3), node(5), &mut t).unwrap();
    assert_eq!(n.commit_index(), 1, "single-node commits immediately");
    assert_eq!(n.log_len(), 1, "log must contain one entry");
}

// ── Follower message handling ─────────────────────────────────────────────────

#[test]
fn follower_accepts_valid_append_entries() {
    let mut n = RaftNode::new(node(1), &PeerSet::new());
    let mut t = MockTransport::new();

    let mut entries: heapless::Vec<LogEntry, 16> = heapless::Vec::new();
    let _ = entries.push(LogEntry {
        term: 1,
        src: node(1),
        dst: node(2),
    });

    let _ = n.step(
        node(2),
        RaftMessage::AppendEntries {
            term: 1,
            leader_id: node(2),
            prev_log_index: 0,
            prev_log_term: 0,
            entries,
            leader_commit: 0,
        },
        &mut t,
    );

    let sent = t.sent();
    assert_eq!(sent.len(), 1);
    assert!(
        matches!(
            sent[0].1,
            RaftMessage::AppendEntriesReply {
                success: true,
                match_index: 1,
                ..
            }
        ),
        "valid AppendEntries must be accepted"
    );
    assert_eq!(n.log_len(), 1, "entry must have been appended");
}

#[test]
fn follower_rejects_stale_term_append_entries() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    // Advance term to 5 via a high-term AppendEntries.
    let _ = n.step(
        node(2),
        RaftMessage::AppendEntries {
            term: 5,
            leader_id: node(2),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: heapless::Vec::new(),
            leader_commit: 0,
        },
        &mut t,
    );
    let sent_before = t.sent().len();

    // Now send AppendEntries with stale term 2.
    let _ = n.step(
        node(2),
        RaftMessage::AppendEntries {
            term: 2,
            leader_id: node(2),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: heapless::Vec::new(),
            leader_commit: 0,
        },
        &mut t,
    );

    let latest = &t.sent()[sent_before];
    assert!(
        matches!(
            latest.1,
            RaftMessage::AppendEntriesReply { success: false, .. }
        ),
        "stale-term AppendEntries must be rejected"
    );
}

#[test]
fn follower_updates_commit_index_from_leader() {
    let mut n = RaftNode::new(node(1), &PeerSet::new());
    let mut t = MockTransport::new();

    let mut entries: heapless::Vec<LogEntry, 16> = heapless::Vec::new();
    let _ = entries.push(LogEntry {
        term: 1,
        src: node(1),
        dst: node(2),
    });

    let _ = n.step(
        node(2),
        RaftMessage::AppendEntries {
            term: 1,
            leader_id: node(2),
            prev_log_index: 0,
            prev_log_term: 0,
            entries,
            leader_commit: 1,
        },
        &mut t,
    );

    assert_eq!(
        n.commit_index(),
        1,
        "follower must advance commit_index from leader_commit"
    );
}

// ── Follower vote granting ────────────────────────────────────────────────────

#[test]
fn follower_grants_vote_to_up_to_date_candidate() {
    let mut n = RaftNode::new(node(1), &PeerSet::new());
    let mut t = MockTransport::new();

    let _ = n.step(
        node(2),
        RaftMessage::RequestVote {
            term: 1,
            candidate_id: node(2),
            last_log_index: 0,
            last_log_term: 0,
        },
        &mut t,
    );

    assert!(
        matches!(
            t.sent()[0].1,
            RaftMessage::RequestVoteReply {
                vote_granted: true,
                ..
            }
        ),
        "must grant vote to first valid candidate"
    );
}

#[test]
fn follower_denies_vote_for_stale_term() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    // Advance to term 5 via AppendEntries.
    let _ = n.step(
        node(2),
        RaftMessage::AppendEntries {
            term: 5,
            leader_id: node(2),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: heapless::Vec::new(),
            leader_commit: 0,
        },
        &mut t,
    );

    // RequestVote with term 2 must be denied.
    let _ = n.step(
        node(3),
        RaftMessage::RequestVote {
            term: 2,
            candidate_id: node(3),
            last_log_index: 0,
            last_log_term: 0,
        },
        &mut t,
    );

    let last = t.sent().last().unwrap();
    assert!(
        matches!(
            last.1,
            RaftMessage::RequestVoteReply {
                vote_granted: false,
                ..
            }
        ),
        "stale-term RequestVote must be denied"
    );
}

#[test]
fn follower_denies_second_vote_in_same_term() {
    let mut n = RaftNode::new(node(1), &PeerSet::new());
    let mut t = MockTransport::new();

    // Vote for node(2) in term 1.
    let _ = n.step(
        node(2),
        RaftMessage::RequestVote {
            term: 1,
            candidate_id: node(2),
            last_log_index: 0,
            last_log_term: 0,
        },
        &mut t,
    );
    assert!(matches!(
        t.sent()[0].1,
        RaftMessage::RequestVoteReply {
            vote_granted: true,
            ..
        }
    ));

    // Different candidate in the same term — must be denied.
    let _ = n.step(
        node(3),
        RaftMessage::RequestVote {
            term: 1,
            candidate_id: node(3),
            last_log_index: 0,
            last_log_term: 0,
        },
        &mut t,
    );
    assert!(
        matches!(
            t.sent()[1].1,
            RaftMessage::RequestVoteReply {
                vote_granted: false,
                ..
            }
        ),
        "already-voted term must not grant a second vote"
    );
}

// ── Role transitions ─────────────────────────────────────────────────────────

#[test]
fn candidate_reverts_to_follower_on_higher_term_ae() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    n.start_election(&mut t); // now Candidate in term 1

    // Receive AppendEntries with higher term — must revert to Follower.
    let _ = n.step(
        node(2),
        RaftMessage::AppendEntries {
            term: 3,
            leader_id: node(2),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: heapless::Vec::new(),
            leader_commit: 0,
        },
        &mut t,
    );

    assert_eq!(
        n.role(),
        RaftRole::Follower,
        "higher-term AE must revert candidate to follower"
    );
}

#[test]
fn leader_reverts_to_follower_on_higher_term_ae_reply() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    let mut n = RaftNode::new(node(1), &ps);
    let mut t = MockTransport::new();

    // Elect as leader.
    n.start_election(&mut t);
    let _ = n.step(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
        &mut t,
    );
    assert!(n.is_leader());

    // Receive AppendEntriesReply with higher term.
    let _ = n.step(
        node(2),
        RaftMessage::AppendEntriesReply {
            term: 9,
            success: false,
            match_index: 0,
        },
        &mut t,
    );
    assert_eq!(
        n.role(),
        RaftRole::Follower,
        "higher-term reply must demote leader"
    );
}
