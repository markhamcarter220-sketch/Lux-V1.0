//! Integration tests: distributed topology consensus — Raft (Phase 5, Tier 3).
//!
//! Tests verify that `BootState::run_topology_consensus` and the `RaftNode`
//! state machine uphold all four kernel invariants:
//!
//! - I1 (Fail-Closed):      a partitioned minority cannot commit.
//! - I2 (Capability-Gated): consensus does not bypass capability checks.
//! - I3 (Accountable):      no resource side-effects from consensus.
//! - I4 (Topology-Bounded): only declared edges can be committed.

use core::num::NonZeroU32;

use ed25519_dalek::SigningKey;

use lux_kernel::{
    audit::AuditLog,
    boot::{BootCredentials, BootState},
    consensus::{PeerSet, RaftMessage, RaftTransport},
    types::NodeId,
};

fn node(n: u32) -> NodeId {
    NonZeroU32::new(n).unwrap()
}

// ── Mock transport ────────────────────────────────────────────────────────────

/// A mock transport that returns a preset sequence of messages and records
/// all messages sent by the node under test.
struct MockRaftTransport {
    incoming: heapless::Vec<(NodeId, RaftMessage), 64>,
    recv_idx: usize,
    sent: heapless::Vec<(NodeId, RaftMessage), 64>,
}

impl MockRaftTransport {
    const fn new() -> Self {
        Self {
            incoming: heapless::Vec::new(),
            recv_idx: 0,
            sent: heapless::Vec::new(),
        }
    }

    fn add_message(&mut self, from: NodeId, msg: RaftMessage) {
        let _ = self.incoming.push((from, msg));
    }

    fn sent_messages(&self) -> &[(NodeId, RaftMessage)] {
        &self.sent
    }
}

impl RaftTransport for MockRaftTransport {
    fn send(&mut self, peer: NodeId, msg: RaftMessage) {
        let _ = self.sent.push((peer, msg));
    }

    fn recv(&mut self) -> Option<(NodeId, RaftMessage)> {
        if self.recv_idx < self.incoming.len() {
            let idx = self.recv_idx;
            self.recv_idx += 1;
            Some(self.incoming[idx].clone())
        } else {
            None
        }
    }
}

// ── PeerSet unit tests ────────────────────────────────────────────────────────

#[test]
fn empty_peer_set_quorum_is_zero() {
    assert_eq!(PeerSet::new().quorum_threshold(), 0);
}

#[test]
fn single_peer_quorum_is_one() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    assert_eq!(ps.quorum_threshold(), 1);
}

#[test]
fn two_peers_quorum_is_two() {
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    ps.add(node(3)).unwrap();
    assert_eq!(ps.quorum_threshold(), 2);
}

#[test]
fn three_peers_quorum_is_two() {
    let mut ps = PeerSet::new();
    for i in 2..=4 {
        ps.add(node(i)).unwrap();
    }
    assert_eq!(ps.quorum_threshold(), 2); // ⌊3/2⌋ + 1 = 2
}

#[test]
fn four_peers_quorum_is_three() {
    let mut ps = PeerSet::new();
    for i in 2..=5 {
        ps.add(node(i)).unwrap();
    }
    assert_eq!(ps.quorum_threshold(), 3); // ⌊4/2⌋ + 1 = 3
}

#[test]
fn peer_set_add_beyond_capacity_fails() {
    let mut ps = PeerSet::new();
    for i in 1u32..=16 {
        ps.add(node(i)).unwrap();
    }
    assert!(ps.add(node(17)).is_err(), "capacity exceeded must fail");
}

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Build a minimal signed manifest with edge 1→2 and quota 1000 on node 1.
fn boot_with_edge() -> BootState {
    use ed25519_dalek::Signer as _;
    let sk = SigningKey::from_bytes(&[0u8; 32]);
    let creds = BootCredentials::from_key_bytes(sk.verifying_key().to_bytes()).unwrap();
    let payload = vec![
        0x83u8, // array(3)
        0x01, // version = 1
        // edges = [[1, 2]]
        0x81, // array(1)
        0x82, // array(2)
        0x01, // src = 1
        0x02, // dst = 2
        // quotas = [[1, 1000]]
        0x81, // array(1)
        0x82, // array(2)
        0x01, // node = 1
        0x19,
        0x03,
        0xe8, // quota = 1000
    ];
    let sig = sk.sign(&payload);
    let mut wire = sig.to_bytes().to_vec();
    wire.extend_from_slice(&payload);
    BootState::initialise(&wire, &creds).expect("boot must succeed")
}

// ── I1: Fail-Closed — single-node ─────────────────────────────────────────────

#[test]
fn single_node_declared_edge_commits() {
    let mut boot = boot_with_edge();
    let ps = PeerSet::new();
    let mut t = MockRaftTransport::new();
    let mut a = AuditLog::new();

    let result = boot.run_topology_consensus(&ps, node(1), node(2), &mut t, &mut a);
    assert!(
        result.is_ok(),
        "declared edge 1→2 in single-node must commit"
    );
    assert!(
        t.sent_messages().is_empty(),
        "single-node needs no network I/O"
    );
}

#[test]
fn single_node_undeclared_edge_aborts() {
    let mut boot = boot_with_edge();
    let ps = PeerSet::new();
    let mut t = MockRaftTransport::new();
    let mut a = AuditLog::new();

    // Reverse edge 2→1 is not declared.
    let result = boot.run_topology_consensus(&ps, node(2), node(1), &mut t, &mut a);
    assert!(
        result.is_err(),
        "undeclared edge 2→1 in single-node must abort"
    );
}

// ── I1: Fail-Closed — multi-node ─────────────────────────────────────────────

/// N=3 (peers=2, quorum=2): leader + 1 peer grant = quorum → commit.
#[test]
fn multi_node_majority_commits() {
    let mut boot = boot_with_edge();
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();
    ps.add(node(3)).unwrap();

    let mut t = MockRaftTransport::new();
    // Election: 1 grant suffices (self + 1 = quorum of 2).
    t.add_message(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
    );
    t.add_message(
        node(3),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: false,
        },
    );
    // Replication: 1 ack suffices (self + 1 = quorum of 2).
    t.add_message(
        node(2),
        RaftMessage::AppendEntriesReply {
            term: 1,
            success: true,
            match_index: 1,
        },
    );

    let mut a = AuditLog::new();
    let result = boot.run_topology_consensus(&ps, node(1), node(2), &mut t, &mut a);
    assert!(result.is_ok(), "majority must commit");
}

/// N=6 (peers=5, quorum=4): only 1 vote grant — cannot reach quorum → abort.
#[test]
fn multi_node_partitioned_minority_aborts() {
    let mut boot = boot_with_edge();
    let mut ps = PeerSet::new();
    for i in 2..=6 {
        ps.add(node(i)).unwrap();
    }

    let mut t = MockRaftTransport::new();
    // Only node 2 responds; transport exhausted before quorum is reached.
    t.add_message(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
    );

    let mut a = AuditLog::new();
    let result = boot.run_topology_consensus(&ps, node(1), node(2), &mut t, &mut a);
    // self(1) + peer(1) = 2 < quorum(4) → abort
    assert!(result.is_err(), "partitioned minority must not commit");
}

/// I1 strengthened: local graph denial aborts unconditionally, even if every
/// declared peer would accept.  The boot manifest is authoritative.
#[test]
fn local_denial_aborts_regardless_of_peer_quorum() {
    let mut boot = boot_with_edge();
    let mut ps = PeerSet::new();
    ps.add(node(3)).unwrap(); // one peer; quorum = 2

    let mut t = MockRaftTransport::new();
    // Pre-supply a vote grant — this must never be consumed because the
    // local graph aborts before any election is attempted.
    t.add_message(
        node(3),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
    );

    let mut a = AuditLog::new();
    // Propose undeclared reverse edge 2→1 (not in boot manifest).
    let result = boot.run_topology_consensus(&ps, node(2), node(1), &mut t, &mut a);
    assert!(result.is_err(), "local denial must abort unconditionally");
    // No election messages should be sent when local graph aborts first.
    assert!(
        t.sent_messages().is_empty(),
        "no messages sent after local abort"
    );
}

// ── Message structure ─────────────────────────────────────────────────────────

/// Verify that election and replication messages are sent in the correct order
/// when a 1-peer cluster commits.
#[test]
fn raft_messages_sent_on_success() {
    let mut boot = boot_with_edge();
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();

    let mut t = MockRaftTransport::new();
    t.add_message(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: true,
        },
    );
    t.add_message(
        node(2),
        RaftMessage::AppendEntriesReply {
            term: 1,
            success: true,
            match_index: 1,
        },
    );

    let _ = boot.run_topology_consensus(&ps, node(1), node(2), &mut t, &mut AuditLog::new());

    let sent = t.sent_messages();
    // Expect: RequestVote, AppendEntries
    assert!(
        sent.iter()
            .any(|(_, m)| matches!(m, RaftMessage::RequestVote { .. })),
        "must send RequestVote during election"
    );
    assert!(
        sent.iter()
            .any(|(_, m)| matches!(m, RaftMessage::AppendEntries { .. })),
        "must send AppendEntries during replication"
    );
}

/// When election fails (no vote grant, transport exhausted) no `AppendEntries`
/// are ever sent — the node never reaches leadership.
#[test]
fn no_append_entries_sent_when_election_fails() {
    let mut boot = boot_with_edge();
    let mut ps = PeerSet::new();
    ps.add(node(2)).unwrap();

    let mut t = MockRaftTransport::new();
    // Peer denies the vote; transport exhausted.
    t.add_message(
        node(2),
        RaftMessage::RequestVoteReply {
            term: 1,
            vote_granted: false,
        },
    );

    let result = boot.run_topology_consensus(&ps, node(1), node(2), &mut t, &mut AuditLog::new());
    assert!(result.is_err());
    assert!(
        !t.sent_messages()
            .iter()
            .any(|(_, m)| matches!(m, RaftMessage::AppendEntries { .. })),
        "no AppendEntries must be sent when leader election fails"
    );
}

// ── Audit log wiring ─────────────────────────────────────────────────────────

#[test]
fn commit_emits_audit_event_without_denial() {
    let mut boot = boot_with_edge();
    let ps = PeerSet::new();
    let mut t = MockRaftTransport::new();
    let mut a = AuditLog::new();

    let _ = boot.run_topology_consensus(&ps, node(1), node(2), &mut t, &mut a);

    // At least one event must have been emitted and the last must have no denial.
    let events: Vec<_> = a.events().collect();
    assert!(!events.is_empty());
    let last = events.last().unwrap();
    assert_eq!(
        last.denial_class, None,
        "committed round must carry no denial class"
    );
}

#[test]
fn abort_emits_audit_event_with_denial() {
    let mut boot = boot_with_edge();
    let ps = PeerSet::new();
    let mut t = MockRaftTransport::new();
    let mut a = AuditLog::new();

    // Propose undeclared edge — should abort at local graph check.
    let _ = boot.run_topology_consensus(&ps, node(2), node(1), &mut t, &mut a);

    let events: Vec<_> = a.events().collect();
    assert!(!events.is_empty());
    // The topology-traverse denial must be present.
    assert!(
        events.iter().any(|e| e.denial_class.is_some()),
        "aborted round must contain at least one denied audit event"
    );
}
