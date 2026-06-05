//! Distributed topology consensus: full Raft state machine (Phase 5, Tier 3).
//!
//! Replaces the earlier single-round quorum protocol with a correct,
//! linearisable Raft implementation.  The kernel's four security invariants
//! are preserved:
//!
//! - **I1 (Fail-Closed):** a partitioned minority cannot commit a log entry.
//! - **I2 (Capability-Gated):** consensus does not bypass capability checks.
//! - **I3 (Accountable):** consensus has no resource side-effects.
//! - **I4 (Topology-Bounded):** only entries whose local sealed graph permits
//!   the proposed edge are ever proposed by a well-behaved leader.
//!
//! # Protocol summary
//!
//! 1. The proposer calls [`RaftNode::start_election`] to elect itself leader.
//!    In a single-node cluster this completes immediately.
//! 2. Once [`RaftNode::is_leader`] returns `true`, the proposer calls
//!    [`RaftNode::propose`] with the desired `(src, dst)` pair.
//! 3. Incoming messages from peers are fed through [`RaftNode::step`] until
//!    `step` returns `Some(entry)` — the entry has been committed by a quorum.
//! 4. If the transport is exhausted before commitment the operation is aborted.
//!
//! # Transport
//!
//! The kernel is transport-agnostic.  Callers supply a [`RaftTransport`]
//! implementation that maps `NodeId → network address`.

pub mod log;
pub mod peer;
pub mod protocol;
pub mod raft;

pub use log::{LogEntry, RaftLog};
pub use peer::PeerSet;
pub use protocol::RaftMessage;
pub use raft::{RaftNode, RaftRole, RaftTransport};
