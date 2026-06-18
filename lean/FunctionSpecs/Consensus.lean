import FunctionSpecs.Core

open FunctionSpecs

/-!
# Lux Kernel — Function Spec Layer: Consensus (Raft)

Covers every production function in:

- `src/consensus/mod.rs`   (re-exports only — no functions to spec)
- `src/consensus/log.rs`   (`LogEntry`, `RaftLog`)
- `src/consensus/peer.rs`  (`PeerSet`)
- `src/consensus/protocol.rs` (`RaftMessage` — a pure data enum with no impl
  block in the Rust source; no functions to spec, only the type itself,
  which is modelled below as `RaftMessage` for use by `raft.rs` specs)
- `src/consensus/raft.rs`  (`RaftNode`, `RaftRole`, `RaftTransport`)

**Total functions specified: 39.**

This file follows the spec-layer discipline established in `Core.lean`:
every function gets an `opaque` (or, for genuinely trivial pure accessors, a
direct `def`) signature plus an independent `_pre`/`_post` pair.  No
`theorem`, no `sorry`, no attempt to connect the declarations by proof.

## REFINEMENT_GAP entries in this file

| Function | file:line | Reason |
|---|---|---|
| `startElection` | `src/consensus/raft.rs:146` | Behaviour bifurcates on cluster size and has a transport side-effect (broadcast) that is not capturable by a single state-transition predicate without modelling message delivery. |
| `step` | `src/consensus/raft.rs:214` | Dispatches to one of four sub-protocol handlers depending on message variant; a faithful postcondition would have to restate all four handlers' postconditions, which would make this spec redundant rather than load-bearing — kept weak intentionally. |
| `becomeLeader` | `src/consensus/raft.rs:273` | Mutates per-peer arrays (`next_index`, `match_index`) over a `for` loop bounded by `self.peers.len()`; precise per-index postcondition is stated but the function also depends on the (ignored) transport parameter in a way that has no observable effect, which is easy to mis-specify. |
| `sendAeTo` | `src/consensus/raft.rs:301` | Builds a bounded-capacity entry list by walking the log from `next_index` until either the log or the 16-slot capacity is exhausted; the loop bound is data-dependent (log contents), resisting a tight closed-form postcondition. |
| `onRequestVote` | `src/consensus/raft.rs:336` | Combines a term-driven step-down, an up-to-date log check, and a vote-granting decision in one function with a transport side-effect; modelled but the interaction of all three conditions with the *prior* `voted_for` state is multi-branch and easy to misstate exhaustively. |
| `onAppendEntries` | `src/consensus/raft.rs:377` | Classic Raft `AppendEntries` handler — three early-return branches (stale term, log mismatch) plus a success path that mutates the log and commit index; the full case analysis is large and timing/ordering-sensitive. |
| `appendLogEntries` | `src/consensus/raft.rs:426` | Iterates entries performing conditional truncate-then-append per slot; the resulting log state depends on the *existing* log contents at each index in a way that's awkward to state as a single non-recursive postcondition. |
| `onAeReply` | `src/consensus/raft.rs:442` | Combines stale-term step-down, leader/term guard, peer-index lookup, `next_index`/`match_index` bookkeeping, and a conditional call into `advance_commit_index` whose own result feeds the return value. |
| `advanceCommitIndex` | `src/consensus/raft.rs:469` | Searches log indices in descending order for the highest index satisfying the Raft commit rule (current-term entry acked by a quorum); the search-and-stop-at-first-match semantics over an arbitrary log length resist a tight closed-form postcondition without re-deriving the search itself. |
-/

namespace FunctionSpecs.Consensus

-- ── Domain types (mirrors `src/consensus/log.rs`, `peer.rs`, `protocol.rs`,
--    `raft.rs`) ──────────────────────────────────────────────────────────────

/-- Mirrors `src/consensus/log.rs::LogEntry` — a single proposed topology
    traversal recorded at a given Raft term. -/
structure LogEntry where
  term : Nat
  src : NodeId
  dst : NodeId
  deriving DecidableEq, Repr

/-- Mirrors `src/consensus/log.rs::RaftLog<const N: usize = 256>`.  The
    fixed capacity `N` (default 256) is modelled as an explicit field rather
    than a type-level parameter, since Lean's `opaque`/`def` signatures here
    are simple data, not dependently-sized containers.  `entries` is
    logically 1-indexed in the Rust source (index 0 = "no entry"); here we
    keep the underlying list 0-indexed and have the spec functions perform
    the `index - 1` translation explicitly, matching the Rust `get`/`term_at`
    bodies. -/
structure RaftLog where
  entries : List LogEntry
  capacity : Nat := 256
  deriving DecidableEq, Repr

/-- Mirrors `src/consensus/peer.rs::PeerSet`.  `MAX_PEERS = 16`. -/
structure PeerSet where
  peers : List NodeId
  deriving DecidableEq, Repr

/-- `src/consensus/peer.rs::MAX_PEERS`. -/
def MAX_PEERS : Nat := 16

/-- Mirrors `src/consensus/raft.rs::RaftRole`. -/
inductive RaftRole where
  | Follower
  | Candidate
  | Leader
  deriving DecidableEq, Repr

/-- Mirrors `src/consensus/protocol.rs::RaftMessage`.  `AppendEntries.entries`
    is capped at 16 in the Rust source (`heapless::Vec<LogEntry, 16>`); the
    cap is recorded as a side-condition in `_pre`/`_post` predicates that
    construct or consume this variant, not in the type itself. -/
inductive RaftMessage where
  | RequestVote (term : Nat) (candidateId : NodeId) (lastLogIndex : Nat) (lastLogTerm : Nat)
  | RequestVoteReply (term : Nat) (voteGranted : Bool)
  | AppendEntries (term : Nat) (leaderId : NodeId) (prevLogIndex : Nat)
      (prevLogTerm : Nat) (entries : List LogEntry) (leaderCommit : Nat)
  | AppendEntriesReply (term : Nat) (success : Bool) (matchIndex : Nat)
  deriving DecidableEq, Repr

/-- Opaque transport handle.  Mirrors the Rust trait
    `src/consensus/raft.rs::RaftTransport` (generic parameter `T: RaftTransport`
    appears in `RaftNode` methods).  We do not characterise full trait
    semantics here — only the two operations the trait exposes, modelled as
    abstract opaque functions over an abstract `Transport` carrier type, per
    the task's calling convention for trait-generic parameters. -/
opaque Transport : Type

/-- Rust: `trait RaftTransport { fn send(&mut self, peer: NodeId, msg: RaftMessage); }`
    (`src/consensus/raft.rs:36`).  Implementations are responsible for
    serialisation, addressing, and delivery; send failures must be silently
    absorbed (per the trait's doc comment) — this is a transport-implementation
    obligation, not something `send`'s own contract can express, so `_post`
    here is intentionally weak (the only externally observable fact is that
    the message and recipient are recorded as "in flight"). -/
opaque send (t : Transport) (peer : NodeId) (msg : RaftMessage) : Transport × Unit

def send_pre (_t : Transport) (_peer : NodeId) (_msg : RaftMessage) : Prop := True

def send_post (_t : Transport) (_peer : NodeId) (_msg : RaftMessage) (_r : Transport × Unit) :
    Prop := True

-- REFINEMENT_GAP: src/consensus/raft.rs:42 — `recv` models nondeterministic,
-- possibly-exhausted message delivery; there is no useful closed-form
-- postcondition beyond "if it returns `some`, the sender/message came from
-- the transport's buffered set," which is unobservable from this opaque
-- carrier type alone.
/-- Rust: `trait RaftTransport { fn recv(&mut self) -> Option<(NodeId, RaftMessage)>; }`
    (`src/consensus/raft.rs:42`).  Returns `Some((from, msg))` while messages
    are available, `None` when the receive window is exhausted. -/
opaque recv (t : Transport) : Transport × Option (NodeId × RaftMessage)

def recv_pre (_t : Transport) : Prop := True

def recv_post (_t : Transport) (_r : Transport × Option (NodeId × RaftMessage)) : Prop := True

/-- Mirrors `src/consensus/raft.rs::RaftNode`.  `next_index`/`match_index`
    are modelled as `List Nat` indexed in parallel with `peers` (the Rust
    source uses fixed `[u64; MAX_PEERS]` arrays sized by `MAX_PEERS`, but only
    the first `peers.length` slots are ever meaningfully read). -/
structure RaftNode where
  id : NodeId
  role : RaftRole
  currentTerm : Nat
  votedFor : Option NodeId
  log : RaftLog
  commitIndex : Nat
  votesGranted : Nat
  peers : List NodeId
  nextIndex : List Nat
  matchIndex : List Nat
  deriving DecidableEq, Repr

-- ── `src/consensus/log.rs::RaftLog` impl block ────────────────────────────────

/-- Rust: `impl<const N: usize> RaftLog<N> { pub const fn new() -> Self }`
    (`src/consensus/log.rs:31`).  Trivial pure constructor. -/
def logNew (capacity : Nat) : RaftLog := { entries := [], capacity := capacity }

def logNew_pre (_capacity : Nat) : Prop := True

def logNew_post (capacity : Nat) (l : RaftLog) : Prop :=
  l.entries = [] ∧ l.capacity = capacity

/-- Rust: `impl<const N: usize> RaftLog<N> { pub fn append(&mut self, entry: LogEntry) -> bool }`
    (`src/consensus/log.rs:38`).  Returns `false` (and leaves the log
    unchanged) if the log is at capacity. -/
opaque logAppend (l : RaftLog) (entry : LogEntry) : RaftLog × Bool

def logAppend_pre (_l : RaftLog) (_entry : LogEntry) : Prop := True

def logAppend_post (l : RaftLog) (entry : LogEntry) (r : RaftLog × Bool) : Prop :=
  (l.entries.length < l.capacity →
    r.2 = true ∧ r.1.entries = l.entries ++ [entry] ∧ r.1.capacity = l.capacity) ∧
  (l.entries.length ≥ l.capacity → r.2 = false ∧ r.1 = l)

/-- Rust: `impl<const N: usize> RaftLog<N> { pub fn get(&self, index: u64) -> Option<&LogEntry> }`
    (`src/consensus/log.rs:44`).  1-based; index 0 always yields `None`. -/
def logGet (l : RaftLog) (index : Nat) : Option LogEntry :=
  if index = 0 then none else l.entries[index - 1]?

def logGet_pre (_l : RaftLog) (_index : Nat) : Prop := True

def logGet_post (l : RaftLog) (index : Nat) (r : Option LogEntry) : Prop :=
  (index = 0 → r = none) ∧
  (index ≠ 0 → r = l.entries[index - 1]?)

/-- Rust: `impl<const N: usize> RaftLog<N> { pub fn len(&self) -> u64 }`
    (`src/consensus/log.rs:54`).  Trivial pure accessor. -/
def logLen (l : RaftLog) : Nat := l.entries.length

def logLen_pre (_l : RaftLog) : Prop := True

def logLen_post (l : RaftLog) (r : Nat) : Prop := r = l.entries.length

/-- Rust: `impl<const N: usize> RaftLog<N> { pub fn is_empty(&self) -> bool }`
    (`src/consensus/log.rs:60`).  Trivial pure accessor. -/
def logIsEmpty (l : RaftLog) : Bool := l.entries.isEmpty

def logIsEmpty_pre (_l : RaftLog) : Prop := True

def logIsEmpty_post (l : RaftLog) (r : Bool) : Prop := r = l.entries.isEmpty

/-- Rust: `impl<const N: usize> RaftLog<N> { pub fn last_term(&self) -> u64 }`
    (`src/consensus/log.rs:66`).  `0` if the log is empty. -/
def logLastTerm (l : RaftLog) : Nat := l.entries.getLast?.map (·.term) |>.getD 0

def logLastTerm_pre (_l : RaftLog) : Prop := True

def logLastTerm_post (l : RaftLog) (r : Nat) : Prop :=
  (l.entries = [] → r = 0) ∧
  (∀ e, l.entries.getLast? = some e → r = e.term)

/-- Rust: `impl<const N: usize> RaftLog<N> { pub fn last_index(&self) -> u64 }`
    (`src/consensus/log.rs:72`).  1-based index of the last entry, `0` if empty. -/
def logLastIndex (l : RaftLog) : Nat := l.entries.length

def logLastIndex_pre (_l : RaftLog) : Prop := True

def logLastIndex_post (l : RaftLog) (r : Nat) : Prop := r = l.entries.length

/-- Rust: `impl<const N: usize> RaftLog<N> { pub fn term_at(&self, index: u64) -> Option<u64> }`
    (`src/consensus/log.rs:78`). -/
def logTermAt (l : RaftLog) (index : Nat) : Option Nat :=
  (logGet l index).map (·.term)

def logTermAt_pre (_l : RaftLog) (_index : Nat) : Prop := True

def logTermAt_post (l : RaftLog) (index : Nat) (r : Option Nat) : Prop :=
  r = (logGet l index).map (·.term)

/-- Rust: `impl<const N: usize> RaftLog<N> { pub fn truncate_from(&mut self, from_index: u64) }`
    (`src/consensus/log.rs:85`).  No effect when `from_index` is 0 or exceeds
    `last_index()`. -/
opaque logTruncateFrom (l : RaftLog) (fromIndex : Nat) : RaftLog × Unit

def logTruncateFrom_pre (_l : RaftLog) (_fromIndex : Nat) : Prop := True

def logTruncateFrom_post (l : RaftLog) (fromIndex : Nat) (r : RaftLog × Unit) : Prop :=
  ((fromIndex = 0 ∨ fromIndex > l.entries.length) → r.1 = l) ∧
  (fromIndex ≠ 0 ∧ fromIndex ≤ l.entries.length →
    r.1.entries = l.entries.take (fromIndex - 1) ∧ r.1.capacity = l.capacity)

/-- Rust: `impl<const N: usize> Default for RaftLog<N> { fn default() -> Self }`
    (`src/consensus/log.rs:96`).  Delegates to `new`; trivial pure constructor. -/
def logDefault (capacity : Nat) : RaftLog := logNew capacity

def logDefault_pre (_capacity : Nat) : Prop := True

def logDefault_post (capacity : Nat) (l : RaftLog) : Prop := logNew_post capacity l

-- ── `src/consensus/peer.rs::PeerSet` impl block ───────────────────────────────

/-- Rust: `impl PeerSet { pub const fn new() -> Self }`
    (`src/consensus/peer.rs:27`).  Trivial pure constructor — empty set
    (single-node deployment). -/
def peerSetNew : PeerSet := { peers := [] }

def peerSetNew_pre : Prop := True

def peerSetNew_post (p : PeerSet) : Prop := p.peers = []

/-- Rust: `impl PeerSet { pub fn add(&mut self, peer: NodeId) -> Result<()> }`
    (`src/consensus/peer.rs:40`).  Returns `Err(ManifestInvalid)` if the set
    is already at capacity (`MAX_PEERS` = 16). -/
opaque peerSetAdd (p : PeerSet) (peer : NodeId) : PeerSet × LuxResult Unit

def peerSetAdd_pre (_p : PeerSet) (_peer : NodeId) : Prop := True

def peerSetAdd_post (p : PeerSet) (peer : NodeId) (r : PeerSet × LuxResult Unit) : Prop :=
  (p.peers.length < MAX_PEERS →
    r.1.peers = p.peers ++ [peer] ∧ r.2 = .ok ()) ∧
  (p.peers.length ≥ MAX_PEERS →
    r.1 = p ∧ ∃ detail, r.2 = .error (.ManifestInvalid detail))

/-- Rust: `impl PeerSet { pub fn peers(&self) -> &[NodeId] }`
    (`src/consensus/peer.rs:48`).  Trivial pure accessor. -/
def peerSetPeers (p : PeerSet) : List NodeId := p.peers

def peerSetPeers_pre (_p : PeerSet) : Prop := True

def peerSetPeers_post (p : PeerSet) (r : List NodeId) : Prop := r = p.peers

/-- Rust: `impl PeerSet { pub fn len(&self) -> usize }`
    (`src/consensus/peer.rs:54`).  Trivial pure accessor — does not count
    the local node. -/
def peerSetLen (p : PeerSet) : Nat := p.peers.length

def peerSetLen_pre (_p : PeerSet) : Prop := True

def peerSetLen_post (p : PeerSet) (r : Nat) : Prop := r = p.peers.length

/-- Rust: `impl PeerSet { pub fn is_empty(&self) -> bool }`
    (`src/consensus/peer.rs:60`).  Trivial pure accessor. -/
def peerSetIsEmpty (p : PeerSet) : Bool := p.peers.isEmpty

def peerSetIsEmpty_pre (_p : PeerSet) : Prop := True

def peerSetIsEmpty_post (p : PeerSet) (r : Bool) : Prop := r = p.peers.isEmpty

/-- Rust: `impl PeerSet { pub fn quorum_threshold(&self) -> usize }`
    (`src/consensus/peer.rs:70`).  Formula `⌊N/2⌋ + 1` where `N` is the
    number of other peers; `0` for an empty peer set. -/
def peerSetQuorumThreshold (p : PeerSet) : Nat :=
  if p.peers.isEmpty then 0 else p.peers.length / 2 + 1

def peerSetQuorumThreshold_pre (_p : PeerSet) : Prop := True

def peerSetQuorumThreshold_post (p : PeerSet) (r : Nat) : Prop :=
  (p.peers = [] → r = 0) ∧
  (p.peers ≠ [] → r = p.peers.length / 2 + 1)

/-- Rust: `impl Default for PeerSet { fn default() -> Self }`
    (`src/consensus/peer.rs:80`).  Delegates to `new`; trivial pure
    constructor. -/
def peerSetDefault : PeerSet := peerSetNew

def peerSetDefault_pre : Prop := True

def peerSetDefault_post (p : PeerSet) : Prop := peerSetNew_post p

-- ── `src/consensus/raft.rs::RaftNode` impl block ──────────────────────────────

/-- Rust: `impl RaftNode { pub fn new(id: NodeId, peer_set: &PeerSet) -> Self }`
    (`src/consensus/raft.rs:99`).  Constructs a Follower in term 0 with an
    empty log, no vote cast, and per-peer indices initialised to
    `next_index = 1`, `match_index = 0` for every declared peer. -/
opaque raftNew (id : NodeId) (peerSet : PeerSet) : RaftNode

def raftNew_pre (_id : NodeId) (_peerSet : PeerSet) : Prop := True

def raftNew_post (id : NodeId) (peerSet : PeerSet) (n : RaftNode) : Prop :=
  n.id = id ∧
  n.role = .Follower ∧
  n.currentTerm = 0 ∧
  n.votedFor = none ∧
  n.log.entries = [] ∧
  n.commitIndex = 0 ∧
  n.votesGranted = 0 ∧
  n.peers = peerSet.peers ∧
  n.nextIndex.length = n.peers.length ∧ (∀ x ∈ n.nextIndex, x = 1) ∧
  n.matchIndex.length = n.peers.length ∧ (∀ x ∈ n.matchIndex, x = 0)

/-- Rust: `impl RaftNode { pub const fn role(&self) -> RaftRole }`
    (`src/consensus/raft.rs:120`).  Trivial pure accessor. -/
def raftRole (n : RaftNode) : RaftRole := n.role

def raftRole_pre (_n : RaftNode) : Prop := True

def raftRole_post (n : RaftNode) (r : RaftRole) : Prop := r = n.role

/-- Rust: `impl RaftNode { pub fn is_leader(&self) -> bool }`
    (`src/consensus/raft.rs:126`).  Trivial pure accessor. -/
def raftIsLeader (n : RaftNode) : Bool := n.role = .Leader

def raftIsLeader_pre (_n : RaftNode) : Prop := True

def raftIsLeader_post (n : RaftNode) (r : Bool) : Prop := r = decide (n.role = .Leader)

/-- Rust: `impl RaftNode { pub const fn commit_index(&self) -> u64 }`
    (`src/consensus/raft.rs:132`).  Trivial pure accessor. -/
def raftCommitIndex (n : RaftNode) : Nat := n.commitIndex

def raftCommitIndex_pre (_n : RaftNode) : Prop := True

def raftCommitIndex_post (n : RaftNode) (r : Nat) : Prop := r = n.commitIndex

/-- Rust: `impl RaftNode { pub fn log_len(&self) -> u64 }`
    (`src/consensus/raft.rs:138`).  Trivial pure accessor delegating to
    `RaftLog::len`. -/
def raftLogLen (n : RaftNode) : Nat := n.log.entries.length

def raftLogLen_pre (_n : RaftNode) : Prop := True

def raftLogLen_post (n : RaftNode) (r : Nat) : Prop := r = n.log.entries.length

-- REFINEMENT_GAP: src/consensus/raft.rs:146 — bifurcates on cluster size
-- (single-node auto-becomes-leader vs. multi-node broadcast) and has an
-- observable transport side-effect (one `RequestVote` send per peer) that a
-- single state-transition predicate over `(RaftNode × Transport)` can only
-- approximate.
/-- Rust: `impl RaftNode { pub fn start_election(&mut self, transport: &mut impl RaftTransport) }`
    (`src/consensus/raft.rs:146`).  Increments the term, becomes Candidate,
    votes for self.  For a single-node cluster (`peers` empty) becomes leader
    immediately with no transport interaction; otherwise broadcasts
    `RequestVote` to every peer. -/
opaque startElection (n : RaftNode) (t : Transport) : RaftNode × Transport × Unit

def startElection_pre (_n : RaftNode) (_t : Transport) : Prop := True

def startElection_post (n : RaftNode) (_t : Transport) (r : RaftNode × Transport × Unit) : Prop :=
  r.1.currentTerm = n.currentTerm + 1 ∧
  r.1.votedFor = some n.id ∧
  r.1.peers = n.peers ∧
  (n.peers = [] → r.1.role = .Leader ∧ r.1.votesGranted = 1) ∧
  (n.peers ≠ [] → r.1.role = .Candidate ∧ r.1.votesGranted = 1)

/-- Rust:
    ```
    impl RaftNode {
        pub fn propose(&mut self, src: NodeId, dst: NodeId,
            transport: &mut impl RaftTransport) -> Result<()>
    }
    ```
    (`src/consensus/raft.rs:177`).  Leader-only: appends
    `LogEntry { term: current_term, src, dst }` and replicates to all peers.
    For a single-node cluster the entry commits immediately. Errors:
    `UndefinedState` if not leader; `QuotaExceeded` if the log is full. -/
opaque propose (n : RaftNode) (src dst : NodeId) (t : Transport) :
    RaftNode × Transport × LuxResult Unit

def propose_pre (_n : RaftNode) (_src _dst : NodeId) (_t : Transport) : Prop := True

def propose_post (n : RaftNode) (src dst : NodeId) (_t : Transport)
    (r : RaftNode × Transport × LuxResult Unit) : Prop :=
  (n.role ≠ .Leader →
    r.1 = n ∧ ∃ ctx, r.2.2 = .error (.UndefinedState ctx)) ∧
  (n.role = .Leader ∧ n.log.entries.length ≥ n.log.capacity →
    r.1 = n ∧ ∃ res, r.2.2 = .error (.QuotaExceeded res)) ∧
  (n.role = .Leader ∧ n.log.entries.length < n.log.capacity →
    r.1.log.entries = n.log.entries ++ [{ term := n.currentTerm, src := src, dst := dst }] ∧
    r.2.2 = .ok () ∧
    (n.peers = [] → r.1.commitIndex = r.1.log.entries.length) ∧
    (n.peers ≠ [] → r.1.commitIndex = n.commitIndex))

-- REFINEMENT_GAP: src/consensus/raft.rs:214 — pure dispatcher over four
-- message variants, each handled by a distinct sub-protocol function below;
-- restating all four handlers' postconditions here would make this spec
-- redundant rather than informative, so only the dispatch shape is captured.
/-- Rust:
    ```
    impl RaftNode {
        pub fn step(&mut self, from: NodeId, msg: RaftMessage,
            transport: &mut impl RaftTransport) -> Option<LogEntry>
    }
    ```
    (`src/consensus/raft.rs:214`).  Dispatches `msg` to the matching
    sub-protocol handler (`on_request_vote`, `on_vote_reply`,
    `on_append_entries`, `on_ae_reply`).  Returns `Some(entry)` only when a
    new log entry is committed as a direct result of processing `msg`
    (only possible via the `AppendEntriesReply` branch); every other branch
    returns `None`. -/
opaque step (n : RaftNode) (from : NodeId) (msg : RaftMessage) (t : Transport) :
    RaftNode × Transport × Option LogEntry

def step_pre (_n : RaftNode) (_from : NodeId) (_msg : RaftMessage) (_t : Transport) : Prop := True

def step_post (_n : RaftNode) (_from : NodeId) (msg : RaftMessage) (_t : Transport)
    (r : RaftNode × Transport × Option LogEntry) : Prop :=
  (match msg with
    | .RequestVote .. | .RequestVoteReply .. | .AppendEntries .. => r.2.2 = none
    | .AppendEntriesReply .. => True)

-- ── Private helpers (`src/consensus/raft.rs`, not `pub`, still production
--    code reachable from the `pub` API above — specified for completeness) ──

-- REFINEMENT_GAP: src/consensus/raft.rs:273 — mutates `next_index`/
-- `match_index` over all peer slots in a loop; the transport parameter is
-- accepted but unused (`_transport`), which is easy to mis-specify as
-- having an effect when it provably has none.
/-- Rust: `fn become_leader(&mut self, _transport: &mut impl RaftTransport)`
    (`src/consensus/raft.rs:273`).  Sets role to Leader and resets every
    peer's `next_index` to `log.last_index() + 1` and `match_index` to `0`.
    The transport parameter is accepted but unused. -/
opaque becomeLeader (n : RaftNode) (t : Transport) : RaftNode × Transport × Unit

def becomeLeader_pre (_n : RaftNode) (_t : Transport) : Prop := True

def becomeLeader_post (n : RaftNode) (t : Transport) (r : RaftNode × Transport × Unit) : Prop :=
  r.1.role = .Leader ∧
  r.2.1 = t ∧
  r.1.nextIndex.length = n.peers.length ∧ (∀ x ∈ r.1.nextIndex, x = n.log.entries.length + 1) ∧
  r.1.matchIndex.length = n.peers.length ∧ (∀ x ∈ r.1.matchIndex, x = 0)

/-- Rust: `fn quorum(&self) -> usize` (`src/consensus/raft.rs:282`).
    Trivial pure accessor: `⌈peers.len() / 2⌉ + 1` (note: distinct from
    `PeerSet::quorum_threshold`, which floors and special-cases the empty
    set; here a 0-peer cluster still yields `quorum = 1`, satisfied by the
    leader's own vote/ack). -/
def quorum (n : RaftNode) : Nat := (n.peers.length + 1) / 2 + 1

def quorum_pre (_n : RaftNode) : Prop := True

def quorum_post (n : RaftNode) (r : Nat) : Prop := r = (n.peers.length + 1) / 2 + 1

/-- Rust: `fn peer_index(&self, peer: NodeId) -> Option<usize>`
    (`src/consensus/raft.rs:286`).  Trivial pure accessor: position of
    `peer` in the `peers` list, if present. -/
def peerIndex (n : RaftNode) (peer : NodeId) : Option Nat :=
  n.peers.indexOf? peer

def peerIndex_pre (_n : RaftNode) (_peer : NodeId) : Prop := True

def peerIndex_post (n : RaftNode) (peer : NodeId) (r : Option Nat) : Prop :=
  (peer ∈ n.peers → ∃ i, r = some i ∧ n.peers[i]? = some peer) ∧
  (peer ∉ n.peers → r = none)

/-- Rust: `fn step_down(&mut self, term: u64)` (`src/consensus/raft.rs:290`).
    Adopts `term`, reverts to Follower, and clears any recorded vote. -/
opaque stepDown (n : RaftNode) (term : Nat) : RaftNode × Unit

def stepDown_pre (_n : RaftNode) (_term : Nat) : Prop := True

def stepDown_post (n : RaftNode) (term : Nat) (r : RaftNode × Unit) : Prop :=
  r.1.currentTerm = term ∧ r.1.role = .Follower ∧ r.1.votedFor = none ∧
  r.1.peers = n.peers ∧ r.1.log = n.log ∧ r.1.commitIndex = n.commitIndex

/-- Rust: `fn log_up_to_date_for(&self, last_log_index: u64, last_log_term: u64) -> bool`
    (`src/consensus/raft.rs:296`).  Trivial pure predicate over the local log's
    last term/index, used by the Raft "is the candidate's log at least as
    up-to-date as mine" voting rule. -/
def logUpToDateFor (n : RaftNode) (lastLogIndex lastLogTerm : Nat) : Bool :=
  decide (lastLogTerm > logLastTerm n.log) ||
    decide (lastLogTerm = logLastTerm n.log ∧ lastLogIndex ≥ logLastIndex n.log)

def logUpToDateFor_pre (_n : RaftNode) (_lastLogIndex _lastLogTerm : Nat) : Prop := True

def logUpToDateFor_post (n : RaftNode) (lastLogIndex lastLogTerm : Nat) (r : Bool) : Prop :=
  r = (decide (lastLogTerm > logLastTerm n.log) ||
    decide (lastLogTerm = logLastTerm n.log ∧ lastLogIndex ≥ logLastIndex n.log))

-- REFINEMENT_GAP: src/consensus/raft.rs:301 — builds a bounded (≤16) entry
-- batch by walking the log from `next_index[peer_idx]` until either the log
-- or the 16-slot RPC capacity is exhausted; the loop bound is data-dependent
-- (how many further entries the log holds), resisting a tight closed-form
-- postcondition on the sent message's `entries` field.
/-- Rust: `fn send_ae_to(&self, peer_idx: usize, transport: &mut impl RaftTransport)`
    (`src/consensus/raft.rs:301`).  No-op if `peer_idx` is out of range.
    Otherwise sends an `AppendEntries` to the peer at `peer_idx` carrying up
    to 16 log entries starting at that peer's `next_index`. -/
opaque sendAeTo (n : RaftNode) (peerIdx : Nat) (t : Transport) : Transport × Unit

def sendAeTo_pre (_n : RaftNode) (_peerIdx : Nat) (_t : Transport) : Prop := True

def sendAeTo_post (n : RaftNode) (peerIdx : Nat) (t : Transport) (r : Transport × Unit) : Prop :=
  peerIdx ≥ n.peers.length → r.1 = t

-- REFINEMENT_GAP: src/consensus/raft.rs:336 — combines a term-driven
-- step-down, the up-to-date-log check, and the vote-granting decision in one
-- function with a transport side-effect (always replies); the interaction
-- of all three conditions with the *prior* `voted_for` state is multi-branch
-- and easy to misstate exhaustively in a single postcondition.
/-- Rust:
    ```
    fn on_request_vote(&mut self, from: NodeId, rv: RvParams,
        transport: &mut impl RaftTransport)
    ```
    (`src/consensus/raft.rs:336`).  Steps down if `rv.term` is newer.  Grants
    the vote iff `rv.term >= current_term`, the candidate's log is at least
    as up-to-date as the local log, and no other candidate has already been
    voted for this term.  Always replies with `RequestVoteReply`. -/
opaque onRequestVote (n : RaftNode) (from : NodeId) (term candidateId lastLogIndex lastLogTerm : Nat)
    (t : Transport) : RaftNode × Transport × Unit

def onRequestVote_pre (_n : RaftNode) (_from : NodeId)
    (_term _candidateId _lastLogIndex _lastLogTerm : Nat) (_t : Transport) : Prop := True

def onRequestVote_post (n : RaftNode) (_from : NodeId)
    (term candidateId lastLogIndex lastLogTerm : Nat) (_t : Transport)
    (r : RaftNode × Transport × Unit) : Prop :=
  let stepped := term > n.currentTerm
  let baseTerm := if stepped then term else n.currentTerm
  let logOk := logUpToDateFor n lastLogIndex lastLogTerm
  let canVote := match (if stepped then none else n.votedFor) with
    | none => true
    | some v => v = candidateId
  let granted := decide (term ≥ baseTerm) && logOk && canVote
  r.1.currentTerm = baseTerm ∧
  (granted = true → r.1.votedFor = some candidateId) ∧
  (granted = false ∧ ¬stepped → r.1.votedFor = n.votedFor) ∧
  (stepped → r.1.role = .Follower)

/-- Rust:
    ```
    fn on_vote_reply(&mut self, term: u64, vote_granted: bool,
        transport: &mut impl RaftTransport) -> Option<LogEntry>
    ```
    (`src/consensus/raft.rs:355`).  Steps down on a newer term.  Ignores
    stale replies (wrong role or stale term).  Otherwise tallies the vote and
    transitions to Leader once a quorum is reached.  Always returns `None`
    (vote replies never directly commit an entry). -/
opaque onVoteReply (n : RaftNode) (term : Nat) (voteGranted : Bool) (t : Transport) :
    RaftNode × Transport × Option LogEntry

def onVoteReply_pre (_n : RaftNode) (_term : Nat) (_voteGranted : Bool) (_t : Transport) : Prop :=
  True

def onVoteReply_post (n : RaftNode) (term : Nat) (voteGranted : Bool) (_t : Transport)
    (r : RaftNode × Transport × Option LogEntry) : Prop :=
  r.2.2 = none ∧
  (term > n.currentTerm → r.1.currentTerm = term ∧ r.1.role = .Follower ∧ r.1.votedFor = none) ∧
  (term ≤ n.currentTerm ∧ (n.role ≠ .Candidate ∨ term ≠ n.currentTerm) → r.1 = n) ∧
  (term ≤ n.currentTerm ∧ n.role = .Candidate ∧ term = n.currentTerm ∧ voteGranted = false →
    r.1.votesGranted = n.votesGranted) ∧
  (term ≤ n.currentTerm ∧ n.role = .Candidate ∧ term = n.currentTerm ∧ voteGranted = true →
    r.1.votesGranted = n.votesGranted + 1) ∧
  (term ≤ n.currentTerm ∧ n.role = .Candidate ∧ term = n.currentTerm ∧
    r.1.votesGranted ≥ quorum n → r.1.role = .Leader)

-- REFINEMENT_GAP: src/consensus/raft.rs:377 — classic Raft `AppendEntries`
-- handler with three early-return branches (stale term, log mismatch) plus
-- a success path that mutates the log and commit index; the full case
-- analysis is large and timing/ordering-sensitive, so the postcondition
-- below is a best-effort summary rather than an exhaustive case split.
/-- Rust:
    ```
    fn on_append_entries(&mut self, from: NodeId, ae: &AeParams,
        transport: &mut impl RaftTransport)
    ```
    (`src/consensus/raft.rs:377`).  Rejects (replies `success: false`) if
    `ae.term` is stale, or if the log doesn't match at `prev_log_index`.
    Otherwise steps down/refreshes Follower role, appends `ae.entries`,
    advances `commit_index` toward `leader_commit` (bounded by the new log
    length), and replies `success: true` with the resulting match index. -/
opaque onAppendEntries (n : RaftNode) (from : NodeId)
    (term prevLogIndex prevLogTerm : Nat) (entries : List LogEntry) (leaderCommit : Nat)
    (t : Transport) : RaftNode × Transport × Unit

def onAppendEntries_pre (_n : RaftNode) (_from : NodeId)
    (_term _prevLogIndex _prevLogTerm : Nat) (entries : List LogEntry) (_leaderCommit : Nat)
    (_t : Transport) : Prop :=
  entries.length ≤ 16

def onAppendEntries_post (n : RaftNode) (_from : NodeId)
    (term prevLogIndex _prevLogTerm : Nat) (_entries : List LogEntry) (_leaderCommit : Nat)
    (_t : Transport) (r : RaftNode × Transport × Unit) : Prop :=
  (term < n.currentTerm → r.1 = n) ∧
  (term ≥ n.currentTerm ∧ prevLogIndex ≠ 0 ∧
      logTermAt n.log prevLogIndex ≠ some prevLogIndex →
    r.1.log = n.log ∧ r.1.commitIndex = n.commitIndex) ∧
  (term > n.currentTerm → r.1.currentTerm = term ∧ r.1.role = .Follower) ∧
  (term = n.currentTerm → r.1.role = .Follower)

/-- Rust: `fn append_log_entries(&mut self, prev_log_index: u64, entries: &[LogEntry]) -> u64`
    (`src/consensus/raft.rs:426`).  For each entry past `prev_log_index`,
    truncates a conflicting suffix (mismatched term at that index) and
    appends if the slot is empty; idempotent on entries already matching.
    Returns the resulting match index, `prev_log_index + entries.length`. -/
opaque appendLogEntries (n : RaftNode) (prevLogIndex : Nat) (entries : List LogEntry) :
    RaftNode × Nat

def appendLogEntries_pre (_n : RaftNode) (_prevLogIndex : Nat) (entries : List LogEntry) : Prop :=
  entries.length ≤ 16

def appendLogEntries_post (n : RaftNode) (prevLogIndex : Nat) (entries : List LogEntry)
    (r : RaftNode × Nat) : Prop :=
  r.2 = prevLogIndex + entries.length ∧
  r.1.id = n.id ∧ r.1.role = n.role ∧ r.1.currentTerm = n.currentTerm ∧
  r.1.peers = n.peers

/-- Rust:
    ```
    fn on_ae_reply(&mut self, from: NodeId, term: u64, success: bool,
        match_index: u64) -> Option<LogEntry>
    ```
    (`src/consensus/raft.rs:442`).  Steps down on a newer term.  Ignores the
    reply if stale (not leader, or term mismatch) or from an unknown peer.
    On success, advances that peer's `next_index`/`match_index`; on failure,
    decrements `next_index` (floor of 1).  If the reply was a success and
    advancing the commit index moved it forward, returns the newly committed
    entry; otherwise `None`. -/
opaque onAeReply (n : RaftNode) (from : NodeId) (term : Nat) (success : Bool) (matchIndex : Nat) :
    RaftNode × Option LogEntry

def onAeReply_pre (_n : RaftNode) (_from : NodeId) (_term : Nat) (_success : Bool)
    (_matchIndex : Nat) : Prop := True

def onAeReply_post (n : RaftNode) (from : NodeId) (term : Nat) (success : Bool) (matchIndex : Nat)
    (r : RaftNode × Option LogEntry) : Prop :=
  (term > n.currentTerm →
    r.1.currentTerm = term ∧ r.1.role = .Follower ∧ r.1.votedFor = none ∧ r.2 = none) ∧
  (term ≤ n.currentTerm ∧ (n.role ≠ .Leader ∨ term ≠ n.currentTerm) → r.1 = n ∧ r.2 = none) ∧
  (term ≤ n.currentTerm ∧ n.role = .Leader ∧ term = n.currentTerm ∧ from ∉ n.peers →
    r.1 = n ∧ r.2 = none) ∧
  (success = false → r.2 = none) ∧
  (success = true ∧ r.1.commitIndex = n.commitIndex → r.2 = none) ∧
  (success = true ∧ r.1.commitIndex ≠ n.commitIndex →
    r.2 = logGet r.1.log r.1.commitIndex)

-- REFINEMENT_GAP: src/consensus/raft.rs:469 — searches log indices in
-- descending order for the highest index satisfying the Raft commit rule
-- (current-term entry acked by a quorum of `match_index` values); the
-- search-and-stop-at-first-match control flow over an arbitrary log length
-- resists a tight closed-form postcondition without re-deriving the search
-- itself, so the postcondition only states the monotonicity guarantee and
-- the defining property of the chosen index (when it changes).
/-- Rust: `fn advance_commit_index(&mut self) -> bool`
    (`src/consensus/raft.rs:469`).  Scans candidate indices from
    `log.last_index()` down to `commit_index + 1`; the first index `n` whose
    entry's term equals `current_term` and that is acknowledged
    (`match_index >= n`, plus the leader's own implicit ack) by a quorum
    becomes the new `commit_index`.  Returns `true` iff `commit_index`
    advanced. -/
opaque advanceCommitIndex (n : RaftNode) : RaftNode × Bool

def advanceCommitIndex_pre (_n : RaftNode) : Prop := True

def advanceCommitIndex_post (n : RaftNode) (r : RaftNode × Bool) : Prop :=
  r.2 = decide (r.1.commitIndex > n.commitIndex) ∧
  r.1.commitIndex ≥ n.commitIndex ∧
  r.1.commitIndex ≤ logLastIndex n.log ∧
  (r.1.commitIndex > n.commitIndex →
    logTermAt n.log r.1.commitIndex = some n.currentTerm ∧
    1 + (n.matchIndex.filter (· ≥ r.1.commitIndex)).length ≥ quorum n)

end FunctionSpecs.Consensus
