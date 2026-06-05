# ADR 0004 — Distributed Topology Consensus Protocol

**Status:** Accepted  
**Date:** 2026-Q2

## Context

The single-node Lux kernel enforces topology via a sealed `OperationalGraph`
that is set at boot time and immutable thereafter.  When multiple kernel
instances govern a distributed system, they must agree on topology changes
before any instance applies them — a split-brain scenario where two instances
have different edge sets breaks the Topology-Bounded invariant (I4) at the
system level even if each individual node upholds it locally.

Three failure modes are in scope:

1. **Crash-stop failures** — a peer halts and stops responding.
2. **Network partitions** — a subset of peers become temporarily unreachable.
3. **Stale attestations** — a peer that rebooted from an unattested image tries
   to re-join.

Byzantine (actively malicious) peers are out of scope for this iteration.
The threat model is governed administrators and infrastructure faults, not
adversarial insider nodes.  Byzantine-tolerant consensus (PBFT, HotStuff) is
deferred to a future ADR.

## Decision

### Consensus model: single-round quorum vote

Each topology change is proposed by exactly one peer (the **proposer**) and
broadcast to all known peers in a `Propose` message.  Each peer validates the
proposal against its own boot state and returns `Vote { accept: bool }`.  The
proposer collects votes and commits when it holds a strict quorum of `accept`
votes; otherwise it aborts.

This is a crash-stop protocol — no leader election, no log replication, no
view changes.  It is sufficient for the low-frequency, high-stakes topology
mutations that Lux governs (edge additions happen at provisioning time, not
at runtime hot-path).

### Quorum threshold: ⌊N/2⌋ + 1

The quorum is a strict majority of the **declared** peer set (from the boot
manifest), not the currently reachable peers.  This prevents a partitioned
minority from committing topology changes unilaterally.

If fewer than ⌊N/2⌋ + 1 peers are reachable the proposer **must** abort and
return `TopologyViolation` to the caller.  This is the fail-closed behaviour:
an uncertain partition is treated as a denial, not a grant.

### Failure model: crash-stop

Peers may halt.  They do not lie, forge votes, or send conflicting messages.
A peer that fails mid-round is treated as a non-vote (counts against quorum
but does not produce an `accept`).

### Partition behaviour: fail-closed

A proposer that does not receive a quorum of responses within its timeout
window **rejects** the change and emits a `TopologyViolation` audit event.
No partial or speculative commits are made.  The topology graph is not
modified.

This matches Invariant I1 (Fail-Closed): when the outcome is uncertain, the
kernel denies rather than grants.

### TPM attestation gate

A peer is eligible to vote only if:

1. Its `BootState` carries a non-null `TpmQuote` (i.e. it was initialised with
   a real `TpmProvider`, not `NullTpm`).
2. The quote's PCR 0 value matches the proposer's expected manifest hash.

A peer with a null quote (software-only boot) may observe the protocol but its
vote does not count toward quorum.  This ensures that unattested nodes cannot
unilaterally shift the quorum threshold.

### Message types

```
ConsensusMessage::Propose { round_id: u64, proposed_edge: (NodeId, NodeId) }
ConsensusMessage::Vote    { round_id: u64, accept: bool, attestation: TpmQuote }
ConsensusMessage::Commit  { round_id: u64 }
ConsensusMessage::Abort   { round_id: u64 }
```

All messages are `no_std` compatible (fixed-size, no heap allocation).

### Peer set

The `PeerSet` is declared in the boot manifest and sealed along with the
topology graph.  Peers cannot be added or removed at runtime without a new
boot sequence.  This keeps the quorum denominator stable and auditable.

### Integration point

`BootState` gains a method `run_topology_consensus` that accepts a
`&mut PeerSet`, a proposed edge, and a send/receive function pair, and
returns `Result<()>`.  The caller is responsible for the transport layer
(shared memory, sockets, message queue — out of scope for this ADR).

## Consequences

- Topology changes in a distributed deployment require a round-trip to all
  peers; latency is bounded by the slowest responding quorum member.
- A majority partition that lasts longer than the proposer's timeout blocks
  all topology changes — this is intentional (fail-closed).
- Single-node deployments are unaffected: `PeerSet::single()` declares a
  quorum of 1 and the protocol degenerates to a no-op round.
- Byzantine fault tolerance is explicitly deferred.  If it is needed, this
  ADR should be superseded by one adopting a BFT protocol.
- All consensus events are emitted to the `AuditLog` under
  `EventKind::TopologyChange` so that distributed decisions are fully
  traceable.
