import FunctionSpecs.Core

/-!
# Lux Kernel — Function Spec Layer: Scheduler / WASM / TPM

This file covers every production (non-test, non-kani) function in:

- `src/scheduler/mod.rs`
- `src/scheduler/queue.rs`
- `src/wasm/mod.rs`
- `src/wasm/executor.rs`
- `src/wasm/host.rs`
- `src/tpm/mod.rs`
- `src/tpm/attestation.rs`
- `src/tpm/mock.rs`
- `src/tpm/tss.rs`

Per the project's spec-layer convention (see `FunctionSpecs/Core.lean`), every
function gets exactly three declarations: an `opaque` (or, for genuinely
trivial pure accessors, a direct `def`) signature, a `_pre`, and a `_post`.
**No theorems, no `sorry`, no proof attempt anywhere in this file.**

Total functions specified: **55**.

## REFINEMENT_GAP entries in this file

| Function | file:line | Reason |
|---|---|---|
| `WorkQueue.drainOrdered` | `src/scheduler/queue.rs:96` | Correctness depends on heap pop order being a *stable* total order realized by `heapless::BinaryHeap`; modelled abstractly as "sorted by priority" without pinning tie-break behaviour among equal-priority items. |
| `WasmExecutor.new` | `src/wasm/executor.rs:57` | Constructs a real `wasmtime::Engine`/`Linker`; whether linker registration succeeds is a property of the `wasmtime` crate's internals, not something this spec layer can characterize mathematically. |
| `WasmExecutor.callNullary` | `src/wasm/executor.rs:150` | Compiling, instantiating, and executing arbitrary guest WASM bytecode cannot be characterized without modelling the WASM spec itself; "guest computed the right answer" is out of scope. |
| `SoftwareTpm.extendPcr` | `src/tpm/mock.rs:57` | Relies on SHA-256 as an opaque cryptographic primitive; "correct" PCR extension is defined by bit-for-bit hash output, not a property expressible independent of the hash function. |
| `SoftwareTpm.quote` | `src/tpm/mock.rs:71` | Same SHA-256-as-oracle issue as `extendPcr`; quote bytes are defined by hash output, modelled here only up to "is some deterministic function of PCR state and nonce." |
| `SoftwareTpm.verifyQuote` | `src/tpm/mock.rs:102` | Verification correctness is contingent on SHA-256 collision resistance, an unmodelled cryptographic assumption. |
| `TssTpmProvider.newStub` | `src/tpm/tss.rs:41` | Trivial today (stub), but documented as the seam where real TCTI/hardware connection logic will live; flagged so the gap is visible once hardware integration lands. |
| `TssTpmProvider.extendPcr` | `src/tpm/tss.rs:47` | Real-hardware TPM operation; current stub always errs, but the eventual hardware-backed semantics (irreversible PCR extension via silicon) cannot be specified without modelling the TPM 2.0 spec. |
| `TssTpmProvider.quote` | `src/tpm/tss.rs:53` | Real-hardware TPM operation; eventual quote semantics depend on `TPMS_ATTEST` structure and AK signature, out of scope. |
| `TssTpmProvider.readPcr` | `src/tpm/tss.rs:59` | Real-hardware PCR read; depends on physical TPM state not modelled here. |
| `TssTpmProvider.verifyQuote` | `src/tpm/tss.rs:65` | Real-hardware signature verification against an AK public key; cryptographic verification is out of scope for this spec layer. |
-/

namespace FunctionSpecs

-- ════════════════════════════════════════════════════════════════════════
-- §1  src/scheduler/queue.rs
-- ════════════════════════════════════════════════════════════════════════

/-- Mirrors `src/scheduler/queue.rs::WorkItem`.  `priority : Nat` — lower
    value = higher urgency (Min-heap surfaces smallest first).  `target`
    is a `NodeId`.  `payload` is an opaque caller-defined `u64`. -/
structure WorkItem where
  priority : Nat
  target : NodeId
  payload : Nat
  deriving DecidableEq, Repr

/-- Mirrors `src/scheduler/queue.rs::WorkQueue<const N: usize>` — a bounded
    priority queue with compile-time capacity `N`.  Modelled here as its
    logical contents (a list of `WorkItem`) plus the fixed capacity. -/
structure WorkQueueR where
  items : List WorkItem
  capacity : Nat
  deriving DecidableEq, Repr

/-- Rust: `impl Ord for WorkItem { fn cmp(&self, other: &Self) -> core::cmp::Ordering }`
    (`src/scheduler/queue.rs:34`).  Total order by `priority` field only;
    `target`/`payload` do not participate. -/
opaque workItemCmp (a b : WorkItem) : Ordering

def workItemCmp_pre (_a _b : WorkItem) : Prop := True

def workItemCmp_post (a b : WorkItem) (r : Ordering) : Prop :=
  r = compare a.priority b.priority

/-- Rust: `impl PartialOrd for WorkItem { fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> }`
    (`src/scheduler/queue.rs:28`).  Total order, so always `Some`; delegates
    to `Ord::cmp`. -/
opaque workItemPartialCmp (a b : WorkItem) : Option Ordering

def workItemPartialCmp_pre (_a _b : WorkItem) : Prop := True

def workItemPartialCmp_post (a b : WorkItem) (r : Option Ordering) : Prop :=
  r = some (compare a.priority b.priority)

/-- Rust: `impl<const N: usize> core::fmt::Debug for WorkQueue<N> { fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result }`
    (`src/scheduler/queue.rs:46`).  Debug formatting; prints `len` and
    `capacity` fields.  Modelled as a pure string-producing function with
    no effect on `q`. -/
opaque workQueueFmt (q : WorkQueueR) : String

def workQueueFmt_pre (_q : WorkQueueR) : Prop := True

def workQueueFmt_post (q : WorkQueueR) (r : String) : Prop :=
  r ≠ ""  -- best-effort: non-empty Debug output mentioning len/capacity is
          -- the only structurally-checkable property of a `Formatter` write.

/-- Rust: `impl<const N: usize> WorkQueue<N> { pub const fn new() -> Self }`
    (`src/scheduler/queue.rs:57`). -/
opaque workQueueNew (capacity : Nat) : WorkQueueR

def workQueueNew_pre (_capacity : Nat) : Prop := True

def workQueueNew_post (capacity : Nat) (q : WorkQueueR) : Prop :=
  q.items = [] ∧ q.capacity = capacity

/-- Rust: `impl<const N: usize> WorkQueue<N> { pub fn enqueue(&mut self, item: WorkItem) -> Result<()> }`
    (`src/scheduler/queue.rs:70`).  Inserts `item`; fails closed with
    `SchedulerInvariant` when the queue is at capacity. -/
opaque enqueue (q : WorkQueueR) (item : WorkItem) : WorkQueueR × LuxResult Unit

def enqueue_pre (_q : WorkQueueR) (_item : WorkItem) : Prop := True

def enqueue_post (q : WorkQueueR) (item : WorkItem)
    (result : WorkQueueR × LuxResult Unit) : Prop :=
  let (q', r) := result
  (q.items.length < q.capacity →
    r = Except.ok () ∧ q'.items.length = q.items.length + 1 ∧
    item ∈ q'.items ∧ q'.capacity = q.capacity) ∧
  (q.items.length ≥ q.capacity →
    r = Except.error (.SchedulerInvariant "queue capacity exhausted") ∧ q' = q)

/-- Rust: `impl<const N: usize> WorkQueue<N> { pub fn dequeue(&mut self) -> Option<WorkItem> }`
    (`src/scheduler/queue.rs:79`).  Removes and returns the item with the
    lowest `priority` value (highest urgency), or `None` if empty. -/
opaque dequeue (q : WorkQueueR) : WorkQueueR × Option WorkItem

def dequeue_pre (_q : WorkQueueR) : Prop := True

def dequeue_post (q : WorkQueueR) (result : WorkQueueR × Option WorkItem) : Prop :=
  let (q', r) := result
  (q.items = [] → r = none ∧ q' = q) ∧
  (q.items ≠ [] →
    ∃ item, r = some item ∧
      item ∈ q.items ∧
      (∀ other ∈ q.items, item.priority ≤ other.priority) ∧
      q'.items.length = q.items.length - 1 ∧
      q'.capacity = q.capacity)

/-- Rust: `impl<const N: usize> WorkQueue<N> { pub fn len(&self) -> usize }`
    (`src/scheduler/queue.rs:85`).  Trivial pure accessor. -/
def workQueueLen (q : WorkQueueR) : Nat := q.items.length

def workQueueLen_pre (_q : WorkQueueR) : Prop := True

def workQueueLen_post (q : WorkQueueR) (r : Nat) : Prop := r = q.items.length

/-- Rust: `impl<const N: usize> WorkQueue<N> { pub fn is_empty(&self) -> bool }`
    (`src/scheduler/queue.rs:91`).  Trivial pure accessor. -/
def workQueueIsEmpty (q : WorkQueueR) : Bool := q.items.isEmpty

def workQueueIsEmpty_pre (_q : WorkQueueR) : Prop := True

def workQueueIsEmpty_post (q : WorkQueueR) (r : Bool) : Prop :=
  r = true ↔ q.items = []

-- REFINEMENT_GAP: src/scheduler/queue.rs:96 — correctness depends on the
-- stable pop order realized by `heapless::BinaryHeap` among equal-priority
-- items, which this spec models only up to "sorted by priority", not the
-- exact tie-break order the underlying heap implementation produces.
/-- Rust: `impl<const N: usize> WorkQueue<N> { pub fn drain_ordered(&mut self) -> HVec<WorkItem, N> }`
    (`src/scheduler/queue.rs:96`).  Repeatedly pops until empty, returning
    items highest-urgency (lowest priority) first. -/
opaque drainOrdered (q : WorkQueueR) : WorkQueueR × List WorkItem

def drainOrdered_pre (_q : WorkQueueR) : Prop := True

def drainOrdered_post (q : WorkQueueR) (result : WorkQueueR × List WorkItem) : Prop :=
  let (q', out) := result
  q'.items = [] ∧ q'.capacity = q.capacity ∧
  out.length = q.items.length ∧
  (∀ item, item ∈ out ↔ item ∈ q.items) ∧
  (∀ i j, i < j → j < out.length →
    (out.get! i).priority ≤ (out.get! j).priority)

/-- Rust: `impl<const N: usize> Default for WorkQueue<N> { fn default() -> Self }`
    (`src/scheduler/queue.rs:106`). -/
opaque workQueueDefault (capacity : Nat) : WorkQueueR

def workQueueDefault_pre (_capacity : Nat) : Prop := True

def workQueueDefault_post (capacity : Nat) (q : WorkQueueR) : Prop :=
  q.items = [] ∧ q.capacity = capacity

-- ════════════════════════════════════════════════════════════════════════
-- §2  src/scheduler/mod.rs
-- ════════════════════════════════════════════════════════════════════════

/-- Local minimal mirror of `crate::auth::capability::Capability`
    (`src/auth/capability.rs:37`) — only the fields needed to state specs
    in this file.  See the WASM/host section below for the
    `CapabilitySet` mirror (`SchedCapSet`). -/
structure SchedCapability where
  ok : Bool
  deriving DecidableEq, Repr

/-- Local minimal mirror of `crate::auth::capability::CapabilitySet`
    (`src/auth/capability.rs:11`), a bitflags type. -/
abbrev SchedCapSet := Nat

/-- Local minimal mirror of `crate::auth::policy::Policy`
    (used by `Scheduler::schedule` via `Policy::check`). -/
structure SchedPolicy where
  state : Nat
  deriving DecidableEq, Repr

/-- Local minimal mirror of `crate::audit::AuditLog`. -/
structure SchedAuditLog where
  entries : Nat
  deriving DecidableEq, Repr

/-- Mirrors `src/scheduler/mod.rs::Scheduler<const N: usize>` — a
    capability-gated wrapper around `WorkQueueR`. -/
structure SchedulerR where
  queue : WorkQueueR
  deriving DecidableEq, Repr

/-- Rust: `impl<const N: usize> Scheduler<N> { pub const fn new() -> Self }`
    (`src/scheduler/mod.rs:43`). -/
opaque schedulerNew (capacity : Nat) : SchedulerR

def schedulerNew_pre (_capacity : Nat) : Prop := True

def schedulerNew_post (capacity : Nat) (s : SchedulerR) : Prop :=
  s.queue.items = [] ∧ s.queue.capacity = capacity

/-- Rust: `impl<const N: usize> Scheduler<N> { pub fn schedule(&mut self, item: WorkItem, cap: &Capability, policy: &mut Policy, audit: &mut AuditLog) -> Result<()> }`
    (`src/scheduler/mod.rs:62`).  I2 (Capability-Gated): gated behind
    `Policy::check(cap, CapabilitySet::SCHEDULE, audit)`; on success,
    enqueues into the inner `WorkQueue`.  Fails closed: the queue is
    unmodified unless both the capability check and the enqueue succeed. -/
opaque schedule (s : SchedulerR) (item : WorkItem) (cap : SchedCapability)
    (policy : SchedPolicy) (audit : SchedAuditLog) :
    SchedulerR × SchedPolicy × SchedAuditLog × LuxResult Unit

def schedule_pre (_s : SchedulerR) (_item : WorkItem) (_cap : SchedCapability)
    (_policy : SchedPolicy) (_audit : SchedAuditLog) : Prop := True

/-- I2: a denied capability check leaves the queue untouched and propagates
    `CapabilityDenied`.  Only when the capability check passes does the
    underlying `enqueue` run, with its own fail-closed `SchedulerInvariant`
    response on a full queue. -/
def schedule_post (s : SchedulerR) (item : WorkItem) (cap : SchedCapability)
    (policy : SchedPolicy) (audit : SchedAuditLog)
    (result : SchedulerR × SchedPolicy × SchedAuditLog × LuxResult Unit) : Prop :=
  let (s', _policy', _audit', r) := result
  (cap.ok = false →
    (∃ reason, r = Except.error (.CapabilityDenied reason)) ∧ s' = s) ∧
  (cap.ok = true ∧ s.queue.items.length < s.queue.capacity →
    r = Except.ok () ∧ item ∈ s'.queue.items ∧
    s'.queue.items.length = s.queue.items.length + 1) ∧
  (cap.ok = true ∧ s.queue.items.length ≥ s.queue.capacity →
    r = Except.error (.SchedulerInvariant "queue capacity exhausted") ∧ s' = s)

/-- Rust: `impl<const N: usize> Scheduler<N> { pub fn dequeue(&mut self) -> Option<WorkItem> }`
    (`src/scheduler/mod.rs:74`).  Delegates to the inner `WorkQueue::dequeue`. -/
opaque schedulerDequeue (s : SchedulerR) : SchedulerR × Option WorkItem

def schedulerDequeue_pre (_s : SchedulerR) : Prop := True

def schedulerDequeue_post (s : SchedulerR)
    (result : SchedulerR × Option WorkItem) : Prop :=
  let (s', r) := result
  (s.queue.items = [] → r = none ∧ s' = s) ∧
  (s.queue.items ≠ [] →
    ∃ item, r = some item ∧ item ∈ s.queue.items ∧
      (∀ other ∈ s.queue.items, item.priority ≤ other.priority) ∧
      s'.queue.items.length = s.queue.items.length - 1)

/-- Rust: `impl<const N: usize> Scheduler<N> { pub fn len(&self) -> usize }`
    (`src/scheduler/mod.rs:80`).  Trivial pure accessor. -/
def schedulerLen (s : SchedulerR) : Nat := s.queue.items.length

def schedulerLen_pre (_s : SchedulerR) : Prop := True

def schedulerLen_post (s : SchedulerR) (r : Nat) : Prop := r = s.queue.items.length

/-- Rust: `impl<const N: usize> Scheduler<N> { pub fn is_empty(&self) -> bool }`
    (`src/scheduler/mod.rs:86`).  Trivial pure accessor. -/
def schedulerIsEmpty (s : SchedulerR) : Bool := s.queue.items.isEmpty

def schedulerIsEmpty_pre (_s : SchedulerR) : Prop := True

def schedulerIsEmpty_post (s : SchedulerR) (r : Bool) : Prop :=
  r = true ↔ s.queue.items = []

/-- Rust: `impl<const N: usize> Default for Scheduler<N> { fn default() -> Self }`
    (`src/scheduler/mod.rs:92`). -/
opaque schedulerDefault (capacity : Nat) : SchedulerR

def schedulerDefault_pre (_capacity : Nat) : Prop := True

def schedulerDefault_post (capacity : Nat) (s : SchedulerR) : Prop :=
  s.queue.items = [] ∧ s.queue.capacity = capacity

-- ════════════════════════════════════════════════════════════════════════
-- §3  src/wasm/mod.rs
-- ════════════════════════════════════════════════════════════════════════

/-- Local minimal mirror of `crate::auth::capability::Capability`
    (`src/auth/capability.rs:37`), reused across the WASM section. -/
structure WasmCapability where
  ok : Bool
  deriving DecidableEq, Repr

/-- Local minimal mirror of `crate::auth::capability::CapabilitySet`
    bitflags (`src/auth/capability.rs:11`). -/
abbrev WasmCapSet := Nat

/-- Local minimal mirror of `crate::auth::policy::Policy`. -/
structure WasmPolicy where
  state : Nat
  deriving DecidableEq, Repr

/-- Local minimal mirror of `crate::metabolism::ledger::Ledger`. -/
structure WasmLedger where
  balances : List (NodeId × Balance)
  deriving DecidableEq, Repr

/-- Local minimal mirror of `crate::topology::graph::OperationalGraph`. -/
structure WasmGraph where
  edges : List (NodeId × NodeId)
  deriving DecidableEq, Repr

/-- Local minimal mirror of `crate::audit::AuditLog`. -/
structure WasmAuditLog where
  entries : Nat
  deriving DecidableEq, Repr

/-- Local minimal mirror of `crate::boot::BootState` (sealed boot state),
    only the fields `WasmShim::from_boot_state` consumes
    (`policy`, `ledger`, `graph`). -/
structure WasmBootState where
  policy : WasmPolicy
  ledger : WasmLedger
  graph : WasmGraph
  deriving DecidableEq, Repr

/-- Mirrors `src/wasm/mod.rs::WasmShim` — kernel state exposed to the WASM
    guest via the host function ABI.  `capTable` mirrors the bounded
    `heapless::Vec<Option<Capability>, MAX_WASM_CAPS>` (capacity 64). -/
structure WasmShimR where
  policy : WasmPolicy
  ledger : WasmLedger
  graph : WasmGraph
  audit : WasmAuditLog
  capTable : List (Option WasmCapability)
  deriving DecidableEq, Repr

/-- Mirrors `src/wasm/mod.rs::MAX_WASM_CAPS` (`src/wasm/mod.rs:47`). -/
def maxWasmCaps : Nat := 64

/-- Mirrors the ABI return-code constants `RC_PERMITTED` / `RC_CAP_DENIED` /
    `RC_QUOTA_EXCEEDED` / `RC_TOPO_VIOLATION` / `RC_INVALID_HANDLE`
    (`src/wasm/mod.rs:50-54`).  Represented as plain integers since Lean's
    `Int` mirrors Rust's `i32` closely enough for this spec layer. -/
def rcPermitted : Int := 0
def rcCapDenied : Int := 1
def rcQuotaExceeded : Int := 2
def rcTopoViolation : Int := 3
def rcInvalidHandle : Int := -1

/-- Rust: `impl WasmShim { pub fn from_boot_state(boot: BootState) -> Self }`
    (`src/wasm/mod.rs:77`). -/
opaque wasmShimFromBootState (boot : WasmBootState) : WasmShimR

def wasmShimFromBootState_pre (_boot : WasmBootState) : Prop := True

def wasmShimFromBootState_post (boot : WasmBootState) (s : WasmShimR) : Prop :=
  s.policy = boot.policy ∧ s.ledger = boot.ledger ∧ s.graph = boot.graph ∧
  s.audit.entries = 0 ∧ s.capTable = []

/-- Rust: `impl WasmShim { pub const fn from_parts(policy: Policy, ledger: Ledger, graph: OperationalGraph) -> Self }`
    (`src/wasm/mod.rs:92`). -/
opaque wasmShimFromParts (policy : WasmPolicy) (ledger : WasmLedger) (graph : WasmGraph) : WasmShimR

def wasmShimFromParts_pre (_policy : WasmPolicy) (_ledger : WasmLedger) (_graph : WasmGraph) : Prop := True

def wasmShimFromParts_post (policy : WasmPolicy) (ledger : WasmLedger) (graph : WasmGraph)
    (s : WasmShimR) : Prop :=
  s.policy = policy ∧ s.ledger = ledger ∧ s.graph = graph ∧
  s.audit.entries = 0 ∧ s.capTable = []

/-- Rust: `impl WasmShim { pub fn register_cap(&mut self, cap: Capability) -> Option<u32> }`
    (`src/wasm/mod.rs:105`).  I2-supporting: registers `cap` in the bounded
    handle table; fails closed (returns `None`) when the table is full
    rather than overwriting or silently dropping an existing entry. -/
opaque registerCap (s : WasmShimR) (cap : WasmCapability) : WasmShimR × Option Nat

def registerCap_pre (_s : WasmShimR) (_cap : WasmCapability) : Prop := True

def registerCap_post (s : WasmShimR) (cap : WasmCapability)
    (result : WasmShimR × Option Nat) : Prop :=
  let (s', r) := result
  (s.capTable.length < maxWasmCaps →
    ∃ idx, r = some idx ∧ idx = s.capTable.length ∧
      s'.capTable.length = s.capTable.length + 1 ∧
      s'.capTable.get? idx = some (some cap)) ∧
  (s.capTable.length ≥ maxWasmCaps → r = none ∧ s' = s)

/-- Rust: `impl WasmShim { pub const fn audit(&self) -> &AuditLog }`
    (`src/wasm/mod.rs:113`).  Trivial pure accessor. -/
def wasmShimAudit (s : WasmShimR) : WasmAuditLog := s.audit

def wasmShimAudit_pre (_s : WasmShimR) : Prop := True

def wasmShimAudit_post (s : WasmShimR) (r : WasmAuditLog) : Prop := r = s.audit

/-- Rust: `impl WasmShim { pub fn policy_check(&mut self, cap_handle: u32, right_bits: u32) -> i32 }`
    (`src/wasm/mod.rs:118`).  I1 + I2: implementation of
    `host::lux_policy_check`.  Fails closed to `RC_INVALID_HANDLE` on an
    out-of-range or vacated handle, then delegates to `Policy::check`. -/
opaque shimPolicyCheck (s : WasmShimR) (capHandle : Nat) (rightBits : WasmCapSet) :
    WasmShimR × Int

def shimPolicyCheck_pre (_s : WasmShimR) (_capHandle : Nat) (_rightBits : WasmCapSet) : Prop := True

def shimPolicyCheck_post (s : WasmShimR) (capHandle : Nat) (_rightBits : WasmCapSet)
    (result : WasmShimR × Int) : Prop :=
  let (s', r) := result
  (capHandle ≥ s.capTable.length → r = rcInvalidHandle ∧ s' = s) ∧
  (capHandle < s.capTable.length ∧ s.capTable.get! capHandle = none →
    r = rcInvalidHandle ∧ s' = s) ∧
  (capHandle < s.capTable.length →
    (∃ cap, s.capTable.get! capHandle = some cap) →
    r = rcPermitted ∨ r = rcCapDenied)

/-- Rust: `impl WasmShim { pub fn ledger_deduct(&mut self, node_id: u32, amount: u64) -> i32 }`
    (`src/wasm/mod.rs:134`).  I1 + I3: implementation of
    `host::lux_ledger_deduct`.  Fails closed to `RC_INVALID_HANDLE` when
    `node_id` is not a valid nonzero node, otherwise delegates to
    `QuotaEnforcer::deduct`. -/
opaque shimLedgerDeduct (s : WasmShimR) (nodeId : Nat) (amount : Nat) : WasmShimR × Int

def shimLedgerDeduct_pre (_s : WasmShimR) (_nodeId : Nat) (_amount : Nat) : Prop := True

def shimLedgerDeduct_post (s : WasmShimR) (nodeId : Nat) (_amount : Nat)
    (result : WasmShimR × Int) : Prop :=
  let (s', r) := result
  (nodeId = 0 → r = rcInvalidHandle ∧ s' = s) ∧
  (nodeId ≠ 0 → r = rcPermitted ∨ r = rcQuotaExceeded)

/-- Rust: `impl WasmShim { pub fn topology_traverse(&mut self, src_id: u32, dst_id: u32) -> i32 }`
    (`src/wasm/mod.rs:146`).  I1 + I4: implementation of
    `host::lux_topology_traverse`.  Fails closed to `RC_INVALID_HANDLE` when
    either ID is not a valid nonzero node, otherwise delegates to
    `OperationalGraph::traverse`. -/
opaque shimTopologyTraverse (s : WasmShimR) (srcId : Nat) (dstId : Nat) : WasmShimR × Int

def shimTopologyTraverse_pre (_s : WasmShimR) (_srcId : Nat) (_dstId : Nat) : Prop := True

def shimTopologyTraverse_post (s : WasmShimR) (srcId : Nat) (dstId : Nat)
    (result : WasmShimR × Int) : Prop :=
  let (s', r) := result
  (srcId = 0 ∨ dstId = 0 → r = rcInvalidHandle ∧ s' = s) ∧
  (srcId ≠ 0 ∧ dstId ≠ 0 →
    (r = rcPermitted ∧ (srcId, dstId) ∈ s.graph.edges) ∨
    r = rcTopoViolation)

-- ════════════════════════════════════════════════════════════════════════
-- §4  src/wasm/host.rs
-- ════════════════════════════════════════════════════════════════════════

/-- Rust: `pub fn lux_policy_check(shim: &mut WasmShim, cap_handle: u32, right_bits: u32) -> i32`
    (`src/wasm/host.rs:40`).  Thin ABI wrapper delegating to
    `WasmShim::policy_check`. -/
opaque luxPolicyCheck (s : WasmShimR) (capHandle : Nat) (rightBits : WasmCapSet) :
    WasmShimR × Int

def luxPolicyCheck_pre (_s : WasmShimR) (_capHandle : Nat) (_rightBits : WasmCapSet) : Prop := True

/-- Identical contract to `shimPolicyCheck_post`: this function is a pure
    pass-through wrapper. -/
def luxPolicyCheck_post (s : WasmShimR) (capHandle : Nat) (rightBits : WasmCapSet)
    (result : WasmShimR × Int) : Prop :=
  shimPolicyCheck_post s capHandle rightBits result

/-- Rust: `pub fn lux_ledger_deduct(shim: &mut WasmShim, node_id: u32, amount: u64) -> i32`
    (`src/wasm/host.rs:47`).  Thin ABI wrapper delegating to
    `WasmShim::ledger_deduct`. -/
opaque luxLedgerDeduct (s : WasmShimR) (nodeId : Nat) (amount : Nat) : WasmShimR × Int

def luxLedgerDeduct_pre (_s : WasmShimR) (_nodeId : Nat) (_amount : Nat) : Prop := True

def luxLedgerDeduct_post (s : WasmShimR) (nodeId : Nat) (amount : Nat)
    (result : WasmShimR × Int) : Prop :=
  shimLedgerDeduct_post s nodeId amount result

/-- Rust: `pub fn lux_topology_traverse(shim: &mut WasmShim, src_id: u32, dst_id: u32) -> i32`
    (`src/wasm/host.rs:54`).  Thin ABI wrapper delegating to
    `WasmShim::topology_traverse`. -/
opaque luxTopologyTraverse (s : WasmShimR) (srcId : Nat) (dstId : Nat) : WasmShimR × Int

def luxTopologyTraverse_pre (_s : WasmShimR) (_srcId : Nat) (_dstId : Nat) : Prop := True

def luxTopologyTraverse_post (s : WasmShimR) (srcId : Nat) (dstId : Nat)
    (result : WasmShimR × Int) : Prop :=
  shimTopologyTraverse_post s srcId dstId result

-- ════════════════════════════════════════════════════════════════════════
-- §5  src/wasm/executor.rs
-- ════════════════════════════════════════════════════════════════════════

/-- Local minimal mirror of `wasmtime::Module`/guest bytecode handle — an
    opaque compiled-module identifier.  Concrete contents are out of scope
    (see REFINEMENT_GAP entries below). -/
structure WasmModuleHandle where
  id : Nat
  deriving DecidableEq, Repr

/-- Mirrors `src/wasm/executor.rs::WasmExecutor` — wraps a `wasmtime::Engine`,
    `Linker<WasmShim>`, and `Store<WasmShim>`.  Modelled abstractly as the
    `WasmShimR` it carries, since the engine/linker have no kernel-visible
    state of their own. -/
structure WasmExecutorR where
  shim : WasmShimR
  deriving DecidableEq, Repr

/-- Rust: `impl std::fmt::Debug for WasmExecutor { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result }`
    (`src/wasm/executor.rs:40`).  Debug formatting via `finish_non_exhaustive`
    — prints only the struct name, no fields.  Modelled as a pure
    string-producing function with no effect on `ex`. -/
opaque wasmExecutorFmt (ex : WasmExecutorR) : String

def wasmExecutorFmt_pre (_ex : WasmExecutorR) : Prop := True

def wasmExecutorFmt_post (_ex : WasmExecutorR) (r : String) : Prop := r ≠ ""

-- REFINEMENT_GAP: src/wasm/executor.rs:57 — constructs a real
-- `wasmtime::Engine`/`Linker`; whether linker registration succeeds is a
-- property of the `wasmtime` crate's internals, not mathematically
-- characterizable in this spec layer.
/-- Rust: `impl WasmExecutor { pub fn new(shim: WasmShim) -> Result<Self> }`
    (`src/wasm/executor.rs:57`).  Registers the three Lux host functions
    (`lux_policy_check`, `lux_ledger_deduct`, `lux_topology_traverse`) as
    `"lux"`-module imports.  Fails closed with `WasmFault` if registration
    fails (should not occur under normal conditions per the doc comment). -/
opaque wasmExecutorNew (shim : WasmShimR) : LuxResult WasmExecutorR

def wasmExecutorNew_pre (_shim : WasmShimR) : Prop := True

def wasmExecutorNew_post (shim : WasmShimR) (r : LuxResult WasmExecutorR) : Prop :=
  (∃ ex, r = Except.ok ex ∧ ex.shim = shim) ∨
  r = Except.error (.WasmFault "failed to register host function")

/-- Rust: `impl WasmExecutor { pub fn shim(&self) -> &WasmShim }`
    (`src/wasm/executor.rs:120`).  Trivial pure accessor. -/
def wasmExecutorShim (ex : WasmExecutorR) : WasmShimR := ex.shim

def wasmExecutorShim_pre (_ex : WasmExecutorR) : Prop := True

def wasmExecutorShim_post (ex : WasmExecutorR) (r : WasmShimR) : Prop := r = ex.shim

/-- Rust: `impl WasmExecutor { pub fn shim_mut(&mut self) -> &mut WasmShim }`
    (`src/wasm/executor.rs:127`).  Returns a mutable view of the carried
    shim; modelled as the paired-return identity transform since the
    function itself performs no mutation, only exposes one. -/
opaque wasmExecutorShimMut (ex : WasmExecutorR) : WasmExecutorR × WasmShimR

def wasmExecutorShimMut_pre (_ex : WasmExecutorR) : Prop := True

def wasmExecutorShimMut_post (ex : WasmExecutorR)
    (result : WasmExecutorR × WasmShimR) : Prop :=
  let (ex', r) := result
  ex' = ex ∧ r = ex.shim

-- REFINEMENT_GAP: src/wasm/executor.rs:150 — compiling, instantiating, and
-- executing arbitrary guest WASM bytecode cannot be characterized without
-- modelling the WASM spec itself; "the guest computed the right answer" is
-- explicitly out of scope per the task brief.
/-- Rust: `impl WasmExecutor { pub fn call_nullary(&mut self, wasm_bytes: impl AsRef<[u8]>, func_name: String) -> Result<i32> }`
    (`src/wasm/executor.rs:150`).  Compiles `wasm_bytes`, instantiates it
    against the registered Lux host imports, and calls the nullary
    `i32`-returning export `func_name`.  Fails closed with `WasmFault` at
    each of: compile failure, instantiation failure (unsatisfied imports),
    missing/mis-typed export, or guest trap. -/
opaque callNullary (ex : WasmExecutorR) (wasmBytes : List Nat) (funcName : String) :
    WasmExecutorR × LuxResult Int

def callNullary_pre (_ex : WasmExecutorR) (_wasmBytes : List Nat) (_funcName : String) : Prop := True

/-- Best-effort: the four documented `WasmFault` outcomes are mutually
    exclusive with success, and the shim's audit/ledger state persists
    across calls (mutated only via host-function side effects neither of
    which this spec models in detail since the guest's instruction
    sequence is unconstrained). -/
def callNullary_post (ex : WasmExecutorR) (wasmBytes : List Nat) (funcName : String)
    (result : WasmExecutorR × LuxResult Int) : Prop :=
  let (_ex', r) := result
  (∃ n : Int, r = Except.ok n) ∨
  r = Except.error (.WasmFault "failed to compile WASM module") ∨
  r = Except.error (.WasmFault "failed to instantiate WASM module") ∨
  r = Except.error (.WasmFault "WASM function not found or wrong type") ∨
  r = Except.error (.WasmFault "WASM guest trapped")

-- ════════════════════════════════════════════════════════════════════════
-- §6  src/tpm/mod.rs
-- ════════════════════════════════════════════════════════════════════════

/-- Mirrors `src/tpm/mod.rs::TpmQuote` — a 64-byte attestation quote.
    Layout (software mock): bytes `[0..32]` = PCR value,
    `[32..64]` = SHA-256(PCR value || nonce). -/
structure TpmQuoteR where
  bytes : List Nat
  deriving DecidableEq, Repr

/-- Mirrors `src/tpm/mod.rs::TpmQuote::as_bytes` (`src/tpm/mod.rs:55`).
    Trivial pure accessor. -/
def tpmQuoteAsBytes (q : TpmQuoteR) : List Nat := q.bytes

def tpmQuoteAsBytes_pre (q : TpmQuoteR) : Prop := q.bytes.length = 64

def tpmQuoteAsBytes_post (q : TpmQuoteR) (r : List Nat) : Prop := r = q.bytes

/-- Mirrors `src/tpm/mod.rs::TpmQuote::is_null` (`src/tpm/mod.rs:61`). -/
def tpmQuoteIsNull (q : TpmQuoteR) : Bool := q.bytes.all (· = 0)

def tpmQuoteIsNull_pre (q : TpmQuoteR) : Prop := q.bytes.length = 64

def tpmQuoteIsNull_post (q : TpmQuoteR) (r : Bool) : Prop :=
  r = true ↔ q.bytes = List.replicate 64 0

/-- Local minimal mirror of `crate::tpm::NullTpm` state — stateless, so
    modelled as `Unit`. -/
abbrev NullTpmR := Unit

/-- Rust: `impl TpmProvider for NullTpm { fn extend_pcr(&mut self, _pcr_index: u8, _data: &[u8]) -> Result<()> }`
    (`src/tpm/mod.rs:121`).  Always succeeds; no PCR state to mutate. -/
opaque nullTpmExtendPcr (t : NullTpmR) (pcrIndex : Nat) (data : List Nat) :
    NullTpmR × LuxResult Unit

def nullTpmExtendPcr_pre (_t : NullTpmR) (_pcrIndex : Nat) (_data : List Nat) : Prop := True

def nullTpmExtendPcr_post (_t : NullTpmR) (_pcrIndex : Nat) (_data : List Nat)
    (result : NullTpmR × LuxResult Unit) : Prop :=
  result.2 = Except.ok ()

/-- Rust: `impl TpmProvider for NullTpm { fn quote(&self, _pcr_index: u8, _nonce: &[u8; 32]) -> Result<TpmQuote> }`
    (`src/tpm/mod.rs:125`).  Always succeeds with the all-zeros quote. -/
opaque nullTpmQuote (t : NullTpmR) (pcrIndex : Nat) (nonce : List Nat) : LuxResult TpmQuoteR

def nullTpmQuote_pre (_t : NullTpmR) (_pcrIndex : Nat) (nonce : List Nat) : Prop :=
  nonce.length = 32

def nullTpmQuote_post (_t : NullTpmR) (_pcrIndex : Nat) (_nonce : List Nat)
    (r : LuxResult TpmQuoteR) : Prop :=
  r = Except.ok ({ bytes := List.replicate 64 0 } : TpmQuoteR)

/-- Rust: `impl TpmProvider for NullTpm { fn read_pcr(&self, _pcr_index: u8) -> Result<[u8; 32]> }`
    (`src/tpm/mod.rs:129`).  Always succeeds with an all-zeros PCR value. -/
opaque nullTpmReadPcr (t : NullTpmR) (pcrIndex : Nat) : LuxResult (List Nat)

def nullTpmReadPcr_pre (_t : NullTpmR) (_pcrIndex : Nat) : Prop := True

def nullTpmReadPcr_post (_t : NullTpmR) (_pcrIndex : Nat) (r : LuxResult (List Nat)) : Prop :=
  r = Except.ok (List.replicate 32 0)

/-- Rust: `impl TpmProvider for NullTpm { fn verify_quote(&self, _pcr_index: u8, _nonce: &[u8; 32], quote: &TpmQuote) -> Result<()> }`
    (`src/tpm/mod.rs:133`).  I1 (Fail-Closed): accepts only the all-zero
    quote; any non-null quote is rejected with `ManifestInvalid` since
    `NullTpm` has no real PCR state to verify against. -/
opaque nullTpmVerifyQuote (t : NullTpmR) (pcrIndex : Nat) (nonce : List Nat)
    (quote : TpmQuoteR) : LuxResult Unit

def nullTpmVerifyQuote_pre (_t : NullTpmR) (_pcrIndex : Nat) (nonce : List Nat)
    (quote : TpmQuoteR) : Prop :=
  nonce.length = 32 ∧ quote.bytes.length = 64

def nullTpmVerifyQuote_post (_t : NullTpmR) (_pcrIndex : Nat) (_nonce : List Nat)
    (quote : TpmQuoteR) (r : LuxResult Unit) : Prop :=
  (quote.bytes = List.replicate 64 0 → r = Except.ok ()) ∧
  (quote.bytes ≠ List.replicate 64 0 →
    r = Except.error (.ManifestInvalid "NullTpm: non-null quote cannot be verified"))

-- ════════════════════════════════════════════════════════════════════════
-- §7  src/tpm/attestation.rs
-- ════════════════════════════════════════════════════════════════════════

/-- Mirrors `src/tpm/attestation.rs::BootAttestation` — a TPM-anchored
    boot attestation packaging the manifest hash, PCR index, nonce, and
    quote. -/
structure BootAttestationR where
  manifestHash : List Nat
  pcrIndex : Nat
  nonce : List Nat
  quote : TpmQuoteR
  deriving DecidableEq, Repr

/-- Rust: `impl BootAttestation { pub const fn new(manifest_hash: [u8; 32], pcr_index: u8, nonce: [u8; 32], quote: TpmQuote) -> Self }`
    (`src/tpm/attestation.rs:44`).  Pure constructor: no TPM interaction
    occurs; all fields are caller-supplied verbatim. -/
def bootAttestationNew (manifestHash : List Nat) (pcrIndex : Nat) (nonce : List Nat)
    (quote : TpmQuoteR) : BootAttestationR :=
  { manifestHash := manifestHash, pcrIndex := pcrIndex, nonce := nonce, quote := quote }

def bootAttestationNew_pre (manifestHash : List Nat) (_pcrIndex : Nat) (nonce : List Nat)
    (quote : TpmQuoteR) : Prop :=
  manifestHash.length = 32 ∧ nonce.length = 32 ∧ quote.bytes.length = 64

def bootAttestationNew_post (manifestHash : List Nat) (pcrIndex : Nat) (nonce : List Nat)
    (quote : TpmQuoteR) (a : BootAttestationR) : Prop :=
  a.manifestHash = manifestHash ∧ a.pcrIndex = pcrIndex ∧
  a.nonce = nonce ∧ a.quote = quote

/-- Rust: `impl BootAttestation { pub const fn manifest_hash(&self) -> &[u8; 32] }`
    (`src/tpm/attestation.rs:60`).  Trivial pure accessor. -/
def bootAttestationManifestHash (a : BootAttestationR) : List Nat := a.manifestHash

def bootAttestationManifestHash_pre (_a : BootAttestationR) : Prop := True

def bootAttestationManifestHash_post (a : BootAttestationR) (r : List Nat) : Prop :=
  r = a.manifestHash

/-- Rust: `impl BootAttestation { pub const fn pcr_index(&self) -> u8 }`
    (`src/tpm/attestation.rs:66`).  Trivial pure accessor. -/
def bootAttestationPcrIndex (a : BootAttestationR) : Nat := a.pcrIndex

def bootAttestationPcrIndex_pre (_a : BootAttestationR) : Prop := True

def bootAttestationPcrIndex_post (a : BootAttestationR) (r : Nat) : Prop := r = a.pcrIndex

/-- Rust: `impl BootAttestation { pub const fn nonce(&self) -> &[u8; 32] }`
    (`src/tpm/attestation.rs:72`).  Trivial pure accessor. -/
def bootAttestationNonce (a : BootAttestationR) : List Nat := a.nonce

def bootAttestationNonce_pre (_a : BootAttestationR) : Prop := True

def bootAttestationNonce_post (a : BootAttestationR) (r : List Nat) : Prop := r = a.nonce

/-- Rust: `impl BootAttestation { pub const fn quote(&self) -> &TpmQuote }`
    (`src/tpm/attestation.rs:78`).  Trivial pure accessor. -/
def bootAttestationQuote (a : BootAttestationR) : TpmQuoteR := a.quote

def bootAttestationQuote_pre (_a : BootAttestationR) : Prop := True

def bootAttestationQuote_post (a : BootAttestationR) (r : TpmQuoteR) : Prop := r = a.quote

/-- Rust: `impl BootAttestation { pub fn verify<T: TpmProvider>(&self, tpm: &T) -> Result<()> }`
    (`src/tpm/attestation.rs:92`).  Delegates to `TpmProvider::verify_quote`
    with the stored `pcr_index`, `nonce`, and `quote`.  Caller must ensure
    `tpm` is in the PCR state present when the quote was produced
    (precondition, not checked by this function). -/
opaque bootAttestationVerify (a : BootAttestationR)
    (verifyQuote : Nat → List Nat → TpmQuoteR → LuxResult Unit) : LuxResult Unit

def bootAttestationVerify_pre (a : BootAttestationR) (_verifyQuote : Nat → List Nat → TpmQuoteR → LuxResult Unit) : Prop :=
  a.nonce.length = 32 ∧ a.quote.bytes.length = 64

/-- The result is exactly whatever the underlying `verify_quote` oracle
    returns for `(pcrIndex, nonce, quote)` — `verify` adds no logic of its
    own beyond field projection. -/
def bootAttestationVerify_post (a : BootAttestationR)
    (verifyQuote : Nat → List Nat → TpmQuoteR → LuxResult Unit) (r : LuxResult Unit) : Prop :=
  r = verifyQuote a.pcrIndex a.nonce a.quote

-- ════════════════════════════════════════════════════════════════════════
-- §8  src/tpm/mock.rs
-- ════════════════════════════════════════════════════════════════════════

/-- Mirrors `src/tpm/mock.rs::PCR_COUNT` (`src/tpm/mock.rs:26`). -/
def pcrCount : Nat := 24

/-- Mirrors `src/tpm/mock.rs::SoftwareTpm` — a 24-register SHA-256 PCR
    bank, each register a 32-byte digest. -/
structure SoftwareTpmR where
  pcrs : List (List Nat)
  deriving DecidableEq, Repr

/-- Rust: `impl SoftwareTpm { pub const fn new() -> Self }`
    (`src/tpm/mock.rs:37`).  Constructs a fresh TPM with all 24 PCRs
    initialised to 32 zero bytes. -/
def softwareTpmNew : SoftwareTpmR :=
  { pcrs := List.replicate pcrCount (List.replicate 32 0) }

def softwareTpmNew_pre : Prop := True

def softwareTpmNew_post (t : SoftwareTpmR) : Prop :=
  t.pcrs.length = pcrCount ∧ ∀ pcr ∈ t.pcrs, pcr = List.replicate 32 0

/-- Rust: `impl SoftwareTpm { pub fn pcr_value(&self, index: usize) -> Option<[u8; 32]> }`
    (`src/tpm/mock.rs:45`).  Trivial pure accessor: bounds-checked PCR read. -/
def softwareTpmPcrValue (t : SoftwareTpmR) (index : Nat) : Option (List Nat) :=
  t.pcrs.get? index

def softwareTpmPcrValue_pre (t : SoftwareTpmR) (_index : Nat) : Prop :=
  t.pcrs.length = pcrCount

def softwareTpmPcrValue_post (t : SoftwareTpmR) (index : Nat) (r : Option (List Nat)) : Prop :=
  (index < t.pcrs.length → r = t.pcrs.get? index) ∧
  (index ≥ t.pcrs.length → r = none)

/-- Rust: `impl Default for SoftwareTpm { fn default() -> Self }`
    (`src/tpm/mock.rs:51`). -/
def softwareTpmDefault : SoftwareTpmR := softwareTpmNew

def softwareTpmDefault_pre : Prop := True

def softwareTpmDefault_post (t : SoftwareTpmR) : Prop :=
  t.pcrs.length = pcrCount ∧ ∀ pcr ∈ t.pcrs, pcr = List.replicate 32 0

-- REFINEMENT_GAP: src/tpm/mock.rs:57 — relies on SHA-256 as an opaque
-- cryptographic primitive; "correct" PCR extension is defined by
-- bit-for-bit hash output, not expressible independent of the hash
-- function itself.
/-- Rust: `impl TpmProvider for SoftwareTpm { fn extend_pcr(&mut self, pcr_index: u8, data: &[u8]) -> Result<()> }`
    (`src/tpm/mock.rs:57`).  `PCR[pcr_index] = SHA-256(PCR[pcr_index] || data)`.
    I1 (Fail-Closed): out-of-range `pcr_index` yields `Err(ManifestInvalid)`
    and leaves the PCR bank unmodified. -/
opaque softwareTpmExtendPcr (t : SoftwareTpmR) (pcrIndex : Nat) (data : List Nat) :
    SoftwareTpmR × LuxResult Unit

def softwareTpmExtendPcr_pre (t : SoftwareTpmR) (_pcrIndex : Nat) (_data : List Nat) : Prop :=
  t.pcrs.length = pcrCount

def softwareTpmExtendPcr_post (t : SoftwareTpmR) (pcrIndex : Nat) (_data : List Nat)
    (result : SoftwareTpmR × LuxResult Unit) : Prop :=
  let (t', r) := result
  (pcrIndex ≥ pcrCount →
    r = Except.error (.ManifestInvalid "TPM PCR index out of range") ∧ t' = t) ∧
  (pcrIndex < pcrCount →
    r = Except.ok () ∧ t'.pcrs.length = pcrCount ∧
    (∀ i, i ≠ pcrIndex → t'.pcrs.get? i = t.pcrs.get? i) ∧
    t'.pcrs.get? pcrIndex ≠ t.pcrs.get? pcrIndex)

-- REFINEMENT_GAP: src/tpm/mock.rs:71 — quote bytes are a deterministic
-- function of PCR state and nonce via SHA-256, treated here only up to
-- "is some deterministic function of (pcrValue, nonce)" since the hash
-- function itself is an unmodelled oracle.
/-- Rust: `impl TpmProvider for SoftwareTpm { fn quote(&self, pcr_index: u8, nonce: &[u8; 32]) -> Result<TpmQuote> }`
    (`src/tpm/mock.rs:71`).  Produces `quote.bytes[0..32] = PCR[pcr_index]`,
    `quote.bytes[32..64] = SHA-256(PCR[pcr_index] || nonce)`.  I1: fails
    closed with `ManifestInvalid` on out-of-range `pcr_index`. -/
opaque softwareTpmQuote (t : SoftwareTpmR) (pcrIndex : Nat) (nonce : List Nat) :
    LuxResult TpmQuoteR

def softwareTpmQuote_pre (t : SoftwareTpmR) (_pcrIndex : Nat) (nonce : List Nat) : Prop :=
  t.pcrs.length = pcrCount ∧ nonce.length = 32

def softwareTpmQuote_post (t : SoftwareTpmR) (pcrIndex : Nat) (_nonce : List Nat)
    (r : LuxResult TpmQuoteR) : Prop :=
  (pcrIndex ≥ pcrCount → r = Except.error (.ManifestInvalid "TPM PCR index out of range")) ∧
  (pcrIndex < pcrCount →
    ∃ q : TpmQuoteR, r = Except.ok q ∧ q.bytes.length = 64 ∧
      q.bytes.take 32 = t.pcrs.get! pcrIndex)

/-- Rust: `impl TpmProvider for SoftwareTpm { fn read_pcr(&self, pcr_index: u8) -> Result<[u8; 32]> }`
    (`src/tpm/mock.rs:92`).  I1: fails closed with `ManifestInvalid` on
    out-of-range `pcr_index`; otherwise returns the current PCR value. -/
opaque softwareTpmReadPcr (t : SoftwareTpmR) (pcrIndex : Nat) : LuxResult (List Nat)

def softwareTpmReadPcr_pre (t : SoftwareTpmR) (_pcrIndex : Nat) : Prop :=
  t.pcrs.length = pcrCount

def softwareTpmReadPcr_post (t : SoftwareTpmR) (pcrIndex : Nat) (r : LuxResult (List Nat)) : Prop :=
  (pcrIndex ≥ pcrCount → r = Except.error (.ManifestInvalid "TPM PCR index out of range")) ∧
  (pcrIndex < pcrCount → r = Except.ok (t.pcrs.get! pcrIndex))

-- REFINEMENT_GAP: src/tpm/mock.rs:102 — verification correctness is
-- contingent on SHA-256 collision resistance, an unmodelled cryptographic
-- assumption; modelled here only up to "accepts iff bytes match the PCR
-- value and an oracle-computed signed digest."
/-- Rust: `impl TpmProvider for SoftwareTpm { fn verify_quote(&self, pcr_index: u8, nonce: &[u8; 32], quote: &TpmQuote) -> Result<()> }`
    (`src/tpm/mock.rs:102`).  Recomputes the expected quote bytes from the
    current PCR state and nonce, and compares against `quote`.  I1: fails
    closed with `ManifestInvalid` on out-of-range `pcr_index` or on
    mismatch. -/
opaque softwareTpmVerifyQuote (t : SoftwareTpmR) (pcrIndex : Nat) (nonce : List Nat)
    (quote : TpmQuoteR) : LuxResult Unit

def softwareTpmVerifyQuote_pre (t : SoftwareTpmR) (_pcrIndex : Nat) (nonce : List Nat)
    (quote : TpmQuoteR) : Prop :=
  t.pcrs.length = pcrCount ∧ nonce.length = 32 ∧ quote.bytes.length = 64

def softwareTpmVerifyQuote_post (t : SoftwareTpmR) (pcrIndex : Nat) (_nonce : List Nat)
    (quote : TpmQuoteR) (r : LuxResult Unit) : Prop :=
  (pcrIndex ≥ pcrCount → r = Except.error (.ManifestInvalid "TPM PCR index out of range")) ∧
  (pcrIndex < pcrCount ∧ quote.bytes.take 32 ≠ t.pcrs.get! pcrIndex →
    r = Except.error (.ManifestInvalid
      "TPM quote verification failed: PCR value or signature mismatch")) ∧
  (pcrIndex < pcrCount ∧ quote.bytes.take 32 = t.pcrs.get! pcrIndex →
    r = Except.ok () ∨
    r = Except.error (.ManifestInvalid
      "TPM quote verification failed: PCR value or signature mismatch"))

-- ════════════════════════════════════════════════════════════════════════
-- §9  src/tpm/tss.rs
-- ════════════════════════════════════════════════════════════════════════

/-- Mirrors `src/tpm/tss.rs::TssTpmProvider` — currently a software stub
    with a single private `_connected : bool` field. -/
structure TssTpmProviderR where
  connected : Bool
  deriving DecidableEq, Repr

-- REFINEMENT_GAP: src/tpm/tss.rs:41 — trivial today (always produces a
-- disconnected stub), but flagged because it is the seam where real
-- TCTI/hardware connection logic will eventually live.
/-- Rust: `impl TssTpmProvider { pub const fn new_stub() -> Self }`
    (`src/tpm/tss.rs:41`).  Constructs a disconnected stub; no TCTI
    connection is opened. -/
def tssTpmProviderNewStub : TssTpmProviderR := { connected := false }

def tssTpmProviderNewStub_pre : Prop := True

def tssTpmProviderNewStub_post (t : TssTpmProviderR) : Prop := t.connected = false

-- REFINEMENT_GAP: src/tpm/tss.rs:47 — real-hardware TPM operation; the
-- current stub always errs, but the eventual hardware-backed semantics
-- (irreversible PCR extension via silicon) cannot be specified without
-- modelling the TPM 2.0 spec.
/-- Rust: `impl TpmProvider for TssTpmProvider { fn extend_pcr(&mut self, _pcr_index: u8, _data: &[u8]) -> Result<()> }`
    (`src/tpm/tss.rs:47`).  I1 (Fail-Closed): always returns
    `Err(ManifestInvalid)` until a real TPM 2.0 device is connected. -/
opaque tssTpmExtendPcr (t : TssTpmProviderR) (pcrIndex : Nat) (data : List Nat) :
    TssTpmProviderR × LuxResult Unit

def tssTpmExtendPcr_pre (_t : TssTpmProviderR) (_pcrIndex : Nat) (_data : List Nat) : Prop := True

def tssTpmExtendPcr_post (t : TssTpmProviderR) (_pcrIndex : Nat) (_data : List Nat)
    (result : TssTpmProviderR × LuxResult Unit) : Prop :=
  let (t', r) := result
  t' = t ∧
  r = Except.error (.ManifestInvalid "TssTpmProvider: hardware not connected (stub implementation)")

-- REFINEMENT_GAP: src/tpm/tss.rs:53 — real-hardware TPM operation;
-- eventual quote semantics depend on `TPMS_ATTEST` structure and AK
-- signature, out of scope for this spec layer.
/-- Rust: `impl TpmProvider for TssTpmProvider { fn quote(&self, _pcr_index: u8, _nonce: &[u8; 32]) -> Result<TpmQuote> }`
    (`src/tpm/tss.rs:53`).  I1: always returns `Err(ManifestInvalid)` until
    a real TPM 2.0 device is connected. -/
opaque tssTpmQuote (t : TssTpmProviderR) (pcrIndex : Nat) (nonce : List Nat) : LuxResult TpmQuoteR

def tssTpmQuote_pre (_t : TssTpmProviderR) (_pcrIndex : Nat) (nonce : List Nat) : Prop :=
  nonce.length = 32

def tssTpmQuote_post (_t : TssTpmProviderR) (_pcrIndex : Nat) (_nonce : List Nat)
    (r : LuxResult TpmQuoteR) : Prop :=
  r = Except.error (.ManifestInvalid "TssTpmProvider: hardware not connected (stub implementation)")

-- REFINEMENT_GAP: src/tpm/tss.rs:59 — real-hardware PCR read; depends on
-- physical TPM state not modelled here.
/-- Rust: `impl TpmProvider for TssTpmProvider { fn read_pcr(&self, _pcr_index: u8) -> Result<[u8; 32]> }`
    (`src/tpm/tss.rs:59`).  I1: always returns `Err(ManifestInvalid)` until
    a real TPM 2.0 device is connected. -/
opaque tssTpmReadPcr (t : TssTpmProviderR) (pcrIndex : Nat) : LuxResult (List Nat)

def tssTpmReadPcr_pre (_t : TssTpmProviderR) (_pcrIndex : Nat) : Prop := True

def tssTpmReadPcr_post (_t : TssTpmProviderR) (_pcrIndex : Nat) (r : LuxResult (List Nat)) : Prop :=
  r = Except.error (.ManifestInvalid "TssTpmProvider: hardware not connected (stub implementation)")

-- REFINEMENT_GAP: src/tpm/tss.rs:65 — real-hardware signature verification
-- against an AK public key; cryptographic verification is out of scope
-- for this spec layer.
/-- Rust: `impl TpmProvider for TssTpmProvider { fn verify_quote(&self, _pcr_index: u8, _nonce: &[u8; 32], _quote: &TpmQuote) -> Result<()> }`
    (`src/tpm/tss.rs:65`).  I1: always returns `Err(ManifestInvalid)` until
    a real TPM 2.0 device is connected. -/
opaque tssTpmVerifyQuote (t : TssTpmProviderR) (pcrIndex : Nat) (nonce : List Nat)
    (quote : TpmQuoteR) : LuxResult Unit

def tssTpmVerifyQuote_pre (_t : TssTpmProviderR) (_pcrIndex : Nat) (nonce : List Nat)
    (quote : TpmQuoteR) : Prop :=
  nonce.length = 32 ∧ quote.bytes.length = 64

def tssTpmVerifyQuote_post (_t : TssTpmProviderR) (_pcrIndex : Nat) (_nonce : List Nat)
    (_quote : TpmQuoteR) (r : LuxResult Unit) : Prop :=
  r = Except.error (.ManifestInvalid "TssTpmProvider: hardware not connected (stub implementation)")

end FunctionSpecs
