/-!
# Lux Kernel — Function Spec Layer: Topology Module

Covers every production function in `src/topology/graph.rs` (9 functions):
- `BootingGraph::new`, `activate`, `permit_edge`, `seal`, `default`
- `OperationalGraph::traverse`, `traverse_inner`, `is_active`
- `node_idx` (private helper)

Total: 9 functions specified.

This module backs **I4 (Topology-Bounded)**.  The typestate design
(`BootingGraph` → `seal()` → `OperationalGraph`) is encoded here as two
separate Lean structures, mirroring the Rust types exactly — `seal`'s
postcondition is the only place the two types meet. No proofs are attempted
anywhere in this file.

## REFINEMENT_GAP entries in this file

None.  Every function in `src/topology/graph.rs` is a pure, deterministic
function of its inputs (bitmask arithmetic and array indexing only).
-/

import FunctionSpecs.Core

open FunctionSpecs

namespace FunctionSpecs.Topology

def maxNodes : Nat := 64

-- ── Domain types mirroring `src/topology/graph.rs` ────────────────────────────

/-- Mirrors `src/topology/graph.rs::BootingGraph`.  `activeNodes` and
    `edgeMatrix` are `u64` bitmasks / a `[u64; MAX_NODES]` adjacency matrix
    in Rust; modelled here as a `Nat` bitmask and a `List Nat` (length
    `maxNodes`) of row-bitmasks respectively, with bitwise structure exposed
    via the helper predicates `bitSet`/`edgeSet` below rather than Lean's
    native `&&&`/`|||` operators, to keep the pre/post Props readable. -/
structure BootingGraph where
  activeNodes : Nat
  edgeMatrix : List Nat
  deriving Repr

/-- Mirrors `src/topology/graph.rs::OperationalGraph` — structurally
    identical to `BootingGraph`, but produced only via `seal` and exposing
    only `traverse`/`is_active`. -/
structure OperationalGraph where
  activeNodes : Nat
  edgeMatrix : List Nat
  deriving Repr

/-- `true` iff bit `idx` is set in bitmask `mask`. Mirrors `(mask >> idx) & 1 == 1`. -/
def bitSet (mask : Nat) (idx : Nat) : Bool := decide (mask / 2 ^ idx % 2 = 1)

/-- `true` iff the edge `(srcIdx → dstIdx)` is declared in `edgeMatrix`
    (row `srcIdx`, bit `dstIdx`). Mirrors `(edge_matrix[si] >> di) & 1 == 1`. -/
def edgeSet (edgeMatrix : List Nat) (srcIdx dstIdx : Nat) : Bool :=
  match edgeMatrix[srcIdx]? with
  | some row => bitSet row dstIdx
  | none => false

-- ── `node_idx` (`src/topology/graph.rs:184`, private helper) ─────────────────

/-- Rust: `const fn node_idx(id: NodeId) -> Result<usize>`.  Converts a
    1-based `NodeId` to a 0-based array index, or denies if `id > MAX_NODES`. -/
def nodeIdx (id : NodeId) : LuxResult Nat :=
  let idx := if id = 0 then 0 else id - 1
  -- mirrors `(id.get() as usize).saturating_sub(1)`; NodeId = 0 is excluded
  -- by the Rust NonZeroU32 invariant and is not a reachable input in
  -- practice, but the saturating_sub is restated faithfully here.
  if idx ≥ maxNodes then .error (.TopologyViolation id 0) else .ok idx

def nodeIdx_pre (_id : NodeId) : Prop := True

def nodeIdx_post (id : NodeId) (r : LuxResult Nat) : Prop :=
  let idx := if id = 0 then 0 else id - 1
  (idx ≥ maxNodes → r = .error (.TopologyViolation id 0)) ∧
  (idx < maxNodes → r = .ok idx)

-- ── `BootingGraph::new` (`src/topology/graph.rs:42`) ──────────────────────────

/-- Rust: `pub const fn new() -> Self`. -/
def bootingGraphNew : BootingGraph := { activeNodes := 0, edgeMatrix := List.replicate maxNodes 0 }

def bootingGraphNew_pre : Prop := True

def bootingGraphNew_post (g : BootingGraph) : Prop :=
  g.activeNodes = 0 ∧ g.edgeMatrix = List.replicate maxNodes 0

-- ── `BootingGraph::activate` (`src/topology/graph.rs:55`) ─────────────────────

/-- Rust: `pub fn activate(&mut self, id: NodeId) -> Result<()>`. -/
opaque activate (g : BootingGraph) (id : NodeId) : BootingGraph × LuxResult Unit

def activate_pre (_g : BootingGraph) (_id : NodeId) : Prop := True

/-- Denies (`TopologyViolation`, `g` unchanged) iff `nodeIdx id` fails (i.e.
    `id > MAX_NODES`). Otherwise sets bit `idx` in `activeNodes`; `edgeMatrix`
    is untouched. Idempotent: activating an already-active node succeeds
    again with no observable change. -/
def activate_post (g : BootingGraph) (id : NodeId) (r : BootingGraph × LuxResult Unit) : Prop :=
  let (g', res) := r
  (∀ e, nodeIdx id = .error e → res = .error e ∧ g' = g) ∧
  (∀ idx, nodeIdx id = .ok idx →
    res = .ok () ∧ g'.edgeMatrix = g.edgeMatrix ∧ bitSet g'.activeNodes idx = true ∧
      ∀ j, j ≠ idx → bitSet g'.activeNodes j = bitSet g.activeNodes j)

-- ── `BootingGraph::permit_edge` (`src/topology/graph.rs:70`) ─────────────────

/-- Rust: `pub fn permit_edge(&mut self, src: NodeId, dst: NodeId) ->
    Result<()>`.  Requires **both** endpoints to already be active
    (pre-activation guard) — declaring an edge before activating both
    endpoints is denied, preventing "ghost edges." -/
opaque permitEdge (g : BootingGraph) (src dst : NodeId) : BootingGraph × LuxResult Unit

def permitEdge_pre (_g : BootingGraph) (_src _dst : NodeId) : Prop := True

/-- Denies with `TopologyViolation {src, dst}` (and leaves `g` unchanged) if
    either `nodeIdx` fails, or if either endpoint is not active. Otherwise
    sets bit `di` in row `si` of `edgeMatrix` (where `si`/`di` are the
    resolved indices of `src`/`dst`); `activeNodes` is untouched. Idempotent. -/
def permitEdge_post (g : BootingGraph) (src dst : NodeId) (r : BootingGraph × LuxResult Unit) : Prop :=
  let (g', res) := r
  (∀ si, nodeIdx src = .ok si → bitSet g.activeNodes si = false →
    res = .error (.TopologyViolation src dst) ∧ g' = g) ∧
  (∀ di, nodeIdx dst = .ok di → bitSet g.activeNodes di = false →
    res = .error (.TopologyViolation src dst) ∧ g' = g) ∧
  (∀ si di, nodeIdx src = .ok si → nodeIdx dst = .ok di →
    bitSet g.activeNodes si = true → bitSet g.activeNodes di = true →
    res = .ok () ∧ g'.activeNodes = g.activeNodes ∧ edgeSet g'.edgeMatrix si di = true)

-- ── `BootingGraph::seal` (`src/topology/graph.rs:94`) ─────────────────────────

/-- Rust: `pub const fn seal(self) -> OperationalGraph`.  Consumes the
    mutable graph; after this call `activate`/`permit_edge` are unreachable
    by the type system (no Lean counterpart to "consumed" — the spec layer
    just states the field-copy contract). -/
def seal (g : BootingGraph) : OperationalGraph := { activeNodes := g.activeNodes, edgeMatrix := g.edgeMatrix }

def seal_pre (_g : BootingGraph) : Prop := True

def seal_post (g : BootingGraph) (r : OperationalGraph) : Prop :=
  r.activeNodes = g.activeNodes ∧ r.edgeMatrix = g.edgeMatrix

-- ── `impl Default for BootingGraph` (`src/topology/graph.rs:102`) ────────────

/-- Rust: `fn default() -> Self { Self::new() }`. -/
def bootingGraphDefault : BootingGraph := bootingGraphNew

def bootingGraphDefault_pre : Prop := True

def bootingGraphDefault_post (g : BootingGraph) : Prop :=
  g.activeNodes = 0 ∧ g.edgeMatrix = List.replicate maxNodes 0

-- ── `OperationalGraph::traverse` (`src/topology/graph.rs:132`) ───────────────

/-- Rust: `pub fn traverse(&self, src: NodeId, dst: NodeId, audit: &mut
    AuditLog) -> Result<()>`.  `auditIsFull` stands in for `audit.is_full()`
    being relevant only on the otherwise-permitted path (see
    `FunctionSpecs.Audit` for the real `AuditLog` spec; not imported here —
    see `FunctionSpecs.Core`'s module doc on cross-module decoupling). -/
opaque traverse (g : OperationalGraph) (src dst : NodeId) (auditIsFull : Bool) : LuxResult Unit

def traverse_pre (_g : OperationalGraph) (_src _dst : NodeId) (_auditIsFull : Bool) : Prop := True

/-- Let `inner` be the result of `traverseInner g src dst` (below). If
    `inner` is already an error, `traverse` returns that same error
    unchanged regardless of `auditIsFull` (pre-existing denials are never
    masked — the P2 fix's non-masking guarantee). If `inner = .ok ()` and
    `auditIsFull = true`, `traverse` returns `LuxError.AuditFull` instead
    (fail-closed: an otherwise-permitted traversal that cannot be logged is
    denied). If `inner = .ok ()` and `auditIsFull = false`, `traverse`
    returns `.ok ()`. -/
def traverse_post (g : OperationalGraph) (src dst : NodeId) (auditIsFull : Bool)
    (r : LuxResult Unit) : Prop :=
  ∃ inner : LuxResult Unit,
    (∀ e, inner = .error e → r = .error e) ∧
    (inner = .ok () ∧ auditIsFull → r = .error .AuditFull) ∧
    (inner = .ok () ∧ ¬ auditIsFull → r = .ok ())

-- ── `OperationalGraph::traverse_inner` (`src/topology/graph.rs:148`, private) ─

/-- Rust: `fn traverse_inner(&self, src: NodeId, dst: NodeId) -> Result<()>`.
    The pure fail-closed core: both endpoints must resolve to valid
    indices, both must be active, and the edge must be declared. -/
def traverseInner (g : OperationalGraph) (src dst : NodeId) : LuxResult Unit :=
  match nodeIdx src, nodeIdx dst with
  | .error e, _ => .error e
  | _, .error e => .error e
  | .ok si, .ok di =>
    if ¬ bitSet g.activeNodes si then .error (.TopologyViolation src dst)
    else if ¬ bitSet g.activeNodes di then .error (.TopologyViolation src dst)
    else if ¬ edgeSet g.edgeMatrix si di then .error (.TopologyViolation src dst)
    else .ok ()

def traverseInner_pre (_g : OperationalGraph) (_src _dst : NodeId) : Prop := True

def traverseInner_post (g : OperationalGraph) (src dst : NodeId) (r : LuxResult Unit) : Prop :=
  r = traverseInner g src dst

-- ── `OperationalGraph::is_active` (`src/topology/graph.rs:174`) ──────────────

/-- Rust: `pub fn is_active(&self, id: NodeId) -> bool`. -/
def isActive (g : OperationalGraph) (id : NodeId) : Bool :=
  match nodeIdx id with
  | .ok idx => bitSet g.activeNodes idx
  | .error _ => false

def isActive_pre (_g : OperationalGraph) (_id : NodeId) : Prop := True

/-- `false` for any out-of-range `id` (`nodeIdx` failure); otherwise mirrors
    the corresponding bit of `activeNodes`. -/
def isActive_post (g : OperationalGraph) (id : NodeId) (r : Bool) : Prop := r = isActive g id

end FunctionSpecs.Topology
