import FunctionSpecs.Core

/-!
# Lux Kernel — Function Spec Layer: Python Bindings (`PyO3`)

Covers every production function in:
- `src/python/mod.rs`     (`lux_kernel` `PyO3` module registration)
- `src/python/audit.rs`   (`PyAuditLog` — hash-chained audit log binding)
- `src/python/gate.rs`    (`PyLuxGate` — stateless CE authorization gate)
- `src/python/policy.rs`  (`PyPolicyGate` — capability-gated feature checker)

Total functions specified in this file: **22**.

This is a spec-only layer: every function below gets an `opaque` (or, for
genuinely trivial pure accessors, a direct `def`) signature plus independent
`_pre`/`_post` declarations.  No theorems, no `sorry`, no attempt to link the
declarations together.  See `Core.lean`'s module doc for the full disclosure
of scope and the calling convention used throughout this tree.

PyO3 boundary types (`PyResult<T>`, `Python<'_>`, `Bound<'_, PyModule>`,
`Py<PyDict>`, `PyObject`) are modelled abstractly per the task's calling
convention: `PyResult<T>` becomes `LuxResult T` when the only error path is
a `PyValueError`/`PyRuntimeError` translated from a kernel-level rejection,
and an opaque `PyValueResult T` is used where the error carries no kernel
`LuxError` semantics at all (pure Python-side validation errors). The GIL
token `Python<'_>` and dict handles are modelled as opaque `PyDictVal` /
`PyModuleVal` values; no attempt is made to model Python's object model,
GIL semantics, or refcounting.

## REFINEMENT_GAP entries in this file

| Function | file:line | Reason |
|---|---|---|
| `luxKernelModule` | `src/python/mod.rs:45` | PyO3 `#[pymodule]` macro-generated FFI entry point registering classes into the Python C ABI; not a pure function over modelable values |
| `pyAuditLogExportJson` | `src/python/audit.rs:174` | Delegates to a JSON writer over the full audit log; exact JSON shape is a serialization detail not meaningfully captured by a Nat/String-level spec |
| `pyPolicyGateCheck` | `src/python/policy.rs:163` | Acquires the Python GIL (`Python::with_gil`) and builds a `PyDict` via FFI; the GIL acquisition and dict construction are not modelled |
| `pyLuxGateAuthorizeCe` | `src/python/gate.rs:151` | Builds a `PyDict` via FFI from a pure-Rust `CheckResult`; the dict construction step (not the underlying `check` logic, which is separately specified) is FFI-boundary code |
| `pyLuxGateConfig` | `src/python/gate.rs:173` | Builds a `PyDict` via FFI to expose configuration; dict construction is FFI-boundary code, not pure logic |
-/

namespace FunctionSpecs

-- ── Local domain types (PyO3 FFI boundary, modelled abstractly) ──────────────

/-- Opaque handle standing in for `pyo3::types::PyDict` / `Py<PyDict>` /
    `PyObject` return values built across the FFI boundary.  Not modelled
    structurally — see file-level doc comment. -/
opaque PyDictVal : Type

/-- Opaque handle standing in for `&Bound<'_, PyModule>`, the module object
    passed into `#[pymodule]` entry points. -/
opaque PyModuleVal : Type

/-- Opaque handle standing in for the `Python<'_>` GIL token threaded through
    `PyO3` calls.  Carries no information in this spec layer. -/
opaque PyGilVal : Type

/-- A `PyResult<T>` whose error path is a pure Python-side validation error
    (`PyValueError`/`PyRuntimeError`) with no corresponding `LuxError`
    variant — i.e. it never reaches the kernel's I1–I4 enforcement points.
    Modelled as `Except String T`, where the `String` is the human-readable
    PyO3 exception message. -/
abbrev PyValueResult (T : Type) := Except String T

/-- Mirrors `src/audit.rs::EventKind` — the audit event taxonomy accepted by
    `AuditLog::append`. Defined locally since the full `audit` module is
    outside this file's scope; only the variants referenced by
    `src/python/audit.rs::parse_kind` are included. -/
inductive EventKindVal where
  | HiringDecision
  | PolicyGateCheck
  | CapabilityCheck
  | CapabilityRevoked
  | ResourceDeduction
  | TopologyTraverse
  | TopologyChange
  deriving DecidableEq, Repr

/-- Mirrors `src/audit.rs::AuditLog` — opaque hash-chained, append-only,
    fixed-capacity (512 events, `MAX_AUDIT_EVENTS`) event log.  The full
    structure lives outside this file's scope; modelled here only via the
    observable properties (`length`, `headHash`, `chainValid`) needed by the
    `PyAuditLog` specs below. -/
structure AuditLogVal where
  length : Nat
  headHash : List Nat
  chainValid : Bool

/-- Mirrors `src/python/audit.rs::PyAuditLog` — the `pyclass` wrapper around
    `AuditLogVal`. -/
structure PyAuditLogVal where
  inner : AuditLogVal

/-- Mirrors `src/python/gate.rs::PyLuxGate` — fixed configuration for the CE
    authorization gate. -/
structure PyLuxGateVal where
  authorityThreshold : Nat   -- modelled as a fixed-point/Nat surrogate for f64; see *_pre/_post notes
  addAgentThreshold : Nat
  maxAgents : Nat

/-- Mirrors `src/python/gate.rs::CheckResult` (private helper struct) — the
    pure authorization-decision record produced by `PyLuxGate::check`. -/
structure CheckResultVal where
  approved : Bool
  reason : String
  denialClass : Option String

/-- Mirrors `src/python/policy.rs::PyPolicyGate` — fixed approved/blocked
    feature-name configuration (each bounded by `MAX_GATE_FEATURES` = 16). -/
structure PyPolicyGateVal where
  approved : List String
  blocked : List String

-- ── `src/python/mod.rs` ────────────────────────────────────────────────────

/-- Rust: `fn lux_kernel(m: &Bound<'_, PyModule>) -> PyResult<()>` (`src/python/mod.rs:45`).
    PyO3 `#[pymodule]` entry point; registers `PyAuditLog`, `PyLuxGate`, and
    `PyPolicyGate` as classes on the given module object.

    REFINEMENT_GAP: src/python/mod.rs:45 — PyO3 `#[pymodule]` macro-generated
    FFI entry point registering classes into the Python C ABI; not a pure
    function over modelable values. -/
opaque luxKernelModule (m : PyModuleVal) : PyValueResult Unit

def luxKernelModule_pre (_m : PyModuleVal) : Prop := True

/-- Best-effort: registration either succeeds for all three classes or
    fails with a Python-side error (e.g. out-of-memory); partial
    registration is not an intended outcome. -/
def luxKernelModule_post (_m : PyModuleVal) (_r : PyValueResult Unit) : Prop := True

-- ── `src/python/audit.rs` free functions ──────────────────────────────────

/-- Rust: `fn map_denial_reason(s: &str) -> &'static str` (`src/python/audit.rs:40`).
    Maps an incoming Python denial-reason string to its `&'static str`
    counterpart from `KNOWN_REASONS`; unknown strings fall back to
    `"policy violation"` (the last table entry). -/
opaque mapDenialReason (s : String) : String

def mapDenialReason_pre (_s : String) : Prop := True

def mapDenialReason_post (s : String) (r : String) : Prop :=
  let known := ["protected attribute in feature vector",
                "aliased protected attribute in feature vector",
                "unapproved feature in feature vector",
                "policy violation"]
  (s ∈ known → r = s) ∧ (s ∉ known → r = "policy violation")

/-- Rust: `fn parse_kind(s: &str) -> PyResult<EventKind>` (`src/python/audit.rs:48`).
    Fail-closed string-to-enum parser: any string outside the fixed table of
    seven accepted kind names is rejected with a `PyValueError`. -/
opaque parseKind (s : String) : PyValueResult EventKindVal

def parseKind_pre (_s : String) : Prop := True

def parseKind_post (s : String) (r : PyValueResult EventKindVal) : Prop :=
  (s = "hiring_decision" → r = .ok .HiringDecision) ∧
  (s = "policy_gate_check" → r = .ok .PolicyGateCheck) ∧
  (s = "capability_check" → r = .ok .CapabilityCheck) ∧
  (s = "cap_revoked" → r = .ok .CapabilityRevoked) ∧
  (s = "resource_deduct" → r = .ok .ResourceDeduction) ∧
  (s = "topo_traverse" → r = .ok .TopologyTraverse) ∧
  (s = "topo_change" → r = .ok .TopologyChange) ∧
  (s ∉ ["hiring_decision", "policy_gate_check", "capability_check", "cap_revoked",
        "resource_deduct", "topo_traverse", "topo_change"] → ∃ e, r = .error e)

/-- Rust: `fn parse_denial_class(s: &str) -> PyResult<DenialClass>` (`src/python/audit.rs:64`).
    Fail-closed string-to-enum parser: only `"halt"` and `"failure"` are
    accepted; anything else is a `PyValueError`. -/
opaque parseDenialClass (s : String) : PyValueResult LuxDenialClass

def parseDenialClass_pre (_s : String) : Prop := True

def parseDenialClass_post (s : String) (r : PyValueResult LuxDenialClass) : Prop :=
  (s = "halt" → r = .ok .Halt) ∧
  (s = "failure" → r = .ok .Failure) ∧
  (s ≠ "halt" ∧ s ≠ "failure" → ∃ e, r = .error e)

-- ── `src/python/audit.rs::PyAuditLog` impl block ──────────────────────────

/-- Rust: `impl PyAuditLog { pub const fn new() -> Self }` (`src/python/audit.rs:99`).
    Trivial pure constructor wrapping a fresh, empty `AuditLog`. -/
def pyAuditLogNew : PyAuditLogVal :=
  { inner := { length := 0, headHash := List.replicate 32 0, chainValid := true } }

def pyAuditLogNew_pre : Prop := True

def pyAuditLogNew_post (r : PyAuditLogVal) : Prop :=
  r.inner.length = 0 ∧ r.inner.chainValid = true

/-- Rust: `impl PyAuditLog { pub fn append(&mut self, kind: &str, actor: u64, timestamp: u64, denial_class: Option<&str>, denial_reason: Option<&str>) -> PyResult<bool> }`
    (`src/python/audit.rs:132`).  Parses `kind` and (if present)
    `denial_class` via `parse_kind`/`parse_denial_class` (fail-closed on
    unrecognised strings, returning `PyValueError` without mutating the
    log), clamps `actor` into `u32` range via saturation, maps
    `denial_reason` via `map_denial_reason`, and appends to the inner
    `AuditLog`. Returns `true` on success, `false` if the log was already at
    capacity (512 events) — in the `false` case the event is *not* recorded
    (fail-closed: no silent overwrite) and the log length is unchanged. -/
opaque pyAuditLogAppend
    (log : PyAuditLogVal) (kind : String) (actor timestamp : Nat)
    (denialClass : Option String) (denialReason : Option String)
    : PyAuditLogVal × PyValueResult Bool

def pyAuditLogAppend_pre
    (_log : PyAuditLogVal) (_kind : String) (_actor _timestamp : Nat)
    (_denialClass : Option String) (_denialReason : Option String) : Prop := True

def pyAuditLogAppend_post
    (log : PyAuditLogVal) (kind : String) (_actor _timestamp : Nat)
    (denialClass : Option String) (_denialReason : Option String)
    (r : PyAuditLogVal × PyValueResult Bool) : Prop :=
  -- unrecognised kind/denialClass strings deny without mutating the log
  ((kind ∉ ["hiring_decision", "policy_gate_check", "capability_check", "cap_revoked",
            "resource_deduct", "topo_traverse", "topo_change"] ∨
    ∃ s, denialClass = some s ∧ s ≠ "halt" ∧ s ≠ "failure") →
    r.1 = log ∧ ∃ e, r.2 = .error e) ∧
  -- a successful append at capacity returns false and leaves length unchanged
  (log.inner.length ≥ 512 → r.2 = .ok false → r.1.inner.length = log.inner.length) ∧
  -- a successful append below capacity returns true and increments length by 1
  (r.2 = .ok true → r.1.inner.length = log.inner.length + 1)

/-- Rust: `impl PyAuditLog { pub fn verify_chain(&self) -> bool }` (`src/python/audit.rs:161`).
    Recomputes every hash in the chain from genesis; `true` iff every
    event's hash matches the value recomputed from its predecessor (tamper
    detection). Pure accessor — does not mutate the log. -/
opaque pyAuditLogVerifyChain (log : PyAuditLogVal) : Bool

def pyAuditLogVerifyChain_pre (_log : PyAuditLogVal) : Prop := True

def pyAuditLogVerifyChain_post (log : PyAuditLogVal) (r : Bool) : Prop :=
  r = log.inner.chainValid

/-- Rust: `impl PyAuditLog { pub fn export_json(&self) -> PyResult<String> }`
    (`src/python/audit.rs:174`).  Serializes the full log as a JSON array,
    one object per event with fields `seq, kind, actor, ts, ok, class,
    reason, hash`.

    REFINEMENT_GAP: src/python/audit.rs:174 — delegates to a JSON writer
    over the full audit log; exact JSON shape is a serialization detail not
    meaningfully captured by a Nat/String-level spec. -/
opaque pyAuditLogExportJson (log : PyAuditLogVal) : PyValueResult String

def pyAuditLogExportJson_pre (_log : PyAuditLogVal) : Prop := True

/-- Best-effort: an empty log exports as the literal empty-array text
    `"[]"` (a reasonable assumption for a JSON array writer; not verified
    against the actual writer implementation, which is out of scope). -/
def pyAuditLogExportJson_post (log : PyAuditLogVal) (r : PyValueResult String) : Prop :=
  log.inner.length = 0 → r = .ok "[]"

/-- Rust: `impl PyAuditLog { pub fn len(&self) -> usize }` (`src/python/audit.rs:184`).
    Trivial pure accessor. -/
def pyAuditLogLen (log : PyAuditLogVal) : Nat := log.inner.length

def pyAuditLogLen_pre (_log : PyAuditLogVal) : Prop := True

def pyAuditLogLen_post (log : PyAuditLogVal) (r : Nat) : Prop := r = log.inner.length

/-- Rust: `impl PyAuditLog { pub fn is_empty(&self) -> bool }` (`src/python/audit.rs:190`).
    Trivial pure accessor. -/
def pyAuditLogIsEmpty (log : PyAuditLogVal) : Bool := log.inner.length == 0

def pyAuditLogIsEmpty_pre (_log : PyAuditLogVal) : Prop := True

def pyAuditLogIsEmpty_post (log : PyAuditLogVal) (r : Bool) : Prop :=
  r = true ↔ log.inner.length = 0

/-- Rust: `impl PyAuditLog { pub fn head_hash(&self) -> String }` (`src/python/audit.rs:197`).
    Hex-encodes the most recent event's hash (64 lowercase hex chars); for
    an empty log this is 64 zero characters (the all-zeros genesis hash). -/
opaque pyAuditLogHeadHash (log : PyAuditLogVal) : String

def pyAuditLogHeadHash_pre (_log : PyAuditLogVal) : Prop := True

def pyAuditLogHeadHash_post (log : PyAuditLogVal) (r : String) : Prop :=
  r.length = 64 ∧ (log.inner.length = 0 → r = String.mk (List.replicate 64 '0'))

/-- Rust: `impl PyAuditLog { fn __len__(&self) -> usize }` (`src/python/audit.rs:208`).
    Python `len()` protocol hook; identical behaviour to `len`. -/
def pyAuditLogDunderLen (log : PyAuditLogVal) : Nat := log.inner.length

def pyAuditLogDunderLen_pre (_log : PyAuditLogVal) : Prop := True

def pyAuditLogDunderLen_post (log : PyAuditLogVal) (r : Nat) : Prop := r = log.inner.length

/-- Rust: `impl PyAuditLog { fn __repr__(&self) -> String }` (`src/python/audit.rs:212`).
    Python `repr()` protocol hook; formats as
    `"PyAuditLog(len=<n>, chain_valid=<bool>)"`. -/
opaque pyAuditLogDunderRepr (log : PyAuditLogVal) : String

def pyAuditLogDunderRepr_pre (_log : PyAuditLogVal) : Prop := True

def pyAuditLogDunderRepr_post (_log : PyAuditLogVal) (r : String) : Prop :=
  r.length > 0

-- ── `src/python/gate.rs::PyLuxGate` impl block ────────────────────────────

/-- Rust: `impl PyLuxGate { pub fn new(authority_threshold: f64, add_agent_threshold: f64, max_agents: usize) -> PyResult<Self> }`
    (`src/python/gate.rs:102`).  Fail-closed validation constructor: both
    thresholds must lie in `[0.0, 1.0]` and `add_agent_threshold` must be
    `>= authority_threshold`; any violation returns `PyValueError` rather
    than constructing a gate. Thresholds are modelled as `Nat`-scaled
    surrogates (e.g. parts-per-thousand) since this spec layer does not
    model floating point; the ordering/bounds properties below are stated
    over the abstract `Nat` representation and are intended to mirror the
    real `[0.0, 1.0]` bound and `>=` ordering on the original `f64`s. -/
opaque pyLuxGateNew (authorityThreshold addAgentThreshold maxAgents : Nat) : PyValueResult PyLuxGateVal

def pyLuxGateNew_pre (_authorityThreshold _addAgentThreshold _maxAgents : Nat) : Prop := True

def pyLuxGateNew_post
    (authorityThreshold addAgentThreshold maxAgents : Nat) (r : PyValueResult PyLuxGateVal) : Prop :=
  (addAgentThreshold < authorityThreshold → ∃ e, r = .error e) ∧
  (addAgentThreshold ≥ authorityThreshold →
    ∃ g, r = .ok g ∧ g.authorityThreshold = authorityThreshold ∧
         g.addAgentThreshold = addAgentThreshold ∧ g.maxAgents = maxAgents)

/-- Rust: `impl PyLuxGate { pub fn authorize_ce(&self, py: Python<'_>, event_type: &str, participants: Vec<String>, authority_scores: HashMap<String, f64>, graph_size: usize) -> PyResult<Py<PyDict>> }`
    (`src/python/gate.rs:151`).  Pure wrapper: delegates the actual
    authorization decision to the private `check` helper (separately
    specified as `pyLuxGateCheck` below) and packages the result into a
    `PyDict`; the receiver is not mutated.

    REFINEMENT_GAP: src/python/gate.rs:151 — builds a PyDict via FFI from a
    pure-Rust CheckResult; the dict construction step (not the underlying
    `check` logic, which is separately specified) is FFI-boundary code. -/
opaque pyLuxGateAuthorizeCe
    (gate : PyLuxGateVal) (py : PyGilVal) (eventType : String) (participants : List String)
    (authorityScores : List (String × Nat)) (graphSize : Nat) : PyValueResult PyDictVal

def pyLuxGateAuthorizeCe_pre
    (_gate : PyLuxGateVal) (_py : PyGilVal) (_eventType : String) (_participants : List String)
    (_authorityScores : List (String × Nat)) (_graphSize : Nat) : Prop := True

/-- Best-effort: only fails (returns `.error`) on PyDict construction
    failure (out-of-memory), which is not characterized further; the
    authorization decision itself never produces an `Err` (see
    `pyLuxGateCheck_post`, which always returns a `CheckResultVal`, never an
    error). -/
def pyLuxGateAuthorizeCe_post
    (_gate : PyLuxGateVal) (_py : PyGilVal) (_eventType : String) (_participants : List String)
    (_authorityScores : List (String × Nat)) (_graphSize : Nat) (_r : PyValueResult PyDictVal) : Prop :=
  True

/-- Rust: `impl PyLuxGate { pub fn config(&self, py: Python<'_>) -> PyResult<Py<PyDict>> }`
    (`src/python/gate.rs:173`).  Exposes `authority_threshold`,
    `add_agent_threshold`, `max_agents` as a dict for observability; pure
    accessor, no mutation.

    REFINEMENT_GAP: src/python/gate.rs:173 — builds a PyDict via FFI to
    expose configuration; dict construction is FFI-boundary code, not pure
    logic. -/
opaque pyLuxGateConfig (gate : PyLuxGateVal) (py : PyGilVal) : PyValueResult PyDictVal

def pyLuxGateConfig_pre (_gate : PyLuxGateVal) (_py : PyGilVal) : Prop := True

def pyLuxGateConfig_post (_gate : PyLuxGateVal) (_py : PyGilVal) (_r : PyValueResult PyDictVal) : Prop :=
  True

-- ── `src/python/gate.rs::PyLuxGate` private `check` helper ───────────────

/-- Rust: `impl PyLuxGate { fn check(&self, event_type: &str, participants: &[String], authority_scores: &HashMap<String, f64>, graph_size: usize) -> CheckResult }`
    (`src/python/gate.rs:191`, private helper).  The core authorization
    decision function: pure, total, never panics, no I/O. Implements I1
    (unknown event type / no participants → deny), I2 (proposer must appear
    in `authority_scores`; standard/elevated authority thresholds), and I4
    (`add_agent` blocked at `graph_size >= max_agents`) in a fixed
    precedence order (checked exactly in the order listed in `_post`
    below). Always returns a `CheckResultVal`; never raises. -/
opaque pyLuxGateCheck
    (gate : PyLuxGateVal) (eventType : String) (participants : List String)
    (authorityScores : List (String × Nat)) (graphSize : Nat) : CheckResultVal

def pyLuxGateCheck_pre
    (_gate : PyLuxGateVal) (_eventType : String) (_participants : List String)
    (_authorityScores : List (String × Nat)) (_graphSize : Nat) : Prop := True

/-- Precedence order, each returning immediately on failure (fail-closed,
    I1/I2/I4): (1) unknown `eventType` → deny, reason "unknown event type",
    class `some "halt"`; (2) empty `participants` → deny, "no participants
    in CE"; (3) `participants.head` not a key of `authorityScores` → deny,
    "proposer not in authority scores"; (4) `eventType = "add_agent"` and
    `graphSize ≥ gate.maxAgents` → deny, "topology bound exceeded"; (5)
    `eventType = "add_agent"` and proposer authority `<
    gate.addAgentThreshold` → deny, "add_agent requires elevated
    authority"; (6) proposer authority `< gate.authorityThreshold` → deny,
    "insufficient authority"; (7) otherwise → approve, "authorized",
    `denialClass = none`. Every denial path sets `denialClass = some
    "halt"`; the approval path sets it to `none`. -/
def pyLuxGateCheck_post
    (gate : PyLuxGateVal) (eventType : String) (participants : List String)
    (authorityScores : List (String × Nat)) (graphSize : Nat) (r : CheckResultVal) : Prop :=
  let knownEvents := ["add_edge", "remove_edge", "add_agent", "remove_agent",
                       "update_capabilities", "execute_task", "decompose_goal", "delegate"]
  (eventType ∉ knownEvents → r.approved = false ∧ r.reason = "unknown event type" ∧ r.denialClass = some "halt") ∧
  (eventType ∈ knownEvents → participants = [] →
    r.approved = false ∧ r.reason = "no participants in CE" ∧ r.denialClass = some "halt") ∧
  (r.approved = true → r.reason = "authorized" ∧ r.denialClass = none) ∧
  (r.approved = false → r.denialClass = some "halt") ∧
  (r.approved = true → eventType ∈ knownEvents ∧ participants ≠ [] ∧
    ∃ proposer score, participants.head? = some proposer ∧
      (authorityScores.find? (fun kv => kv.1 = proposer)) = some (proposer, score))

-- ── `src/python/policy.rs` free functions ─────────────────────────────────

/-- Rust: `fn str_to_static_approved(s: &str) -> Option<&'static str>` (`src/python/policy.rs:61`).
    Looks `s` up in the compile-time `KNOWN_APPROVED` table; `none` if absent. -/
opaque strToStaticApproved (s : String) : Option String

def strToStaticApproved_pre (_s : String) : Prop := True

def strToStaticApproved_post (s : String) (r : Option String) : Prop :=
  let known := ["years_experience", "education_level", "technical_skills",
                "communication_score", "problem_solving", "fit_score"]
  (s ∈ known → r = some s) ∧ (s ∉ known → r = none)

/-- Rust: `fn str_to_static_blocked(s: &str) -> Option<&'static str>` (`src/python/policy.rs:65`).
    Looks `s` up in the compile-time `KNOWN_BLOCKED_SUBSTRINGS` table;
    `none` if absent. -/
opaque strToStaticBlocked (s : String) : Option String

def strToStaticBlocked_pre (_s : String) : Prop := True

def strToStaticBlocked_post (s : String) (r : Option String) : Prop :=
  let known := ["age", "gender", "race", "ethnicity", "sex"]
  (s ∈ known → r = some s) ∧ (s ∉ known → r = none)

-- ── `src/python/policy.rs::PyPolicyGate` impl block ───────────────────────

/-- Rust: `impl PyPolicyGate { pub fn new(approved_features: Vec<String>, blocked_attrs: Vec<String>) -> PyResult<Self> }`
    (`src/python/policy.rs:112`).  Fail-closed validation constructor: every
    string in `approved_features` must be in `KNOWN_APPROVED` and every
    string in `blocked_attrs` must be in `KNOWN_BLOCKED_SUBSTRINGS`; any
    unknown string, or either list exceeding `MAX_GATE_FEATURES` (16),
    rejects construction with `PyValueError`. -/
opaque pyPolicyGateNew (approvedFeatures blockedAttrs : List String) : PyValueResult PyPolicyGateVal

def pyPolicyGateNew_pre (_approvedFeatures _blockedAttrs : List String) : Prop := True

def pyPolicyGateNew_post
    (approvedFeatures blockedAttrs : List String) (r : PyValueResult PyPolicyGateVal) : Prop :=
  let knownApproved := ["years_experience", "education_level", "technical_skills",
                         "communication_score", "problem_solving", "fit_score"]
  let knownBlocked := ["age", "gender", "race", "ethnicity", "sex"]
  ((∃ f ∈ approvedFeatures, f ∉ knownApproved) ∨
   (∃ a ∈ blockedAttrs, a ∉ knownBlocked) ∨
   approvedFeatures.length > 16 ∨ blockedAttrs.length > 16 →
    ∃ e, r = .error e) ∧
  ((∀ f ∈ approvedFeatures, f ∈ knownApproved) ∧ (∀ a ∈ blockedAttrs, a ∈ knownBlocked) ∧
   approvedFeatures.length ≤ 16 ∧ blockedAttrs.length ≤ 16 →
    ∃ g, r = .ok g ∧ g.approved = approvedFeatures ∧ g.blocked = blockedAttrs)

/-- Rust: `impl PyPolicyGate { pub fn check(&self, feature_names: Vec<String>) -> PyResult<PyObject> }`
    (`src/python/policy.rs:163`).  Applies three invariants in fixed order
    over `feature_names`: (1) exact match against `PROTECTED_EXACT` ⊆
    `{"age","gender","race"}` → deny "protected attribute in feature
    vector"; (2) case-insensitive substring scan against `self.blocked` →
    deny "aliased protected attribute in feature vector"; (3) membership
    check against `self.approved` → deny "unapproved feature in feature
    vector"; if all three pass → allow "all approved features; no protected
    attributes". Every denial sets `denial_class = "halt"`; allow sets it to
    Python `None`. Acquires the GIL internally (`Python::with_gil`).

    REFINEMENT_GAP: src/python/policy.rs:163 — acquires the Python GIL
    (Python::with_gil) and builds a PyDict via FFI; the GIL acquisition and
    dict construction are not modelled. -/
opaque pyPolicyGateCheck (gate : PyPolicyGateVal) (featureNames : List String) : PyValueResult PyDictVal

def pyPolicyGateCheck_pre (_gate : PyPolicyGateVal) (_featureNames : List String) : Prop := True

/-- Best-effort: only fails (returns `.error`) on PyDict construction
    failure; the gate decision itself (allow vs. deny, and which of the
    four reasons) is always computable and never raises. The precise
    allow/deny outcome per the three ordered invariants is not re-derived
    here in full (it mirrors `pyLuxGateCheck_post`'s style but is omitted
    for brevity since the dict-shaped result is opaque); see the Rust
    doc comment on `PyPolicyGate::check` for the exact precedence. -/
def pyPolicyGateCheck_post
    (_gate : PyPolicyGateVal) (_featureNames : List String) (_r : PyValueResult PyDictVal) : Prop :=
  True

/-- Rust: `impl PyPolicyGate { fn __repr__(&self) -> String }` (`src/python/policy.rs:206`).
    Python `repr()` protocol hook; formats as
    `"PyPolicyGate(approved=<list>, blocked=<list>)"`. -/
opaque pyPolicyGateDunderRepr (gate : PyPolicyGateVal) : String

def pyPolicyGateDunderRepr_pre (_gate : PyPolicyGateVal) : Prop := True

def pyPolicyGateDunderRepr_post (_gate : PyPolicyGateVal) (r : String) : Prop :=
  r.length > 0

end FunctionSpecs
