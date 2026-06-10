//! `PyLuxGate` — Python binding for CE authorization in the Emergo integration.
//!
//! Exposes a stateless, fail-closed authorization gate for Coordination Events.
//! Called by Emergo's `RealLuxBridge.authorize_ce()` to enforce the four Lux
//! invariants (Fail-Closed, Capability-Gated, Topology-Bounded, Accountable)
//! on CE proposals before they enter the kernel loop.
//!
//! # Usage (Python)
//!
//! ```python
//! from lux_kernel import PyLuxGate
//!
//! gate = PyLuxGate(
//!     authority_threshold=0.3,
//!     add_agent_threshold=0.6,
//!     max_agents=20,
//! )
//! result = gate.authorize_ce(
//!     event_type="add_edge",
//!     participants=["agent_0", "agent_1"],
//!     authority_scores={"agent_0": 0.6, "agent_1": 0.4},
//!     graph_size=5,
//! )
//! # result == {"approved": True, "reason": "authorized", "denial_class": None}
//! ```
//!
//! # Invariants enforced
//!
//! - **Fail-Closed (I1)**: default deny; unknown event types → deny.
//! - **Capability-Gated (I2)**: proposer authority must meet threshold.
//! - **Topology-Bounded (I4)**: `add_agent` blocked at capacity.
//! - **Accountable (I3)**: `denial_class` always set on denial.
//!
//! # Static strings (EDGE B pattern)
//!
//! All denial reasons are `&'static str` literals — no heap allocation at
//! check time. `denial_class` is either `None` (allowed) or `"halt"` (denied).

use pyo3::prelude::*;
use pyo3::types::PyDict;

// ── Known event types ────────────────────────────────────────────────────────

/// Compile-time table of all valid Emergo CE event types.
/// Unknown strings are denied (Fail-Closed invariant).
static KNOWN_EVENT_TYPES: &[&str] = &[
    "add_edge",
    "remove_edge",
    "add_agent",
    "remove_agent",
    "update_capabilities",
    "execute_task",
    "decompose_goal",
    "delegate",
];

// ── Static denial-reason strings (EDGE B pattern) ────────────────────────────

const REASON_AUTHORIZED: &str = "authorized";
const REASON_NO_PARTICIPANTS: &str = "no participants in CE";
const REASON_UNKNOWN_EVENT: &str = "unknown event type";
const REASON_INSUFFICIENT_AUTHORITY: &str = "insufficient authority";
const REASON_ADD_AGENT_AUTHORITY: &str = "add_agent requires elevated authority";
const REASON_TOPOLOGY_BOUND: &str = "topology bound exceeded";
const REASON_PROPOSER_UNKNOWN: &str = "proposer not in authority scores";

// ── PyLuxGate ────────────────────────────────────────────────────────────────

/// Stateless CE authorization gate. Enforces four Lux invariants.
///
/// Configuration is fixed at construction time. All check logic is a pure
/// function of the inputs — no state mutates on `authorize_ce`.
#[pyclass(name = "PyLuxGate")]
#[derive(Debug)]
pub struct PyLuxGate {
    /// Minimum proposer authority for standard CE types.
    authority_threshold: f64,
    /// Elevated authority threshold for `add_agent` (higher blast radius).
    add_agent_threshold: f64,
    /// Maximum number of agents allowed in the topology (INV-Topology-Bounded).
    max_agents: usize,
}

#[pymethods]
impl PyLuxGate {
    /// Construct a `PyLuxGate` with fixed configuration.
    ///
    /// Args:
    ///     `authority_threshold`: Minimum proposer authority for standard CEs.
    ///                            Default 0.3. Must be in \[0.0, 1.0\].
    ///     `add_agent_threshold`: Elevated threshold for `add_agent` events.
    ///                            Default 0.6. Must be >= `authority_threshold`.
    ///     `max_agents`:          Maximum agents permitted in the topology.
    ///                            Default 20.
    ///
    /// # Errors
    ///
    /// Returns `PyValueError` if thresholds are out of \[0.0, 1.0\] or if
    /// `add_agent_threshold` < `authority_threshold`.
    #[new]
    #[pyo3(signature = (authority_threshold=0.3, add_agent_threshold=0.6, max_agents=20))]
    pub fn new(
        authority_threshold: f64,
        add_agent_threshold: f64,
        max_agents: usize,
    ) -> PyResult<Self> {
        if !(0.0..=1.0).contains(&authority_threshold) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "authority_threshold must be in [0.0, 1.0]",
            ));
        }
        if !(0.0..=1.0).contains(&add_agent_threshold) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "add_agent_threshold must be in [0.0, 1.0]",
            ));
        }
        if add_agent_threshold < authority_threshold {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "add_agent_threshold must be >= authority_threshold",
            ));
        }
        Ok(Self {
            authority_threshold,
            add_agent_threshold,
            max_agents,
        })
    }

    /// Authorize a Coordination Event proposal.
    ///
    /// Args:
    ///     `event_type`:        CE event type string. Must be a known type.
    ///     participants:        Ordered list of agent IDs. `participants[0]`
    ///                          is the proposer.
    ///     `authority_scores`:  Dict mapping `agent_id` → authority score.
    ///     `graph_size`:        Current number of agents in the graph.
    ///
    /// Returns:
    ///     dict with keys:
    ///         `approved`      : bool
    ///         `reason`        : str  — human-readable authorization result
    ///         `denial_class`  : str | None — `"halt"` on denial, `None` on approval
    ///
    /// # Errors
    ///
    /// Only errors if `PyDict` construction fails (out-of-memory), which is
    /// a fatal Python interpreter error. All authorization logic is fail-closed
    /// and returns `approved=False` rather than raising.
    #[pyo3(signature = (event_type, participants, authority_scores, graph_size))]
    #[allow(clippy::needless_pass_by_value)]
    pub fn authorize_ce(
        &self,
        py: Python<'_>,
        event_type: &str,
        participants: Vec<String>,
        authority_scores: std::collections::HashMap<String, f64>,
        graph_size: usize,
    ) -> PyResult<Py<PyDict>> {
        let result = self.check(event_type, &participants, &authority_scores, graph_size);
        let dict = PyDict::new(py);
        dict.set_item("approved", result.approved)?;
        dict.set_item("reason", result.reason)?;
        dict.set_item("denial_class", result.denial_class)?;
        Ok(dict.into())
    }

    /// Return configuration as a dict for observability/logging.
    ///
    /// # Errors
    ///
    /// Only errors if `PyDict` construction fails (out-of-memory), which is
    /// a fatal Python interpreter error.
    pub fn config(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("authority_threshold", self.authority_threshold)?;
        dict.set_item("add_agent_threshold", self.add_agent_threshold)?;
        dict.set_item("max_agents", self.max_agents)?;
        Ok(dict.into())
    }
}

// ── Internal check logic ─────────────────────────────────────────────────────

struct CheckResult {
    approved: bool,
    reason: &'static str,
    denial_class: Option<&'static str>,
}

impl PyLuxGate {
    fn check(
        &self,
        event_type: &str,
        participants: &[String],
        authority_scores: &std::collections::HashMap<String, f64>,
        graph_size: usize,
    ) -> CheckResult {
        // I1 — Fail-Closed: unknown event type → deny
        if !KNOWN_EVENT_TYPES.contains(&event_type) {
            return CheckResult {
                approved: false,
                reason: REASON_UNKNOWN_EVENT,
                denial_class: Some("halt"),
            };
        }

        // I1 — Fail-Closed: no participants → deny
        if participants.is_empty() {
            return CheckResult {
                approved: false,
                reason: REASON_NO_PARTICIPANTS,
                denial_class: Some("halt"),
            };
        }

        let proposer = &participants[0];

        // I2 — Capability-Gated: proposer must be in authority_scores
        let Some(&proposer_authority) = authority_scores.get(proposer) else {
            return CheckResult {
                approved: false,
                reason: REASON_PROPOSER_UNKNOWN,
                denial_class: Some("halt"),
            };
        };

        // I4 — Topology-Bounded: add_agent blocked at capacity
        if event_type == "add_agent" && graph_size >= self.max_agents {
            return CheckResult {
                approved: false,
                reason: REASON_TOPOLOGY_BOUND,
                denial_class: Some("halt"),
            };
        }

        // I2 — Capability-Gated: add_agent requires elevated authority
        if event_type == "add_agent" && proposer_authority < self.add_agent_threshold {
            return CheckResult {
                approved: false,
                reason: REASON_ADD_AGENT_AUTHORITY,
                denial_class: Some("halt"),
            };
        }

        // I2 — Capability-Gated: standard authority threshold for all other types
        if proposer_authority < self.authority_threshold {
            return CheckResult {
                approved: false,
                reason: REASON_INSUFFICIENT_AUTHORITY,
                denial_class: Some("halt"),
            };
        }

        // All checks passed
        CheckResult {
            approved: true,
            reason: REASON_AUTHORIZED,
            denial_class: None,
        }
    }
}
