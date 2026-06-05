//! PyPolicyGate — Python binding for the Lux kernel's capability-gated policy gate.
//!
//! # EDGE E+F resolution: dynamic feature names → static strings
//!
//! The kernel uses `&'static str` throughout.  Python strings are heap-allocated.
//! Resolution: `PyPolicyGate::new()` validates each approved/blocked string against
//! compile-time static tables (`KNOWN_APPROVED`, `KNOWN_BLOCKED_SUBSTRINGS`) and
//! returns the corresponding `&'static str`.  Unknown strings raise `PyValueError`
//! at construction time (fail-closed: unknown names are rejected, not ignored).
//! At check time the gate works only with pre-validated `&'static str` values.
//! heapless::Vec capacity is 16; the hiring pipeline needs 6 + 5 = 11.
//!
//! # EDGE B resolution: static denial reasons
//!
//! The four denial-reason strings defined here as `&'static str` literals are
//! exactly the strings accepted by `PyAuditLog`'s `map_denial_reason` lookup.
//! The Python wrapper passes `result["reason"]` directly into `PyAuditLog.append`,
//! completing the lossless round-trip.
//!
//! # Gate logic
//!
//! Mirrors `hiring-audit/policy_gate.py` exactly (same three invariants, same order):
//!   1. Exact match against `PROTECTED_EXACT` — protected attribute in feature vector.
//!   2. Substring scan against `self.blocked` — aliased protected attribute.
//!   3. Membership check against `self.approved` — unapproved feature.
//!
//! All three pass → ALLOW.  Any fail → DENY (denial_class = "halt", I1/I2 enforced).

use heapless::Vec as HVec;
use pyo3::prelude::*;
use pyo3::types::PyDict;

const MAX_GATE_FEATURES: usize = 16;

/// Compile-time table of all valid approved feature names.
static KNOWN_APPROVED: &[&'static str] = &[
    "years_experience",
    "education_level",
    "technical_skills",
    "communication_score",
    "problem_solving",
    "fit_score",
];

/// Compile-time table of all valid blocked-attribute substrings.
static KNOWN_BLOCKED_SUBSTRINGS: &[&'static str] = &[
    "age",
    "gender",
    "race",
    "ethnicity",
    "sex",
];

/// Exact-match protected attribute names (subset of KNOWN_BLOCKED_SUBSTRINGS).
/// Checked first to give the most precise denial reason.
static PROTECTED_EXACT: &[&str] = &["age", "gender", "race"];

// ── Static denial-reason strings (EDGE B) ────────────────────────────────────
// These strings are stored as &'static str.  PyAuditLog.map_denial_reason()
// has a matching entry for each; the round-trip is lossless.

const REASON_PROTECTED_EXACT: &str = "protected attribute in feature vector";
const REASON_PROTECTED_ALIAS: &str = "aliased protected attribute in feature vector";
const REASON_UNAPPROVED:      &str = "unapproved feature in feature vector";
const REASON_ALLOWED:         &str = "all approved features; no protected attributes";

fn str_to_static_approved(s: &str) -> Option<&'static str> {
    KNOWN_APPROVED.iter().copied().find(|&k| k == s)
}

fn str_to_static_blocked(s: &str) -> Option<&'static str> {
    KNOWN_BLOCKED_SUBSTRINGS.iter().copied().find(|&k| k == s)
}

/// Python-accessible policy gate that enforces the Lux capability-gate contract
/// (Invariant I2) for the hiring domain.
///
/// Configuration is fixed at construction time: the approved feature list and
/// blocked-attribute substring list are validated against compile-time tables.
/// Unknown strings are rejected immediately (fail-closed).
///
/// The gate is **stateless** for enforcement purposes; call-count statistics are
/// tracked in the Python wrapper (`hiring-audit/policy_gate.py`).
///
/// Capacity: each list holds up to 16 entries (heapless::Vec).
#[pyclass(name = "PyPolicyGate")]
#[derive(Debug)]
pub struct PyPolicyGate {
    approved: HVec<&'static str, MAX_GATE_FEATURES>,
    blocked:  HVec<&'static str, MAX_GATE_FEATURES>,
}

#[pymethods]
impl PyPolicyGate {
    /// Construct the gate.
    ///
    /// Parameters
    /// ----------
    /// approved_features : list[str]
    ///     Feature names that are permitted in a decision vector.
    ///     Each string must be one of the known approved features
    ///     (see KNOWN_APPROVED).  Unknown strings raise ValueError.
    ///
    /// blocked_attrs : list[str]
    ///     Substrings whose presence in any feature name triggers a denial.
    ///     Each string must be one of the known blocked-attribute substrings
    ///     (see KNOWN_BLOCKED_SUBSTRINGS).  Unknown strings raise ValueError.
    ///
    /// Raises
    /// ------
    /// ValueError
    ///     If any string is unknown, or if either list exceeds 16 entries.
    #[new]
    pub fn new(
        approved_features: Vec<String>,
        blocked_attrs:     Vec<String>,
    ) -> PyResult<Self> {
        let mut approved: HVec<&'static str, MAX_GATE_FEATURES> = HVec::new();
        let mut blocked:  HVec<&'static str, MAX_GATE_FEATURES> = HVec::new();

        for feat in &approved_features {
            let s = str_to_static_approved(feat).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown approved feature {:?}; must be one of {:?}",
                    feat, KNOWN_APPROVED
                ))
            })?;
            approved.push(s).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "approved_features list exceeds capacity (16)",
                )
            })?;
        }

        for attr in &blocked_attrs {
            let s = str_to_static_blocked(attr).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown blocked attribute {:?}; must be one of {:?}",
                    attr, KNOWN_BLOCKED_SUBSTRINGS
                ))
            })?;
            blocked.push(s).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err(
                    "blocked_attrs list exceeds capacity (16)",
                )
            })?;
        }

        Ok(Self { approved, blocked })
    }

    /// Check a list of feature names against the policy gate.
    ///
    /// Mirrors `PolicyGate.check()` in `hiring-audit/policy_gate.py` exactly,
    /// applying the same three invariants in the same order.
    ///
    /// Parameters
    /// ----------
    /// feature_names : list[str]
    ///     The keys of the feature vector (dict keys, not values).
    ///
    /// Returns
    /// -------
    /// dict with keys:
    ///   "allowed"       : bool
    ///   "reason"        : str   (one of the four static reason strings)
    ///   "denial_class"  : str | None  ("halt" on denial; None on allow)
    pub fn check(&self, feature_names: Vec<String>) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let result = PyDict::new_bound(py);

            // Invariant 1: exact protected-attribute match.
            for name in &feature_names {
                if PROTECTED_EXACT.contains(&name.as_str()) {
                    result.set_item("allowed",      false)?;
                    result.set_item("reason",       REASON_PROTECTED_EXACT)?;
                    result.set_item("denial_class", "halt")?;
                    return Ok(result.into());
                }
            }

            // Invariant 2: blocked-substring scan (catches aliased keys).
            for name in &feature_names {
                let lower = name.to_lowercase();
                if self.blocked.iter().any(|&sub| lower.contains(sub)) {
                    result.set_item("allowed",      false)?;
                    result.set_item("reason",       REASON_PROTECTED_ALIAS)?;
                    result.set_item("denial_class", "halt")?;
                    return Ok(result.into());
                }
            }

            // Invariant 3: all features must be in the approved list.
            for name in &feature_names {
                if !self.approved.iter().any(|&a| a == name.as_str()) {
                    result.set_item("allowed",      false)?;
                    result.set_item("reason",       REASON_UNAPPROVED)?;
                    result.set_item("denial_class", "halt")?;
                    return Ok(result.into());
                }
            }

            // All invariants pass → ALLOW.
            result.set_item("allowed",      true)?;
            result.set_item("reason",       REASON_ALLOWED)?;
            result.set_item("denial_class", py.None())?;
            Ok(result.into())
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "PyPolicyGate(approved={:?}, blocked={:?})",
            self.approved.as_slice(),
            self.blocked.as_slice(),
        )
    }
}
