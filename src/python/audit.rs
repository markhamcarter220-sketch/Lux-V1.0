//! PyAuditLog — Python binding for the kernel's append-only, hash-chained audit log.
//!
//! # EDGE B resolution: &'static str denial reasons
//!
//! The kernel's `AuditLog::append` requires `denial_reason: Option<&'static str>`.
//! Python strings are heap-allocated.  Resolution: `KNOWN_REASONS` is a
//! compile-time table of static string literals.  Incoming Python strings are
//! matched against this table; matches return the corresponding `&'static str`.
//! Unknown strings fall back to the static literal `"policy violation"`.
//!
//! The `PyPolicyGate` in `super::policy` emits exactly these strings as denial
//! reasons, so the round-trip (gate → audit) is lossless for the hiring pipeline.
//!
//! # EDGE G resolution: AuditLog is !Send
//!
//! `AuditLog` holds `PhantomData<*mut ()>`, making it `!Send + !Sync`.  PyO3
//! requires `T: Send` for `#[pyclass]` unless `unsendable` is set.
//! `#[pyclass(unsendable)]` tells PyO3 that this object may only be used from
//! the Python thread that created it; attempting cross-thread use raises
//! `RuntimeError` at the Python layer.

use pyo3::prelude::*;

use crate::{
    audit::{AuditLog, EventKind},
    error::DenialClass,
};

/// Compile-time table of all denial reason strings the binding accepts.
/// Any Python string not in this table maps to the last entry ("policy violation").
static KNOWN_REASONS: &[&str] = &[
    "protected attribute in feature vector",
    "aliased protected attribute in feature vector",
    "unapproved feature in feature vector",
    "policy violation",
];

/// Map a Python denial-reason string to its `&'static str` counterpart.
/// Unknown strings silently fall back to `"policy violation"`.
fn map_denial_reason(s: &str) -> &'static str {
    KNOWN_REASONS
        .iter()
        .copied()
        .find(|&k| k == s)
        .unwrap_or("policy violation")
}

fn parse_kind(s: &str) -> PyResult<EventKind> {
    match s {
        "hiring_decision"   => Ok(EventKind::HiringDecision),
        "policy_gate_check" => Ok(EventKind::PolicyGateCheck),
        "capability_check"  => Ok(EventKind::CapabilityCheck),
        "cap_revoked"       => Ok(EventKind::CapabilityRevoked),
        "resource_deduct"   => Ok(EventKind::ResourceDeduction),
        "topo_traverse"     => Ok(EventKind::TopologyTraverse),
        "topo_change"       => Ok(EventKind::TopologyChange),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown EventKind {:?}; accepted: hiring_decision, policy_gate_check, \
             capability_check, cap_revoked, resource_deduct, topo_traverse, topo_change",
            other
        ))),
    }
}

fn parse_denial_class(s: &str) -> PyResult<DenialClass> {
    match s {
        "halt"    => Ok(DenialClass::Halt),
        "failure" => Ok(DenialClass::Failure),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown DenialClass {:?}; use \"halt\" or \"failure\"",
            other
        ))),
    }
}

/// Python-accessible wrapper around the Lux kernel's `AuditLog`.
///
/// The log is SHA-256 hash-chained (tamper-evident) and append-only.
/// Capacity is 512 events (matches `MAX_AUDIT_EVENTS` in `src/types.rs`).
///
/// # Thread safety
///
/// Marked `unsendable` because `AuditLog` is structurally `!Send`.
/// Use this object only from the Python thread that created it.
#[pyclass(unsendable, name = "PyAuditLog")]
#[derive(Debug)]
pub struct PyAuditLog {
    inner: AuditLog,
}

#[pymethods]
impl PyAuditLog {
    #[new]
    pub fn new() -> Self {
        Self { inner: AuditLog::new() }
    }

    /// Append one event to the audit log.
    ///
    /// Parameters
    /// ----------
    /// kind : str
    ///     One of: "hiring_decision", "policy_gate_check", "capability_check",
    ///     "cap_revoked", "resource_deduct", "topo_traverse", "topo_change".
    /// actor : int
    ///     Node / candidate ID (u32 range).
    /// timestamp : int
    ///     Caller-supplied monotonic counter in nanoseconds (e.g. time.time_ns()).
    ///     The kernel does not own a clock; callers supply this value.
    /// denial_class : str | None
    ///     "halt" (authorisation never established) or "failure" (execution
    ///     failed after authorisation passed).  None for permitted events.
    /// denial_reason : str | None
    ///     One of the static denial reason strings (EDGE B resolution), or None.
    ///     Unknown strings silently fall back to "policy violation".
    ///
    /// Returns
    /// -------
    /// bool
    ///     True on success.  False if the log is at capacity (512 events) — the
    ///     event is NOT recorded (fail-closed: no silent overwrites).
    pub fn append(
        &mut self,
        kind:          &str,
        actor:         u64,
        timestamp:     u64,
        denial_class:  Option<&str>,
        denial_reason: Option<&str>,
    ) -> PyResult<bool> {
        let kind  = parse_kind(kind)?;
        let actor = actor as u32; // caller-responsible: candidate_id always fits u32

        let denial = match denial_class {
            None => None,
            Some(cls_str) => {
                let cls    = parse_denial_class(cls_str)?;
                let reason = denial_reason
                    .map(map_denial_reason)
                    .unwrap_or("policy violation");
                Some((cls, reason))
            }
        };

        Ok(self.inner.append(kind, actor, timestamp, denial))
    }

    /// Recompute every hash in the chain from genesis.
    ///
    /// Returns True iff every event's hash matches the expected value
    /// recomputed from its predecessor.  Any single-bit mutation anywhere
    /// in the event log or in the hash fields is detected.
    pub fn verify_chain(&self) -> bool {
        self.inner.verify_chain()
    }

    /// Export the audit log as a JSON string (kernel canonical format).
    ///
    /// Format: JSON array, one object per event.  Each object has fields:
    ///   seq, kind, actor, ts, ok, class, reason, hash (64-char lowercase hex).
    ///
    /// The "hash" field is the SHA-256 of this event's chain input.
    pub fn export_json(&self) -> PyResult<String> {
        let mut buf = String::new();
        self.inner
            .export_json(&mut buf)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
                format!("export_json failed: {:?}", e),
            ))?;
        Ok(buf)
    }

    /// Number of events currently in the log.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if the log contains no events.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// 64-char hex string of the most recent event's hash.
    /// Returns 64 zeros for an empty log.
    pub fn head_hash(&self) -> String {
        self.inner
            .head_hash()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __repr__(&self) -> String {
        format!("PyAuditLog(len={}, chain_valid={})", self.inner.len(), self.inner.verify_chain())
    }
}
