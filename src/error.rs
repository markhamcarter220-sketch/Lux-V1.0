//! Kernel-wide error taxonomy.
//!
//! All errors are non-recoverable from the caller's perspective — the kernel
//! never silently degrades.  The sentinel value for "unknown / catch-all" is
//! intentionally absent: every rejection must carry a precise cause.
//!
//! ## HALT vs. FAILURE
//!
//! Every denial is classified as one of two kinds via [`Error::denial_class`]:
//!
//! - **[`DenialClass::Halt`]** — the operation was stopped *before* execution
//!   because authorization was never established.  No kernel state was modified.
//!   Examples: missing or expired token, wrong generation, revoked nonce,
//!   undeclared topology edge, boot manifest rejection.
//!
//! - **[`DenialClass::Failure`]** — authorization was checked and passed, but
//!   the operation could not complete during execution.  The failure occurred
//!   after the authorization gate.  Examples: ledger underflow on resource
//!   deduction, scheduler invariant broken mid-scheduling.
//!
//! This distinction is load-bearing for the audit log: HALT events indicate
//! that a caller lacked standing; FAILURE events indicate an execution-time
//! invariant was violated despite valid standing.

use thiserror::Error;

/// Canonical result type for all kernel operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Classification of a denial — indicates *when* in the call sequence the
/// denial was generated.
///
/// Used by the audit log to distinguish pre-authorization stops (HALT) from
/// post-authorization execution failures (FAILURE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialClass {
    /// Operation stopped before execution; authorization was never established.
    ///
    /// Covers: invalid/expired tokens, revoked nonces, undeclared topology
    /// edges, boot manifest failures, undefined state transitions.
    Halt,

    /// Authorization checked and passed; operation failed during execution.
    ///
    /// Covers: resource ledger underflow, scheduler invariant violations.
    Failure,
}

/// Every path that returns `Err` **denies** the requested operation.
/// Adding a variant here requires a corresponding entry in `docs/SECURITY.md`.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The caller's capability token is absent, expired, or malformed.
    #[error("capability denied: {reason}")]
    CapabilityDenied {
        /// Human-readable explanation of why the token was rejected.
        reason: &'static str,
    },

    /// The operation would exceed the caller's allocated resource quota.
    #[error("quota exceeded: {resource}")]
    QuotaExceeded {
        /// The resource class that was exhausted (e.g. `"compute"`, `"memory"`).
        resource: &'static str,
    },

    /// The requested topology edge is not declared in the boot manifest.
    #[error("topology violation: edge ({src}, {dst}) is not permitted")]
    TopologyViolation {
        /// Source node ID.
        src: u32,
        /// Destination node ID.
        dst: u32,
    },

    /// The boot manifest failed structural or cryptographic validation.
    #[error("manifest invalid: {detail}")]
    ManifestInvalid {
        /// Specific validation failure reason.
        detail: &'static str,
    },

    /// A scheduler invariant was broken (e.g. priority inversion detected).
    #[error("scheduler invariant violated: {detail}")]
    SchedulerInvariant {
        /// Description of the invariant that was violated.
        detail: &'static str,
    },

    /// Internal state machine reached an undefined transition.
    /// Maps directly to the fail-closed default: deny and halt sub-system.
    #[error("undefined state: {context}")]
    UndefinedState {
        /// The context in which the undefined state was encountered.
        context: &'static str,
    },
}

impl Error {
    /// Returns a static string describing the denial reason, suitable for
    /// embedding in an audit event.
    ///
    /// For `TopologyViolation`, the src/dst pair is not included because audit
    /// events accept only `&'static str`; the edge coordinates are recorded in
    /// the structured error returned to the caller.
    #[must_use]
    pub fn denial_reason_str(&self) -> &'static str {
        match self {
            Self::CapabilityDenied { reason }   => reason,
            Self::QuotaExceeded { resource }     => resource,
            Self::TopologyViolation { .. }        => "edge not in boot manifest",
            Self::ManifestInvalid { detail }      => detail,
            Self::SchedulerInvariant { detail }   => detail,
            Self::UndefinedState { context }      => context,
        }
    }

    /// Returns the [`DenialClass`] for this error.
    ///
    /// Every variant is assigned to exactly one class — no ambiguous variants
    /// exist.  See the module-level documentation for the HALT / FAILURE
    /// semantics.
    #[must_use]
    pub fn denial_class(&self) -> DenialClass {
        match self {
            // ── HALT: authorization never established ─────────────────────────
            //
            // CapabilityDenied: token is absent, expired, revoked, replayed, or
            //   the nonce window is exhausted.  No execution was attempted.
            Self::CapabilityDenied { .. } => DenialClass::Halt,

            // TopologyViolation: the requested edge is not declared in the boot
            //   manifest, so no authorization path for this traversal exists.
            //   Also covers BootingGraph configuration errors (pre-operational).
            Self::TopologyViolation { .. } => DenialClass::Halt,

            // ManifestInvalid: boot-time validation failed before any
            //   operational state was established.
            Self::ManifestInvalid { .. } => DenialClass::Halt,

            // UndefinedState: the state machine reached an unrecognised
            //   transition.  The fail-closed contract requires halting the
            //   sub-system rather than proceeding in an unknown state.
            Self::UndefinedState { .. } => DenialClass::Halt,

            // ── FAILURE: authorization passed, execution failed ───────────────
            //
            // QuotaExceeded: the caller held valid rights and the Policy gate
            //   passed, but the resource ledger could not satisfy the requested
            //   deduction.  Execution was attempted; atomicity holds (ledger
            //   unchanged on failure).
            Self::QuotaExceeded { .. } => DenialClass::Failure,

            // SchedulerInvariant: a correctness invariant (e.g. priority
            //   inversion) was detected during scheduling execution, after the
            //   caller's authority was confirmed.
            Self::SchedulerInvariant { .. } => DenialClass::Failure,
        }
    }
}
