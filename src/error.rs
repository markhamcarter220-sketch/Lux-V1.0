//! Kernel-wide error taxonomy.
//!
//! All errors are non-recoverable from the caller's perspective — the kernel
//! never silently degrades.  The sentinel value for "unknown / catch-all" is
//! intentionally absent: every rejection must carry a precise cause.

use thiserror::Error;

/// Canonical result type for all kernel operations.
pub type Result<T> = core::result::Result<T, Error>;

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
