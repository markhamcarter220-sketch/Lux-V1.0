//! Audit subsystem — append-only, tamper-evident event log.
//!
//! Every security-relevant operation in the kernel produces an `AuditEvent`.
//! Events are chained via SHA-256 so that any post-hoc mutation is detectable.
//!
//! See `log::AuditLog` for the primary API and `event::AuditEvent` for the
//! event record format.

pub mod event;
pub mod log;

pub use crate::error::DenialClass;
pub use event::{AuditEvent, EventKind, Outcome};
pub use log::AuditLog;

/// Sentinel timestamp for audit events emitted without a caller-supplied clock.
///
/// The kernel is `no_std` and does not own a monotonic timer.  Callers of the
/// three enforcement gates ([`Policy::check`], [`OperationalGraph::traverse`],
/// [`QuotaEnforcer::deduct`]) do not currently thread a timestamp into those
/// calls.  Events marked `UNTIMED` are correctly sequenced (via `seq`) and
/// hash-chained, but carry no wall-time or monotonic dimension.
///
/// Replacing `UNTIMED` with a real counter requires adding a `timestamp: u64`
/// parameter to every gate signature and all their callers (Python, WASM,
/// tests, boot path).  That is a coordinated API-change design, not a one-line
/// fix — track it as a dedicated work item.
pub const UNTIMED: u64 = 0;
