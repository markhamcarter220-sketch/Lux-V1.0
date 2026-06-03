//! Audit subsystem — append-only, tamper-evident event log.
//!
//! Every security-relevant operation in the kernel produces an `AuditEvent`.
//! Events are chained via SHA-256 so that any post-hoc mutation is detectable.
//!
//! See `log::AuditLog` for the primary API and `event::AuditEvent` for the
//! event record format.

pub mod event;
pub mod log;

pub use event::{AuditEvent, EventKind, Outcome};
pub use log::AuditLog;
