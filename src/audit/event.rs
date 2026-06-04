//! Audit event types.

use crate::error::DenialClass;

/// Classification of the operation that generated the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    /// A capability was presented and checked by `Policy::check`.
    CapabilityCheck   = 0,
    /// A capability token was explicitly revoked.
    CapabilityRevoked = 1,
    /// A resource deduction was attempted via the metabolism ledger.
    ResourceDeduction = 2,
    /// A topology edge traversal was attempted.
    TopologyTraverse  = 3,
}

/// Result of the audited operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    /// The operation was permitted.
    Permitted = 0,
    /// The operation was denied.
    Denied    = 1,
}

/// A single immutable entry in the audit log.
///
/// # Fields
///
/// - `timestamp` — caller-provided monotonic counter (hardware tick or
///   logical clock).  The kernel does not own a wall clock; callers supply
///   this value.
/// - `denial_class` — [`DenialClass::Halt`] or [`DenialClass::Failure`] for
///   denied events; `None` for permitted events.  See `docs/error.rs` for the
///   HALT/FAILURE semantics.
/// - `denial_reason` — the static reason string from the originating
///   [`crate::error::Error`]; `None` for permitted events.
///
/// All fields except `hash` are inputs to the SHA-256 chain.  Mutating any
/// field after insertion is detectable via [`crate::audit::AuditLog::verify_chain`].
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Classification of the audited operation.
    pub kind:          EventKind,
    /// Raw node ID of the actor that initiated the operation.
    pub actor:         u32,
    /// Monotonic sequence number (incremented per event, resets to 0 at startup).
    pub seq:           u64,
    /// Caller-provided monotonic timestamp (hardware tick, not wall time).
    pub timestamp:     u64,
    /// Whether the operation was permitted or denied.
    pub outcome:       Outcome,
    /// HALT or FAILURE classification for denied events; `None` for permitted.
    pub denial_class:  Option<DenialClass>,
    /// Static reason string for denied events; `None` for permitted.
    pub denial_reason: Option<&'static str>,
    /// SHA-256 of the chain input for this event (see `AuditLog` for wire format).
    /// For the genesis event, `prev_hash` is `[0u8; 32]`.
    pub hash:          [u8; 32],
}

impl AuditEvent {
    /// Returns a short string label for the event kind, suitable for JSON export.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self.kind {
            EventKind::CapabilityCheck   => "cap_check",
            EventKind::CapabilityRevoked => "cap_revoked",
            EventKind::ResourceDeduction => "resource_deduct",
            EventKind::TopologyTraverse  => "topo_traverse",
        }
    }

    /// Returns a string label for the denial class, suitable for JSON export.
    /// Returns `None` for permitted events.
    #[must_use]
    pub fn denial_class_str(&self) -> Option<&'static str> {
        match self.denial_class {
            Some(DenialClass::Halt)    => Some("halt"),
            Some(DenialClass::Failure) => Some("failure"),
            None                       => None,
        }
    }
}
