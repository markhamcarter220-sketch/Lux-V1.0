//! Audit event types.

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
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Classification of the audited operation.
    pub kind:      EventKind,
    /// Raw node ID of the actor that initiated the operation.
    pub actor:     u32,
    /// Monotonic sequence number (incremented per event, resets to 0 at startup).
    pub seq:       u64,
    /// Whether the operation was permitted or denied.
    pub outcome:   Outcome,
    /// SHA-256 of `(prev_hash || kind || actor || seq || outcome)`.
    /// For the genesis event, `prev_hash` is `[0u8; 32]`.
    pub hash:      [u8; 32],
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
}
