//! Quota enforcer — single-call entry point for resource checks.

use crate::{
    audit::{AuditLog, EventKind},
    error::Error,
    metabolism::ledger::Ledger,
    types::NodeId,
    Result,
};

/// Stateless enforcer that delegates to the ledger.
#[derive(Debug, Default)]
pub struct QuotaEnforcer;

impl QuotaEnforcer {
    /// Attempt to deduct `amount` from `node`'s ledger entry.
    ///
    /// Returns `Ok(remaining)` on success.
    /// Returns `Err(QuotaExceeded)` if the deduction would underflow the
    /// remaining balance — the ledger is **not** modified on failure.
    /// An audit event is always emitted to `audit` regardless of outcome.
    ///
    /// # Errors
    /// Returns `Err(QuotaExceeded)` if `amount` exceeds the node's current balance or the node is undeclared.
    pub fn deduct(
        &self,
        ledger: &mut Ledger,
        node: NodeId,
        amount: u64,
        resource: &'static str,
        audit: &mut AuditLog,
    ) -> Result<u64> {
        let result = ledger
            .deduct(node, amount)
            .ok_or(Error::QuotaExceeded { resource });
        let denial = result
            .as_ref()
            .err()
            .map(|e| (e.denial_class(), e.denial_reason_str()));
        audit.append(EventKind::ResourceDeduction, node.get(), 0, denial);
        result
    }
}
