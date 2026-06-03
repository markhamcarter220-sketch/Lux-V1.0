//! Quota enforcer — single-call entry point for resource checks.

use crate::{
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
    pub fn deduct(
        &self,
        ledger: &mut Ledger,
        node: NodeId,
        amount: u64,
        resource: &'static str,
    ) -> Result<u64> {
        ledger.deduct(node, amount).ok_or(Error::QuotaExceeded { resource })
    }
}
