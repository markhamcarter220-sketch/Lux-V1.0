//! Per-node resource ledger.

use alloc::collections::BTreeMap;

use crate::types::{NodeId, Quota};

/// Live accounting ledger for all registered nodes.
#[derive(Debug, Default)]
pub struct Ledger {
    balances: BTreeMap<u32, u64>,
}

impl Ledger {
    /// Seed the ledger with `node`'s initial quota from the manifest.
    pub fn seed(&mut self, node: NodeId, ceiling: Quota) {
        self.balances.insert(node.get(), ceiling.get());
    }

    /// Attempt a deduction.  Returns the new balance on success, `None` if
    /// `amount` exceeds the current balance.
    #[must_use]
    pub fn deduct(&mut self, node: NodeId, amount: u64) -> Option<u64> {
        let balance = self.balances.get_mut(&node.get())?;
        let new_balance = balance.checked_sub(amount)?;
        *balance = new_balance;
        Some(new_balance)
    }

    /// Returns the current balance for `node`, or `None` if undeclared.
    #[must_use]
    pub fn balance(&self, node: NodeId) -> Option<u64> {
        self.balances.get(&node.get()).copied()
    }
}
