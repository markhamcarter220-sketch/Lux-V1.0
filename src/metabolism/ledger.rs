//! Per-node resource ledger — deterministic, allocator-free.
//!
//! `heapless::LinearMap` replaces `BTreeMap`: the node count is bounded by
//! `MAX_NODES`, making the worst-case memory footprint fully predictable at
//! compile time and eliminating any interaction with the global allocator.

use heapless::LinearMap;

use crate::types::{NodeId, Quota, MAX_NODES};

/// Live accounting ledger for all registered nodes.
#[derive(Debug)]
pub struct Ledger {
    balances: LinearMap<u32, u64, MAX_NODES>,
}

impl Ledger {
    /// Constructs an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            balances: LinearMap::new(),
        }
    }

    /// Seed the ledger with `node`'s initial quota from the manifest.
    pub fn seed(&mut self, node: NodeId, ceiling: Quota) {
        let _ = self.balances.insert(node.get(), ceiling.get());
    }

    /// Attempt a deduction.  Returns the new balance on success, `None` if
    /// `amount` exceeds the current balance or the node is undeclared.
    ///
    /// The ledger is **not** modified on failure — atomicity is preserved.
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

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

// ── Kani proof harnesses ──────────────────────────────────────────────────────

#[cfg(kani)]
mod proofs {
    use super::*;
    use core::num::NonZeroU32;

    /// Formal proof: a failed deduction never modifies the ledger balance.
    #[kani::proof]
    fn failed_deduction_leaves_balance_unchanged() {
        let ceiling: u64 = kani::any();
        let amount: u64 = kani::any();

        let node = NonZeroU32::new(1).unwrap();
        let mut ledger = Ledger::default();
        ledger.seed(node, Quota::new(ceiling));

        let before = ledger.balance(node).unwrap();
        let result = ledger.deduct(node, amount);

        if result.is_none() {
            let after = ledger.balance(node).unwrap();
            kani::assert(
                after == before,
                "INVARIANT VIOLATION: failed deduction modified ledger balance",
            );
        }
    }

    /// Formal proof: a successful deduction strictly reduces the balance by
    /// exactly `amount`.
    #[kani::proof]
    fn successful_deduction_is_exact() {
        let ceiling: u64 = kani::any();
        let amount: u64 = kani::any();
        kani::assume(amount <= ceiling);

        let node = NonZeroU32::new(1).unwrap();
        let mut ledger = Ledger::default();
        ledger.seed(node, Quota::new(ceiling));

        let before = ledger.balance(node).unwrap();
        let new_bal = ledger.deduct(node, amount);

        kani::assert(new_bal.is_some(), "deduction within quota must succeed");
        kani::assert(
            new_bal.unwrap() == before - amount,
            "INVARIANT VIOLATION: deduction amount was not exact",
        );
    }
}
