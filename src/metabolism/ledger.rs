//! Per-node resource ledger — deterministic, allocator-free.
//!
//! `heapless::LinearMap` replaces `BTreeMap`: the node count is bounded by
//! `MAX_NODES`, making the worst-case memory footprint fully predictable at
//! compile time and eliminating any interaction with the global allocator.

use heapless::LinearMap;

use crate::{
    error::Error,
    types::{NodeId, Quota, MAX_NODES},
    Result,
};

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
    ///
    /// Returns `Err(ManifestInvalid)` if:
    /// - `node` has already been seeded (duplicate manifest entry), or
    /// - the node table is already at `MAX_NODES` capacity.
    ///
    /// Rejecting duplicates prevents a manifest with two entries for the same
    /// node from silently overwriting the first quota with the second.
    ///
    /// # Errors
    /// Returns `Err(ManifestInvalid)` if the node is already seeded or the
    /// ledger node table is full.
    pub fn seed(&mut self, node: NodeId, ceiling: Quota) -> Result<()> {
        if self.balances.contains_key(&node.get()) {
            return Err(Error::ManifestInvalid {
                detail: "duplicate node quota in manifest",
            });
        }
        self.balances
            .insert(node.get(), ceiling.get())
            .map(|_| ())
            .map_err(|_| Error::ManifestInvalid {
                detail: "ledger node capacity exceeded (MAX_NODES)",
            })
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

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU32;

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    #[test]
    fn seed_duplicate_node_is_rejected() {
        let mut ledger = Ledger::new();
        let node = nz(1);
        ledger
            .seed(node, Quota::new(100))
            .expect("first seed must succeed");
        assert!(
            matches!(
                ledger.seed(node, Quota::new(200)),
                Err(Error::ManifestInvalid {
                    detail: "duplicate node quota in manifest"
                })
            ),
            "re-seeding same node must be rejected"
        );
        // Original balance must be unchanged — no silent overwrite.
        assert_eq!(
            ledger.balance(node),
            Some(100),
            "balance must not be overwritten by rejected duplicate seed"
        );
    }

    #[test]
    fn seed_distinct_nodes_succeeds() {
        let mut ledger = Ledger::new();
        ledger.seed(nz(1), Quota::new(100)).expect("node 1");
        ledger.seed(nz(2), Quota::new(200)).expect("node 2");
        assert_eq!(ledger.balance(nz(1)), Some(100));
        assert_eq!(ledger.balance(nz(2)), Some(200));
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
        ledger.seed(node, Quota::new(ceiling)).expect("single node within capacity");

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
        ledger.seed(node, Quota::new(ceiling)).expect("single node within capacity");

        let before = ledger.balance(node).unwrap();
        let new_bal = ledger.deduct(node, amount);

        kani::assert(new_bal.is_some(), "deduction within quota must succeed");
        kani::assert(
            new_bal.unwrap() == before - amount,
            "INVARIANT VIOLATION: deduction amount was not exact",
        );
    }
}
