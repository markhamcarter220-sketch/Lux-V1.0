//! Capability revocation ledger — O(1) explicit pre-use token denial.
//!
//! The revocation ledger records token IDs (capability nonces) that have been
//! explicitly invalidated before use.  It is one of three invalidation
//! mechanisms exercised by `Policy::check`:
//!
//! | Mechanism | Use case | Location | Complexity |
//! |-----------|----------|----------|------------|
//! | Generation check | Deny stale-generation tokens | `Policy::check` step 1 | O(1) |
//! | Revocation ledger | Deny a specific token before it is used | `Policy::check` step 2 | O(1) amortised |
//! | Nonce replay window | Detect re-presentation of an already-used token | `Policy::check` step 3 | O(N), N ≤ 256 |
//!
//! All three are cleared on `rotate_generation`.
//!
//! # O(1) guarantee (this module)
//!
//! Backed by `heapless::FnvIndexSet` (open-addressed hash map with FNV-1a).
//! Both `revoke` and `is_revoked` are O(1) amortised.  The capacity is
//! bounded by `MAX_REVOCATIONS` (a compile-time constant and a power of two).
//! When the set is full, `revoke` returns `false` — the caller must rotate
//! the generation to clear space.
//!
//! Note: the O(1) guarantee applies to this struct's operations in isolation.
//! The overall `Policy::check` call has `O(NONCE_WINDOW)` worst-case complexity
//! due to the nonce replay linear scan; see `src/auth/policy.rs` for details.

use heapless::FnvIndexSet;

use crate::types::MAX_REVOCATIONS;

/// Per-generation, O(1) capability revocation store.
#[derive(Debug)]
pub struct RevocationLedger {
    revoked: FnvIndexSet<u64, MAX_REVOCATIONS>,
    /// Count of successful revocations in this generation.
    epoch: u64,
}

impl RevocationLedger {
    /// Constructs an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            revoked: FnvIndexSet::new(),
            epoch: 0,
        }
    }

    /// Mark `token_id` as revoked.
    ///
    /// Returns `true` on success, `false` if the revocation set is full.
    /// When `false`, the caller should rotate the generation to clear space.
    pub fn revoke(&mut self, token_id: u64) -> bool {
        if self.revoked.insert(token_id).is_ok() {
            self.epoch = self.epoch.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Returns `true` if `token_id` has been revoked in this generation.
    ///
    /// O(1) amortised via FNV-1a hash table.
    #[must_use]
    pub fn is_revoked(&self, token_id: u64) -> bool {
        self.revoked.contains(&token_id)
    }

    /// Clear all revocations.  Called on generation rotation.
    pub fn clear(&mut self) {
        self.revoked.clear();
        self.epoch = 0;
    }

    /// Number of tokens revoked in the current generation.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Default for RevocationLedger {
    fn default() -> Self {
        Self::new()
    }
}
