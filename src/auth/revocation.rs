//! Capability revocation ledger — O(1) per-generation token invalidation.
//!
//! The revocation ledger records token IDs (capability nonces) that have been
//! explicitly invalidated before use.  It complements the nonce replay window:
//!
//! | Mechanism       | Use case                                  | Complexity |
//! |-----------------|-------------------------------------------|------------|
//! | Nonce replay    | Detect re-presentation of a used token    | O(N) scan  |
//! | Revocation ledger | Deny a token before it is used (pre-use) | O(1) hash  |
//!
//! Both are cleared on `rotate_generation`.
//!
//! # O(1) guarantee
//!
//! Backed by `heapless::FnvIndexSet` (open-addressed hash map with FNV-1a).
//! Both `revoke` and `is_revoked` are O(1) amortised.  The capacity is
//! bounded by `MAX_REVOCATIONS` (a compile-time constant and a power of two).
//! When the set is full, `revoke` returns `false` — the caller must rotate
//! the generation to clear space.

use heapless::FnvIndexSet;

use crate::types::MAX_REVOCATIONS;

/// Per-generation, O(1) capability revocation store.
#[derive(Debug)]
pub struct RevocationLedger {
    revoked: FnvIndexSet<u64, MAX_REVOCATIONS>,
    /// Count of successful revocations in this generation.
    epoch:   u64,
}

impl RevocationLedger {
    /// Constructs an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            revoked: FnvIndexSet::new(),
            epoch:   0,
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
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl Default for RevocationLedger {
    fn default() -> Self {
        Self::new()
    }
}
