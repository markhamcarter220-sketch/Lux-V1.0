//! Policy enforcement point — the kernel's single authorisation gate.
//!
//! ## Check order (fail-closed at each step)
//!
//! | Step | Check | Data structure | Complexity |
//! |------|-------|----------------|------------|
//! | 1 | Generation ≥ current + rights bitmask | integer comparison | O(1) |
//! | 2 | Explicit revocation (`RevocationLedger`) | FNV-1a hash set | O(1) amortised |
//! | 3 | Nonce replay detection (`used_nonces`) | linear scan of `Vec` | O(N), N ≤ `NONCE_WINDOW` = 256 |
//! | 4 | Nonce recording (window exhaustion → deny) | `Vec::push` | O(1) |
//!
//! The overall worst-case complexity of `Policy::check` is **O(`NONCE_WINDOW`)**
//! due to step 3.  Calling `rotate_generation` resets the nonce window and
//! keeps the window depth low in practice.  The O(1) revocation claim in
//! `RevocationLedger`'s documentation refers to step 2 in isolation.
//!
//! `check` requires `&mut self` because steps 3–4 mutate state.
//!
//! ## Revocation integration
//!
//! `Policy` owns a `RevocationLedger`.  Callers revoke tokens via
//! `Policy::revoke_capability(nonce)`.  On `rotate_generation`, both the
//! nonce window and the revocation ledger are cleared atomically.

use heapless::Vec as HVec;

use crate::{
    audit::{AuditLog, EventKind},
    auth::{
        capability::{Capability, CapabilitySet},
        revocation::RevocationLedger,
    },
    error::Error,
    types::{Generation, NONCE_WINDOW},
    Result,
};

/// The kernel's central enforcement point.
#[derive(Debug)]
pub struct Policy {
    current_generation: Generation,
    /// Nonces consumed in the current generation.  Cleared on rotation.
    used_nonces: HVec<u64, NONCE_WINDOW>,
    /// Explicitly revoked token IDs.  Cleared on rotation.
    revocation: RevocationLedger,
}

impl Policy {
    /// Construct a `Policy` anchored at `generation`.
    #[must_use]
    pub const fn new(generation: Generation) -> Self {
        Self {
            current_generation: generation,
            used_nonces: HVec::new(),
            revocation: RevocationLedger::new(),
        }
    }

    /// Gate the operation described by `required_right` on `cap`.
    ///
    /// Returns `Ok(())` iff all four checks pass (generation, rights,
    /// revocation, replay).  Every other path returns `Err(CapabilityDenied)`.
    /// An audit event is always emitted to `audit` regardless of outcome.
    ///
    /// # Errors
    /// Returns `Err(CapabilityDenied)` if generation, rights, revocation, or nonce checks fail.
    pub fn check(
        &mut self,
        cap: &Capability,
        required_right: CapabilitySet,
        audit: &mut AuditLog,
    ) -> Result<()> {
        let actor = cap.target.get();
        let result = self.check_inner(cap, required_right);
        let denial = result
            .as_ref()
            .err()
            .map(|e| (e.denial_class(), e.denial_reason_str()));
        audit.append(EventKind::CapabilityCheck, actor, 0, denial);
        result
    }

    fn check_inner(&mut self, cap: &Capability, required_right: CapabilitySet) -> Result<()> {
        // Step 1: generation and rights.
        if !cap.authorises(required_right, self.current_generation) {
            return Err(Error::CapabilityDenied {
                reason: "token expired, insufficient rights, or wrong generation",
            });
        }

        // Step 2: revocation check (pre-use denial).
        if self.revocation.is_revoked(cap.nonce) {
            return Err(Error::CapabilityDenied {
                reason: "capability revoked",
            });
        }

        // Step 3: nonce replay.
        if self.used_nonces.contains(&cap.nonce) {
            return Err(Error::CapabilityDenied {
                reason: "nonce replayed",
            });
        }

        // Step 4: record nonce — fail-closed on window exhaustion.
        self.used_nonces
            .push(cap.nonce)
            .map_err(|_| Error::CapabilityDenied {
                reason: "nonce window exhausted; rotate generation",
            })?;

        Ok(())
    }

    /// Explicitly revoke a capability token by its nonce.
    ///
    /// Returns `true` on success, `false` if the revocation set is full.
    pub fn revoke_capability(&mut self, token_id: u64) -> bool {
        self.revocation.revoke(token_id)
    }

    /// Returns `true` if `token_id` is currently revoked.
    #[must_use]
    pub fn is_revoked(&self, token_id: u64) -> bool {
        self.revocation.is_revoked(token_id)
    }

    /// Advance the generation counter, clearing both the nonce replay window
    /// and the revocation ledger atomically.
    pub fn rotate_generation(&mut self) {
        self.current_generation = Generation(self.current_generation.0.saturating_add(1));
        self.used_nonces.clear();
        self.revocation.clear();
    }

    /// Returns the current generation value.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.current_generation
    }
}
