//! Capability tokens and operation bitflags.

use bitflags::bitflags;
use zeroize::Zeroize;

use crate::types::{Generation, NodeId};

bitflags! {
    /// Granular operation rights encoded in a capability token.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CapabilitySet: u32 {
        /// May read topology edges originating at the bound node.
        const READ_TOPOLOGY   = 0b0000_0001;
        /// May request allocation from the metabolism ledger.
        const ALLOC_RESOURCE  = 0b0000_0010;
        /// May schedule work items into the kernel queue.
        const SCHEDULE        = 0b0000_0100;
        /// May delegate a strict subset of own capabilities.
        const DELEGATE        = 0b0000_1000;
        /// May invoke the graceful shutdown path for the bound node.
        const SHUTDOWN        = 0b0001_0000;
    }
}

/// An unforgeable, time-scoped, node-bound capability token.
///
/// Tokens are intentionally `!Clone` — possession is transfer.
/// Delegation produces a *new* token with a subset of rights.
///
/// The `nonce` field is consumed on first use by `Policy::check`; re-presenting
/// the same token is detected and denied as a replay.
///
/// Secret fields (`rights`, `generation`, `nonce`) are zeroed on drop.
/// `issuer` and `target` are `NonZeroU32` and cannot be zeroed to 0; they
/// are non-secret routing metadata.
#[derive(Debug)]
pub struct Capability {
    pub(crate) issuer: NodeId,
    pub(crate) target: NodeId,
    pub(crate) rights: CapabilitySet,
    pub(crate) generation: Generation,
    pub(crate) nonce: u64,
}

impl Zeroize for Capability {
    fn zeroize(&mut self) {
        self.nonce = 0u64;
        self.generation.0 = 0u64;
        self.rights = CapabilitySet::empty();
    }
}

impl Drop for Capability {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Capability {
    /// Returns `true` if this token grants the requested right and its
    /// generation matches the current epoch exactly.
    ///
    /// Equality is required (not `>=`) so that tokens minted with a future
    /// generation cannot bypass `rotate_generation()`.  A token with
    /// `generation > current_gen` would permanently pass a `>=` check and
    /// survive rotation, defeating the kill switch.  The TLA+ spec
    /// (`IsValidCap`) requires `cap.gen = epoch`; this method enforces it.
    #[must_use]
    pub fn authorises(&self, right: CapabilitySet, current_gen: Generation) -> bool {
        self.generation == current_gen && self.rights.contains(right)
    }

    /// Delegate a strict subset of rights to `new_target`.
    ///
    /// Returns `None` if:
    /// - the token does not hold `DELEGATE`, or
    /// - `subset` is not a bitwise subset of `self.rights`.
    ///
    /// The kernel never allows privilege amplification — this is enforced
    /// algebraically by the `contains` check.
    ///
    /// # Caller obligation — nonce uniqueness
    ///
    /// The caller **must** supply a `nonce` that is unique within the current
    /// generation.  Reusing a nonce across delegated tokens causes one of two
    /// failure modes:
    ///
    /// 1. If a token with the same nonce was already checked by `Policy::check`
    ///    (step 3 — replay detection), the delegated token will be denied as a
    ///    replay.
    /// 2. If a revoked token shares the same nonce, the new delegated token
    ///    will also be denied (step 2 — explicit revocation by nonce).
    ///
    /// The kernel cannot generate nonces in `no_std` without an RNG dependency;
    /// nonce sourcing is therefore an application-layer responsibility.  A
    /// hardware counter, CSPRNG output, or monotonically-incrementing per-issuer
    /// counter are all suitable sources.
    ///
    /// Nonce uniqueness is **scoped per generation**: `Policy::rotate_generation`
    /// clears the replay window, so a nonce that was used in generation N may be
    /// safely reused in generation N+1.  See `Policy::check` step 3 for the
    /// replay detection logic.
    #[must_use]
    pub const fn delegate(
        &self,
        new_target: NodeId,
        subset: CapabilitySet,
        nonce: u64,
    ) -> Option<Self> {
        if !self.rights.contains(CapabilitySet::DELEGATE) {
            return None;
        }
        if !self.rights.contains(subset) {
            return None;
        }
        Some(Self {
            issuer: self.target,
            target: new_target,
            rights: subset,
            generation: self.generation,
            nonce,
        })
    }

    /// Returns the node that issued this token.
    #[must_use]
    pub const fn issuer(&self) -> NodeId {
        self.issuer
    }

    /// Returns the node to which this token is bound.
    #[must_use]
    pub const fn target(&self) -> NodeId {
        self.target
    }

    /// Returns the raw rights bits (used by HSM capability signing).
    #[cfg(feature = "hsm")]
    #[must_use]
    pub(crate) const fn rights_bits(&self) -> u32 {
        self.rights.bits()
    }

    /// Returns the raw generation value (used by HSM capability signing).
    #[cfg(feature = "hsm")]
    #[must_use]
    pub(crate) const fn generation_raw(&self) -> u64 {
        self.generation.0
    }

    /// Returns the raw nonce (used by HSM capability signing).
    #[cfg(feature = "hsm")]
    #[must_use]
    pub(crate) const fn nonce_raw(&self) -> u64 {
        self.nonce
    }

    /// Test-only constructor — use only in test harnesses.
    ///
    /// Not gated behind `#[cfg(test)]` because integration tests compile as
    /// separate crates and would not see `cfg(test)` items.  The `new_for_`
    /// prefix and this doc comment are the canonical signal.
    #[must_use]
    pub const fn new_for_test(
        issuer: NodeId,
        target: NodeId,
        rights: CapabilitySet,
        generation: Generation,
        nonce: u64,
    ) -> Self {
        Self {
            issuer,
            target,
            rights,
            generation,
            nonce,
        }
    }
}

// ── Kani proof harnesses ──────────────────────────────────────────────────────

#[cfg(kani)]
mod proofs {
    use super::*;
    use core::num::NonZeroU32;

    /// Formal proof: `delegate` can never produce a token whose rights are a
    /// strict superset of the delegating token's rights.
    ///
    /// Kani explores all possible `rights_raw` and `subset_raw` bit patterns
    /// (2^32 × 2^32 combinations) and asserts the invariant holds for every
    /// one.  A counterexample here is a P0 security finding.
    #[kani::proof]
    fn delegate_never_amplifies_rights() {
        let rights_raw: u32 = kani::any();
        let subset_raw: u32 = kani::any();
        let gen_val: u64 = kani::any();
        let nonce: u64 = kani::any();
        let new_nonce: u64 = kani::any();

        let issuer = NonZeroU32::new(1).unwrap();
        let target = NonZeroU32::new(2).unwrap();
        let new_target = NonZeroU32::new(3).unwrap();

        let rights = CapabilitySet::from_bits_truncate(rights_raw);
        let requested_subset = CapabilitySet::from_bits_truncate(subset_raw);

        let cap = Capability {
            issuer,
            target,
            rights,
            generation: Generation(gen_val),
            nonce,
        };

        if let Some(delegated) = cap.delegate(new_target, requested_subset, new_nonce) {
            kani::assert(
                rights.contains(delegated.rights),
                "INVARIANT VIOLATION: delegation produced rights not held by delegator",
            );
        }
    }

    /// Formal proof: a token without `DELEGATE` right can never produce a
    /// delegated token under any input.
    #[kani::proof]
    fn no_delegate_right_produces_no_delegation() {
        let rights_raw: u32 = kani::any();
        let subset_raw: u32 = kani::any();
        let gen_val: u64 = kani::any();
        let nonce: u64 = kani::any();
        let new_nonce: u64 = kani::any();

        // Mask out the DELEGATE bit — this token explicitly lacks it.
        let rights =
            CapabilitySet::from_bits_truncate(rights_raw).difference(CapabilitySet::DELEGATE);
        let subset = CapabilitySet::from_bits_truncate(subset_raw);

        let issuer = NonZeroU32::new(1).unwrap();
        let target = NonZeroU32::new(2).unwrap();
        let new_target = NonZeroU32::new(3).unwrap();

        let cap = Capability {
            issuer,
            target,
            rights,
            generation: Generation(gen_val),
            nonce,
        };

        let result = cap.delegate(new_target, subset, new_nonce);
        kani::assert(
            result.is_none(),
            "INVARIANT VIOLATION: token without DELEGATE produced a delegation",
        );
    }
}
