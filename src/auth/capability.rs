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
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct Capability {
    pub(crate) issuer:     NodeId,
    pub(crate) target:     NodeId,
    pub(crate) rights:     CapabilitySet,
    pub(crate) generation: Generation,
    pub(crate) nonce:      u64,
}

impl Capability {
    /// Returns `true` if this token grants the requested right and has not
    /// been superseded by a newer generation.
    #[must_use]
    pub fn authorises(&self, right: CapabilitySet, current_gen: Generation) -> bool {
        self.generation >= current_gen && self.rights.contains(right)
    }

    /// Delegate a strict subset of rights to `new_target`.
    ///
    /// Returns `None` if `subset` would expand rights beyond what this token
    /// holds — the kernel never allows privilege amplification.
    #[must_use]
    pub fn delegate(
        &self,
        new_target: NodeId,
        subset: CapabilitySet,
        nonce: u64,
    ) -> Option<Capability> {
        if !self.rights.contains(CapabilitySet::DELEGATE) {
            return None;
        }
        if !self.rights.contains(subset) {
            return None;
        }
        Some(Capability {
            issuer:     self.target,
            target:     new_target,
            rights:     subset,
            generation: self.generation,
            nonce,
        })
    }
}
