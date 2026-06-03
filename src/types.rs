//! Primitive domain types shared across kernel subsystems.

use core::num::NonZeroU32;

/// Unique, non-zero identifier for a kernel node.
pub type NodeId = NonZeroU32;

/// Monotonic generation counter used to detect stale capability tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(pub u64);

/// A saturating resource counter — never wraps, never overflows silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Quota(u64);

impl Quota {
    /// Creates a new quota ceiling.
    #[must_use]
    pub const fn new(ceiling: u64) -> Self {
        Self(ceiling)
    }

    /// Returns the raw ceiling value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Checked subtraction — returns `None` when the deduction would underflow.
    #[must_use]
    pub fn checked_sub(self, amount: u64) -> Option<Self> {
        self.0.checked_sub(amount).map(Self)
    }
}
