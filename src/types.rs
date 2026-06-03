//! Primitive domain types shared across kernel subsystems.

use core::num::NonZeroU32;

// ── Capacity constants ────────────────────────────────────────────────────────
// All statically-allocated structures are bounded by these values.
// Increasing any constant widens the worst-case stack frame proportionally.

/// Maximum number of nodes in the topology graph.
/// Encoded as a 64-bit bitmask row per node, so 64 is the natural ceiling.
pub const MAX_NODES: usize = 64;

/// Maximum number of directed edges declared in a boot manifest.
pub const MAX_EDGES: usize = 256;

/// Maximum capacity of a `WorkQueue`.
pub const MAX_QUEUE: usize = 256;

/// Number of per-generation nonces tracked for replay protection.
/// When exhausted the kernel denies new capabilities (fail-closed).
pub const NONCE_WINDOW: usize = 256;

/// Maximum simultaneously-revoked capability tokens per generation.
/// Must be a power of two (heapless `FnvIndexSet` requirement).
pub const MAX_REVOCATIONS: usize = 256;

/// Maximum events retained in the in-memory audit log.
pub const MAX_AUDIT_EVENTS: usize = 512;

// ── Domain primitives ─────────────────────────────────────────────────────────

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
