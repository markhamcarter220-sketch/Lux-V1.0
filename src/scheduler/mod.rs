//! Scheduler subsystem — capability-gated, priority-ordered work queue.
//!
//! ## Invariants enforced
//!
//! 1. **Capability-Gated (I2):** every call to [`Scheduler::schedule`] is gated
//!    behind `Policy::check(CapabilitySet::SCHEDULE)`.  A caller without the
//!    `SCHEDULE` right — or with an expired/revoked token — receives
//!    `Err(CapabilityDenied)` and the queue is not modified.
//!
//! 2. **Fail-Closed (I1):** queue capacity exhaustion returns
//!    `Err(SchedulerInvariant)`, never a silent drop.
//!
//! ## Usage
//!
//! Use [`Scheduler`] (the capability-gated wrapper) for all production paths.
//! [`WorkQueue`] is the inner data structure; it is exposed for use in test
//! harnesses where capability infrastructure is unavailable.

pub mod queue;

pub use queue::{WorkItem, WorkQueue};

use crate::{
    audit::AuditLog,
    auth::{capability::{Capability, CapabilitySet}, policy::Policy},
    types::MAX_QUEUE,
    Result,
};

/// Capability-gated scheduler.
///
/// Wraps [`WorkQueue`] and enforces `CapabilitySet::SCHEDULE` on every
/// enqueue via `Policy::check`.  This is the production entry point for
/// submitting work items to the kernel queue (I2 — Capability-Gated).
#[derive(Debug)]
pub struct Scheduler<const N: usize = MAX_QUEUE> {
    queue: WorkQueue<N>,
}

impl<const N: usize> Scheduler<N> {
    /// Construct an empty scheduler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            queue: WorkQueue::new(),
        }
    }

    /// Attempt to enqueue `item` after verifying the `SCHEDULE` right.
    ///
    /// Steps (fail-closed at each step):
    /// 1. `Policy::check` verifies the token holds `SCHEDULE`, is not expired,
    ///    revoked, or replayed.  Returns `Err(CapabilityDenied)` on failure.
    /// 2. `WorkQueue::enqueue` inserts the item.  Returns
    ///    `Err(SchedulerInvariant)` if the queue is at capacity `N`.
    ///
    /// The queue is not modified unless both steps succeed.
    ///
    /// # Errors
    /// Returns `Err(CapabilityDenied)` if the capability check fails, or
    /// `Err(SchedulerInvariant)` if the queue is full.
    pub fn schedule(
        &mut self,
        item: WorkItem,
        cap: &Capability,
        policy: &mut Policy,
        audit: &mut AuditLog,
    ) -> Result<()> {
        policy.check(cap, CapabilitySet::SCHEDULE, audit)?;
        self.queue.enqueue(item)
    }

    /// Dequeue the highest-urgency item, or `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<WorkItem> {
        self.queue.dequeue()
    }

    /// Current queue depth.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns `true` if the queue contains no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl<const N: usize> Default for Scheduler<N> {
    fn default() -> Self {
        Self::new()
    }
}
