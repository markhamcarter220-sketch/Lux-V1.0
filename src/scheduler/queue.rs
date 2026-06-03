//! Bounded, priority-ordered work queue — allocator-free.
//!
//! Capacity is a const generic parameter baked into the type.  The queue
//! never grows beyond `N` items; `enqueue` returns `SchedulerInvariant` when
//! the ceiling is reached, which is the fail-closed response to overload.
//!
//! `heapless::BinaryHeap` with `Min` kind replaces `std::collections::BinaryHeap`:
//! lower `priority` values (higher urgency) surface first, with no `Reverse`
//! wrapper required and no allocator interaction at runtime.

use heapless::{binary_heap::Min, BinaryHeap, Vec as HVec};

use crate::{error::Error, types::MAX_QUEUE, Result};

/// A single unit of scheduled work.
#[derive(Debug, PartialEq, Eq)]
pub struct WorkItem {
    /// Lower value = higher urgency.  A Min-heap surfaces the smallest
    /// `priority` first, so no `Reverse` wrapper is needed.
    pub priority: u8,
    /// The node that will execute this work item.
    pub target:   crate::types::NodeId,
    /// Opaque caller-defined payload associated with the work item.
    pub payload:  u64,
}

impl PartialOrd for WorkItem {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WorkItem {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

/// Bounded priority queue.  `N` is the hard capacity ceiling, fixed at
/// compile time — no runtime allocation ever occurs.
pub struct WorkQueue<const N: usize = MAX_QUEUE> {
    inner: BinaryHeap<WorkItem, Min, N>,
}

impl<const N: usize> core::fmt::Debug for WorkQueue<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WorkQueue")
            .field("len", &self.inner.len())
            .field("capacity", &N)
            .finish()
    }
}

impl<const N: usize> WorkQueue<N> {
    /// Construct an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self { inner: BinaryHeap::new() }
    }

    /// Attempt to enqueue `item`.
    ///
    /// Returns `Err(SchedulerInvariant)` if the queue is at capacity — the
    /// fail-closed response to sustained overload.
    pub fn enqueue(&mut self, item: WorkItem) -> Result<()> {
        self.inner
            .push(item)
            .map_err(|_| Error::SchedulerInvariant { detail: "queue capacity exhausted" })
    }

    /// Dequeue the highest-urgency (lowest `priority`) item, or `None`.
    pub fn dequeue(&mut self) -> Option<WorkItem> {
        self.inner.pop()
    }

    /// Current queue depth.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the queue contains no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Drain all items into a stack-allocated `Vec`, highest-urgency first.
    pub fn drain_ordered(&mut self) -> HVec<WorkItem, N> {
        let mut out = HVec::new();
        while let Some(item) = self.inner.pop() {
            let _ = out.push(item);
        }
        out
    }
}

impl<const N: usize> Default for WorkQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}
