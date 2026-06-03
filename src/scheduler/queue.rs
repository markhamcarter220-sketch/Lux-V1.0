//! Bounded, priority-ordered work queue.

use alloc::{collections::BinaryHeap, vec::Vec};
use core::cmp::Reverse;

use crate::{
    error::Error,
    types::NodeId,
    Result,
};

/// A single unit of scheduled work.
#[derive(Debug, PartialEq, Eq)]
pub struct WorkItem {
    /// Lower value = higher priority (min-heap via `Reverse`).
    pub priority: u8,
    pub target:   NodeId,
    pub payload:  u64,
}

impl PartialOrd for WorkItem {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WorkItem {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        Reverse(self.priority).cmp(&Reverse(other.priority))
    }
}

/// Bounded priority queue.  Capacity is fixed at construction and enforced
/// on every enqueue — no unbounded growth is permitted.
#[derive(Debug)]
pub struct WorkQueue {
    inner:    BinaryHeap<WorkItem>,
    capacity: usize,
}

impl WorkQueue {
    /// Construct a queue with a hard capacity ceiling.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: BinaryHeap::with_capacity(capacity),
            capacity,
        }
    }

    /// Attempt to enqueue `item`.
    ///
    /// Returns `Err(SchedulerInvariant)` if the queue is at capacity.
    pub fn enqueue(&mut self, item: WorkItem) -> Result<()> {
        if self.inner.len() >= self.capacity {
            return Err(Error::SchedulerInvariant { detail: "queue capacity exhausted" });
        }
        self.inner.push(item);
        Ok(())
    }

    /// Dequeue the highest-priority item, or `None` if the queue is empty.
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

    /// Drain all items as an ordered `Vec` (highest-priority first).
    pub fn drain_ordered(&mut self) -> Vec<WorkItem> {
        let mut out = Vec::with_capacity(self.inner.len());
        while let Some(item) = self.inner.pop() {
            out.push(item);
        }
        out
    }
}
