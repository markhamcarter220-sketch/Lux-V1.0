//! Scheduler subsystem — priority-ordered work queue with invariant enforcement.
//!
//! The scheduler enforces two hard invariants:
//! 1. No work item may be enqueued without a valid capability token.
//! 2. No work item may target a node that is not declared `Active` in the
//!    topology graph.
//!
//! Violation of either invariant returns an error; the queue state is
//! unchanged.

pub mod queue;

pub use queue::WorkQueue;
