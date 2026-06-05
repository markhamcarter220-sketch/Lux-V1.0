//! Raft log — fixed-capacity, 1-indexed, append-only.
//!
//! Indices follow Raft convention: 1-based.  Index 0 is the sentinel meaning
//! "no entry" (the implicit state before any entry is appended).

use crate::types::NodeId;

/// A single entry in the Raft log, representing a proposed topology traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogEntry {
    /// The Raft term in which this entry was proposed.
    pub term: u64,
    /// Source node of the proposed traversal.
    pub src: NodeId,
    /// Destination node of the proposed traversal.
    pub dst: NodeId,
}

/// Fixed-capacity, append-only Raft log.
///
/// The const parameter `N` bounds the maximum number of entries.
/// Indices are 1-based (Raft convention). Index 0 always means "no entry".
#[derive(Debug)]
pub struct RaftLog<const N: usize = 256> {
    entries: heapless::Vec<LogEntry, N>,
}

impl<const N: usize> RaftLog<N> {
    /// Construct an empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
        }
    }

    /// Append `entry`. Returns `false` if the log is at capacity.
    pub fn append(&mut self, entry: LogEntry) -> bool {
        self.entries.push(entry).is_ok()
    }

    /// Return the entry at 1-based `index`, or `None` if out of range.
    #[must_use]
    pub fn get(&self, index: u64) -> Option<&LogEntry> {
        if index == 0 {
            return None;
        }
        let idx = usize::try_from(index - 1).ok()?;
        self.entries.get(idx)
    }

    /// Number of entries currently in the log.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Returns `true` if the log contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Term of the last entry, or `0` if the log is empty.
    #[must_use]
    pub fn last_term(&self) -> u64 {
        self.entries.last().map_or(0, |e| e.term)
    }

    /// 1-based index of the last entry, or `0` if the log is empty.
    #[must_use]
    pub fn last_index(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Term of the entry at 1-based `index`, or `None` if out of range.
    #[must_use]
    pub fn term_at(&self, index: u64) -> Option<u64> {
        self.get(index).map(|e| e.term)
    }

    /// Truncate all entries from 1-based `from_index` onward.
    ///
    /// Has no effect when `from_index` is 0 or exceeds `last_index()`.
    pub fn truncate_from(&mut self, from_index: u64) {
        if from_index == 0 {
            return;
        }
        if let Ok(idx) = usize::try_from(from_index - 1) {
            self.entries.truncate(idx);
        }
    }
}

impl<const N: usize> Default for RaftLog<N> {
    fn default() -> Self {
        Self::new()
    }
}
