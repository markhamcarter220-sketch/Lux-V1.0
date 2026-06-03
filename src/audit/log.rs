//! Append-only, tamper-evident in-memory audit log.
//!
//! # Tamper evidence
//!
//! Events are chained via SHA-256 hashes.  Each event's `hash` field is:
//!
//! ```text
//! SHA-256(prev_hash || kind_u8 || actor_le32 || seq_le64 || outcome_u8)
//! ```
//!
//! For the first event, `prev_hash = [0u8; 32]` (genesis).
//!
//! Verifying the entire chain is O(N) via `AuditLog::verify_chain`.  Any
//! single-bit mutation in any event or in the hash fields is detected.
//!
//! # Capacity
//!
//! Backed by `heapless::Vec<AuditEvent, MAX_AUDIT_EVENTS>`.  When the log is
//! full, `append` returns `false` but does **not** overwrite old events.
//! Callers must drain/export and reset if they need continued logging.
//!
//! # JSON export
//!
//! `export_json` writes a JSON array to any `core::fmt::Write` implementor,
//! requiring no allocator.

use sha2::{Digest, Sha256};

use crate::types::MAX_AUDIT_EVENTS;

use super::event::{AuditEvent, EventKind, Outcome};

/// Append-only, hash-chained audit log.
#[derive(Debug)]
pub struct AuditLog {
    events:    heapless::Vec<AuditEvent, MAX_AUDIT_EVENTS>,
    last_hash: [u8; 32],
    next_seq:  u64,
}

impl AuditLog {
    /// Construct an empty log.  The genesis hash is all-zeros.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events:    heapless::Vec::new(),
            last_hash: [0u8; 32],
            next_seq:  0,
        }
    }

    /// Append an event to the log.
    ///
    /// Returns `true` on success, `false` if the log is at capacity.
    /// Does **not** overwrite existing events on overflow (fail-closed: prefer
    /// data loss over silent corruption of the audit record).
    pub fn append(&mut self, kind: EventKind, actor: u32, outcome: Outcome) -> bool {
        let seq  = self.next_seq;
        let hash = Self::compute_hash(&self.last_hash, kind, actor, seq, outcome);

        let event = AuditEvent { kind, actor, seq, outcome, hash };

        if self.events.push(event).is_ok() {
            self.last_hash = hash;
            self.next_seq  = self.next_seq.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Verify the integrity of the entire hash chain in O(N).
    ///
    /// Returns `true` iff every event's `hash` field matches the expected
    /// value computed from the preceding event's hash and its own fields.
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        let mut prev = [0u8; 32];
        for event in &self.events {
            let expected =
                Self::compute_hash(&prev, event.kind, event.actor, event.seq, event.outcome);
            if expected != event.hash {
                return false;
            }
            prev = event.hash;
        }
        true
    }

    /// Returns the number of events currently in the log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if the log contains no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns the hash of the most recent event, or all-zeros for an empty log.
    #[must_use]
    pub fn head_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    /// Returns an iterator over all events in insertion order.
    pub fn events(&self) -> impl Iterator<Item = &AuditEvent> {
        self.events.iter()
    }

    /// Write the log as a JSON array to `writer`.
    ///
    /// Works in `no_std` with any `core::fmt::Write` implementor
    /// (e.g. a `heapless::String` or a UART writer).
    ///
    /// # Format
    /// ```json
    /// [{"seq":0,"kind":"cap_check","actor":1,"ok":true,"hash":"aabbcc..."},...]
    /// ```
    pub fn export_json<W: core::fmt::Write>(&self, writer: &mut W) -> core::fmt::Result {
        writer.write_char('[')?;
        for (i, ev) in self.events.iter().enumerate() {
            if i > 0 {
                writer.write_char(',')?;
            }
            write!(
                writer,
                r#"{{"seq":{},"kind":"{}","actor":{},"ok":{}}}"#,
                ev.seq,
                ev.kind_str(),
                ev.actor,
                ev.outcome == Outcome::Permitted,
            )?;
        }
        writer.write_char(']')
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    fn compute_hash(
        prev: &[u8; 32],
        kind: EventKind,
        actor: u32,
        seq: u64,
        outcome: Outcome,
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(prev);
        h.update([kind as u8]);
        h.update(actor.to_le_bytes());
        h.update(seq.to_le_bytes());
        h.update([outcome as u8]);
        h.finalize().into()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}
