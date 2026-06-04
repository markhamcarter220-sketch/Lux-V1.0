//! Append-only, tamper-evident in-memory audit log.
//!
//! # API contract
//!
//! The public API provides only `append`, `verify_chain`, and read-only
//! accessors.  There is no `clear`, `remove`, or mutation path for existing
//! events.  Capacity overflow returns `false` without overwriting old events
//! (fail-closed: prefer silent loss of new events over silent corruption of
//! the existing audit record).
//!
//! # HALT / FAILURE classification
//!
//! `append` takes `denial: Option<(DenialClass, &'static str)>`:
//!
//! - `None` → the operation was **permitted**; no denial fields are recorded.
//! - `Some((class, reason))` → the operation was **denied**; `class` is
//!   [`DenialClass::Halt`] or [`DenialClass::Failure`]; `reason` is the static
//!   string from the originating [`crate::error::Error`].
//!
//! The `Outcome` stored on each event is derived from whether `denial` is
//! `Some` or `None` — callers do not pass it separately.
//!
//! # Tamper evidence
//!
//! Each event's `hash` field is:
//!
//! ```text
//! SHA-256(
//!     prev_hash(32)       ← all-zeros for the genesis event
//!     kind_u8
//!     actor_le32
//!     seq_le64
//!     timestamp_le64
//!     outcome_u8          ← 0x00 = Permitted, 0x01 = Denied
//!     denial_class_u8     ← 0x00 = None, 0x01 = Halt, 0x02 = Failure
//!     denial_reason_bytes ← b"" for permitted events, UTF-8 for denied
//! )
//! ```
//!
//! `denial_reason_bytes` is the last field; no length prefix is needed because
//! `outcome_u8` already disambiguates permitted (empty reason) from denied.
//!
//! # Timing
//!
//! This kernel is `no_std` and single-threaded.  `AuditLog` is `!Send` and
//! `!Sync` by virtue of holding non-`Send` types; `append` requires `&mut self`.
//! There is therefore no race condition between event emission and the operation
//! result.  The correct call order is:
//!
//!   1. Execute the operation (e.g. `Policy::check`, `traverse`, `deduct`).
//!   2. Obtain the `Result`.
//!   3. Call `append` with the result.
//!
//! Reversing steps 1 and 3 would record an event whose result is not yet known
//! and is not supported by this API.
//!
//! # Capacity
//!
//! Backed by `heapless::Vec<AuditEvent, MAX_AUDIT_EVENTS>`.  When the log is
//! full, `append` returns `false` but does **not** overwrite old events.
//!
//! # JSON export
//!
//! `export_json` writes a JSON array to any `core::fmt::Write` implementor,
//! requiring no allocator.  Format:
//!
//! ```json
//! [
//!   {"seq":0,"kind":"cap_check","actor":1,"ts":0,"ok":true,"class":null,"reason":null},
//!   {"seq":1,"kind":"topo_traverse","actor":2,"ts":42,"ok":false,"class":"halt","reason":"undeclared edge"}
//! ]
//! ```

use sha2::{Digest, Sha256};

use crate::{error::DenialClass, types::MAX_AUDIT_EVENTS};

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
    /// # Parameters
    ///
    /// - `kind` — the type of operation being audited.
    /// - `actor` — the node ID of the initiating principal.
    /// - `timestamp` — caller-supplied monotonic counter (hardware tick or
    ///   logical clock).  The kernel does not own a wall clock.
    /// - `denial` — `None` for a **permitted** outcome; `Some((class, reason))`
    ///   for a **denied** outcome, where `class` is [`DenialClass::Halt`] or
    ///   [`DenialClass::Failure`] and `reason` is the static error string.
    ///
    /// # Returns
    ///
    /// `true` on success.  `false` if the log is at capacity — the event is
    /// **not** recorded (fail-closed: no overwrites).
    pub fn append(
        &mut self,
        kind: EventKind,
        actor: u32,
        timestamp: u64,
        denial: Option<(DenialClass, &'static str)>,
    ) -> bool {
        let seq     = self.next_seq;
        let outcome = if denial.is_some() { Outcome::Denied } else { Outcome::Permitted };
        let (denial_class, denial_reason) = match denial {
            Some((c, r)) => (Some(c), Some(r)),
            None         => (None, None),
        };

        let hash = Self::compute_hash(
            &self.last_hash,
            kind,
            actor,
            seq,
            timestamp,
            outcome,
            denial_class,
            denial_reason,
        );

        let event = AuditEvent {
            kind,
            actor,
            seq,
            timestamp,
            outcome,
            denial_class,
            denial_reason,
            hash,
        };

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
    /// value recomputed from the preceding event's hash and its own fields.
    /// Any single-bit mutation in any event or in the hash fields is detected.
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        let mut prev = [0u8; 32];
        for event in &self.events {
            let expected = Self::compute_hash(
                &prev,
                event.kind,
                event.actor,
                event.seq,
                event.timestamp,
                event.outcome,
                event.denial_class,
                event.denial_reason,
            );
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
    /// Works in `no_std` with any `core::fmt::Write` implementor.
    ///
    /// # Format
    /// ```json
    /// [{"seq":0,"kind":"cap_check","actor":1,"ts":0,"ok":true,"class":null,"reason":null}]
    /// ```
    pub fn export_json<W: core::fmt::Write>(&self, writer: &mut W) -> core::fmt::Result {
        writer.write_char('[')?;
        for (i, ev) in self.events.iter().enumerate() {
            if i > 0 {
                writer.write_char(',')?;
            }
            let ok = ev.outcome == Outcome::Permitted;

            // class field: null or "halt" / "failure"
            match ev.denial_class_str() {
                None    => write!(writer,
                    r#"{{"seq":{},"kind":"{}","actor":{},"ts":{},"ok":{},"class":null,"reason":null}}"#,
                    ev.seq, ev.kind_str(), ev.actor, ev.timestamp, ok)?,
                Some(c) => {
                    let reason = ev.denial_reason.unwrap_or("");
                    write!(writer,
                        r#"{{"seq":{},"kind":"{}","actor":{},"ts":{},"ok":{},"class":"{}","reason":"{}"}}"#,
                        ev.seq, ev.kind_str(), ev.actor, ev.timestamp, ok, c, reason)?;
                }
            }
        }
        writer.write_char(']')
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn compute_hash(
        prev:         &[u8; 32],
        kind:         EventKind,
        actor:        u32,
        seq:          u64,
        timestamp:    u64,
        outcome:      Outcome,
        denial_class: Option<DenialClass>,
        denial_reason: Option<&'static str>,
    ) -> [u8; 32] {
        // Wire format (see module-level doc):
        //   prev_hash || kind_u8 || actor_le32 || seq_le64 || timestamp_le64
        //   || outcome_u8 || denial_class_u8 || denial_reason_bytes
        let class_byte: u8 = match denial_class {
            None                       => 0x00,
            Some(DenialClass::Halt)    => 0x01,
            Some(DenialClass::Failure) => 0x02,
        };
        let mut h = Sha256::new();
        h.update(prev);
        h.update([kind as u8]);
        h.update(actor.to_le_bytes());
        h.update(seq.to_le_bytes());
        h.update(timestamp.to_le_bytes());
        h.update([outcome as u8]);
        h.update([class_byte]);
        if let Some(reason) = denial_reason {
            h.update(reason.as_bytes());
        }
        h.finalize().into()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}
