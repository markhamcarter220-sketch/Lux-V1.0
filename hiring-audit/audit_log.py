"""
audit_log.py — SHA-256 hash-chained audit log for hiring decisions.

Mirrors the Lux Kernel AuditLog (src/audit/mod.rs):
  - Every entry covers the previous entry's hash → tamper-evident chain.
  - verify_chain() recomputes every hash from scratch; any mutation fails.
  - Append returns False at capacity (no silent overwrite).
  - No panics: all errors returned as False / None.

Wire format per entry (little-endian):
  prev_hash (32 bytes)
  || seq      (u64 LE)
  || cid      (u32 LE)
  || decision (u8:  1=HIRE, 0=REJECT)
  || conf     (f64 LE IEEE-754)
  || policy   (u8:  1=ALLOW, 0=DENY)
  || ts_ns    (u64 LE  nanoseconds since epoch)
"""

import csv
import hashlib
import json
import struct
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterator, List, Optional

MAX_AUDIT_EVENTS = 512   # mirrors Lux constant


@dataclass
class AuditEntry:
    seq:            int
    candidate_id:   int
    decision:       str        # "HIRE" | "REJECT"
    confidence:     float
    policy_allowed: bool
    policy_reason:  str
    timestamp_ns:   int
    timestamp_iso:  str
    prev_hash:      str        # hex
    entry_hash:     str        # hex


def _pack(seq: int, cid: int, decision: str, conf: float,
          allowed: bool, ts_ns: int) -> bytes:
    return (
        struct.pack("<Q", seq)
        + struct.pack("<I", cid)
        + (b"\x01" if decision == "HIRE" else b"\x00")
        + struct.pack("<d", conf)
        + (b"\x01" if allowed else b"\x00")
        + struct.pack("<Q", ts_ns)
    )


class AuditLog:
    def __init__(self):
        self._entries: List[AuditEntry] = []
        self._prev_hash: bytes = bytes(32)   # genesis: 32 zero bytes

    # ── Append ─────────────────────────────────────────────────────────────

    def append(
        self,
        candidate_id: int,
        decision: str,
        confidence: float,
        policy_allowed: bool,
        policy_reason: str,
    ) -> bool:
        """Return False at capacity; never raise."""
        if len(self._entries) >= MAX_AUDIT_EVENTS:
            return False

        seq    = len(self._entries) + 1
        ts_ns  = time.time_ns()
        ts_iso = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()

        h = hashlib.sha256()
        h.update(self._prev_hash)
        h.update(_pack(seq, candidate_id, decision, confidence, policy_allowed, ts_ns))
        digest = h.digest()

        entry = AuditEntry(
            seq=seq,
            candidate_id=candidate_id,
            decision=decision,
            confidence=round(confidence, 6),
            policy_allowed=policy_allowed,
            policy_reason=policy_reason,
            timestamp_ns=ts_ns,
            timestamp_iso=ts_iso,
            prev_hash=self._prev_hash.hex(),
            entry_hash=digest.hex(),
        )
        self._entries.append(entry)
        self._prev_hash = digest
        return True

    # ── Verification ────────────────────────────────────────────────────────

    def verify_chain(self) -> bool:
        """
        Recompute every hash from genesis.  Returns False on any mismatch.
        Mirrors Lux AuditLog::verify_chain().
        """
        prev = bytes(32)
        for e in self._entries:
            h = hashlib.sha256()
            h.update(prev)
            h.update(_pack(
                e.seq, e.candidate_id, e.decision,
                e.confidence, e.policy_allowed, e.timestamp_ns,
            ))
            digest = h.digest()
            if digest.hex() != e.entry_hash:
                return False
            prev = digest
        return True

    # ── Accessors ───────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self._entries)

    def head_hash(self) -> str:
        return self._prev_hash.hex()

    def events(self) -> Iterator[AuditEntry]:
        return iter(self._entries)

    # ── Export ──────────────────────────────────────────────────────────────

    def to_json(self) -> dict:
        return {
            "audit_log": {
                "total_entries":     len(self._entries),
                "chain_valid":       self.verify_chain(),
                "head_hash":         self.head_hash(),
                "max_capacity":      MAX_AUDIT_EVENTS,
            },
            "entries": [asdict(e) for e in self._entries],
        }

    def save_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_json(), f, indent=2)

    def save_csv(self, path: str) -> None:
        if not self._entries:
            return
        fields = list(AuditEntry.__dataclass_fields__.keys())
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for e in self._entries:
                writer.writerow(asdict(e))
