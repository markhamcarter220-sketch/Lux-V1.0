"""
audit_log.py — SHA-256 hash-chained audit log for lending decisions.

Wire format per entry (little-endian):
  SHA-256( prev_hash(32) || seq_le64 || aid_le32 || decision_u8
           || conf_f64_le || policy_u8 || ts_ns_le64 )

decision_u8  : 0x01 = APPROVE, 0x00 = DENY
policy_u8    : 0x01 = allowed, 0x00 = denied by policy gate
Genesis hash : 32 zero bytes
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import List

log = logging.getLogger(__name__)


def _pack(
    seq: int,
    aid: int,
    decision: str,
    conf: float,
    allowed: bool,
    ts_ns: int,
) -> bytes:
    return (
        struct.pack("<Q", seq)
        + struct.pack("<I", aid)
        + (b"\x01" if decision == "APPROVE" else b"\x00")
        + struct.pack("<d", conf)
        + (b"\x01" if allowed else b"\x00")
        + struct.pack("<Q", ts_ns)
    )


@dataclass
class AuditEntry:
    seq: int
    applicant_id: int
    decision: str
    confidence: float
    policy_allowed: bool
    policy_reason: str
    timestamp_ns: int
    entry_hash: str
    prev_hash: str


class AuditLog:
    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._head: bytes = b"\x00" * 32

    def append(
        self,
        applicant_id: int,
        decision: str,
        confidence: float,
        policy_allowed: bool,
        policy_reason: str,
    ) -> bool:
        try:
            seq = len(self._entries)
            ts_ns = time.time_ns()
            payload = _pack(seq, applicant_id, decision, confidence, policy_allowed, ts_ns)
            entry_hash = hashlib.sha256(self._head + payload).digest()
            entry = AuditEntry(
                seq=seq,
                applicant_id=applicant_id,
                decision=decision,
                confidence=confidence,
                policy_allowed=policy_allowed,
                policy_reason=policy_reason,
                timestamp_ns=ts_ns,
                entry_hash=entry_hash.hex(),
                prev_hash=self._head.hex(),
            )
            self._entries.append(entry)
            self._head = entry_hash
            return True
        except Exception as exc:
            log.error("AuditLog.append failed for applicant %d: %s", applicant_id, exc)
            return False

    def verify_chain(self) -> bool:
        prev = b"\x00" * 32
        for e in self._entries:
            payload = _pack(
                e.seq,
                e.applicant_id,
                e.decision,
                e.confidence,
                e.policy_allowed,
                e.timestamp_ns,
            )
            expected = hashlib.sha256(prev + payload).hexdigest()
            if expected != e.entry_hash:
                log.error(
                    "Chain broken at seq=%d applicant_id=%d", e.seq, e.applicant_id
                )
                return False
            prev = bytes.fromhex(e.entry_hash)
        return True

    def head_hash(self) -> str:
        return self._head.hex()

    def __len__(self) -> int:
        return len(self._entries)

    def save_json(self, path: str) -> None:
        data = [
            {
                "seq": e.seq,
                "applicant_id": e.applicant_id,
                "decision": e.decision,
                "confidence": e.confidence,
                "policy_allowed": e.policy_allowed,
                "policy_reason": e.policy_reason,
                "timestamp_ns": e.timestamp_ns,
                "entry_hash": e.entry_hash,
                "prev_hash": e.prev_hash,
            }
            for e in self._entries
        ]
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)

    def save_csv(self, path: str) -> None:
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=[
                    "seq",
                    "applicant_id",
                    "decision",
                    "confidence",
                    "policy_allowed",
                    "policy_reason",
                    "timestamp_ns",
                    "entry_hash",
                    "prev_hash",
                ],
            )
            writer.writeheader()
            for e in self._entries:
                writer.writerow(
                    {
                        "seq": e.seq,
                        "applicant_id": e.applicant_id,
                        "decision": e.decision,
                        "confidence": e.confidence,
                        "policy_allowed": e.policy_allowed,
                        "policy_reason": e.policy_reason,
                        "timestamp_ns": e.timestamp_ns,
                        "entry_hash": e.entry_hash,
                        "prev_hash": e.prev_hash,
                    }
                )
