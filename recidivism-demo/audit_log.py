"""
audit_log.py — SHA-256 hash-chained audit log for recidivism risk decisions.

Wire format per entry (little-endian):
  SHA-256( prev_hash(32) || seq_le64 || did_le32 || decision_u8
           || risk_f64_le || policy_u8 || ts_ns_le64 )

decision_u8 : 0x01 = RISK_HIGH, 0x00 = RISK_LOW
policy_u8   : 0x01 = allowed,   0x00 = denied by policy gate
Genesis     : 32 zero bytes
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import struct
import time
from dataclasses import dataclass
from typing import List

log = logging.getLogger(__name__)


def _pack(seq: int, did: int, decision: str, risk: float,
          allowed: bool, ts_ns: int) -> bytes:
    return (
        struct.pack("<Q", seq)
        + struct.pack("<I", did)
        + (b"\x01" if decision == "RISK_HIGH" else b"\x00")
        + struct.pack("<d", risk)
        + (b"\x01" if allowed else b"\x00")
        + struct.pack("<Q", ts_ns)
    )


@dataclass
class AuditEntry:
    seq: int
    defendant_id: int
    decision: str
    risk_score: float
    policy_allowed: bool
    policy_reason: str
    timestamp_ns: int
    entry_hash: str
    prev_hash: str


class AuditLog:
    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._head: bytes = b"\x00" * 32

    def append(self, defendant_id: int, decision: str, risk_score: float,
               policy_allowed: bool, policy_reason: str) -> bool:
        try:
            seq = len(self._entries)
            ts_ns = time.time_ns()
            payload = _pack(seq, defendant_id, decision, risk_score,
                            policy_allowed, ts_ns)
            entry_hash = hashlib.sha256(self._head + payload).digest()
            self._entries.append(AuditEntry(
                seq=seq,
                defendant_id=defendant_id,
                decision=decision,
                risk_score=risk_score,
                policy_allowed=policy_allowed,
                policy_reason=policy_reason,
                timestamp_ns=ts_ns,
                entry_hash=entry_hash.hex(),
                prev_hash=self._head.hex(),
            ))
            self._head = entry_hash
            return True
        except Exception as exc:
            log.error("AuditLog.append failed for defendant %d: %s", defendant_id, exc)
            return False

    def verify_chain(self) -> bool:
        prev = b"\x00" * 32
        for e in self._entries:
            payload = _pack(e.seq, e.defendant_id, e.decision, e.risk_score,
                            e.policy_allowed, e.timestamp_ns)
            expected = hashlib.sha256(prev + payload).hexdigest()
            if expected != e.entry_hash:
                log.error("Chain broken at seq=%d defendant_id=%d",
                          e.seq, e.defendant_id)
                return False
            prev = bytes.fromhex(e.entry_hash)
        return True

    def head_hash(self) -> str:
        return self._head.hex()

    def __len__(self) -> int:
        return len(self._entries)

    def save_json(self, path: str) -> None:
        data = [{
            "seq": e.seq,
            "defendant_id": e.defendant_id,
            "decision": e.decision,
            "risk_score": e.risk_score,
            "policy_allowed": e.policy_allowed,
            "policy_reason": e.policy_reason,
            "timestamp_ns": e.timestamp_ns,
            "entry_hash": e.entry_hash,
            "prev_hash": e.prev_hash,
        } for e in self._entries]
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)

    def save_csv(self, path: str) -> None:
        fieldnames = ["seq", "defendant_id", "decision", "risk_score",
                      "policy_allowed", "policy_reason",
                      "timestamp_ns", "entry_hash", "prev_hash"]
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for e in self._entries:
                writer.writerow({
                    "seq": e.seq, "defendant_id": e.defendant_id,
                    "decision": e.decision, "risk_score": e.risk_score,
                    "policy_allowed": e.policy_allowed,
                    "policy_reason": e.policy_reason,
                    "timestamp_ns": e.timestamp_ns,
                    "entry_hash": e.entry_hash,
                    "prev_hash": e.prev_hash,
                })
