"""
audit_log.py — Thin Python wrapper around the Lux Kernel's PyAuditLog.

The cryptographic core (SHA-256 hash-chain, verify_chain, append) is delegated
entirely to the Rust kernel via the lux_kernel.PyAuditLog binding.

This wrapper:
  - Preserves the domain API used by phase2.py (append with candidate fields).
  - Maintains a parallel Python list of domain entries for hiring-specific
    reporting (save_json / save_csv), since the kernel stores only governance
    events (kind, actor, timestamp, outcome, hash).
  - Delegates verify_chain() and the per-entry hash to the Rust kernel.

# What changed from the Python mock

- verify_chain() now runs in Rust using SHA-256 over the canonical kernel wire
  format (kind || actor || seq || ts || outcome || denial_class || denial_reason),
  NOT the old Python mock format (seq || cid || decision || conf || policy || ts).
- Every audit entry now includes the kernel's canonical SHA-256 hash in the
  "entry_hash" field of the JSON/CSV export.
- Capacity is still 512 events (MAX_AUDIT_EVENTS in src/types.rs).
- The "prev_hash" field is removed from per-entry exports; chain integrity is
  verified atomically by verify_chain() rather than per-entry.

See docs/PYTHON_INTEGRATION.md for the full edge analysis and resolution map.
"""

import csv
import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Iterator, List

from lux_kernel import PyAuditLog  # Rust extension


MAX_AUDIT_EVENTS = 512  # mirrors src/types.rs MAX_AUDIT_EVENTS


@dataclass
class AuditEntry:
    """Domain-enriched audit entry (hiring-specific fields + kernel hash)."""
    seq:            int
    candidate_id:   int
    decision:       str        # "HIRE" | "REJECT"
    confidence:     float
    policy_allowed: bool
    policy_reason:  str
    timestamp_ns:   int
    timestamp_iso:  str
    entry_hash:     str        # canonical SHA-256 from the Rust kernel (64 hex chars)


class AuditLog:
    """
    Hiring-domain audit log backed by the Lux Kernel's cryptographic AuditLog.

    The hash chain, verify_chain(), and entry_hash are all computed by the
    Rust kernel — no mock policy or audit logic is in the critical path.
    Domain fields (candidate_id, decision, confidence) are stored in a
    parallel Python list for reporting purposes only.
    """

    def __init__(self) -> None:
        self._inner  = PyAuditLog()          # Rust kernel — cryptographic core
        self._domain: List[AuditEntry] = []  # Python — hiring domain report data

    # ── Append ─────────────────────────────────────────────────────────────────

    def append(
        self,
        candidate_id:   int,
        decision:       str,
        confidence:     float,
        policy_allowed: bool,
        policy_reason:  str,
    ) -> bool:
        """
        Append one hiring-decision audit event.

        Translates the domain API into the kernel's governance API:
          - kind        = "hiring_decision"
          - actor       = candidate_id
          - timestamp   = time.time_ns()
          - denial      = ("halt", policy_reason) if not policy_allowed else None

        The policy_reason string must be one of the four canonical reason strings
        emitted by PyPolicyGate.check(); the Rust kernel maps it to a &'static str.

        Returns False at capacity (512 events); never raises.
        """
        ts_ns  = time.time_ns()
        ts_iso = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()

        denial_class  = None if policy_allowed else "halt"
        denial_reason = None if policy_allowed else policy_reason

        # Delegate cryptographic append to Rust kernel.
        ok = self._inner.append(
            kind          = "hiring_decision",
            actor         = candidate_id,
            timestamp     = ts_ns,
            denial_class  = denial_class,
            denial_reason = denial_reason,
        )

        if not ok:
            return False

        # Parse the kernel's latest event hash for the domain entry.
        # The kernel's export_json() returns all events; we take the last one.
        try:
            kernel_events = json.loads(self._inner.export_json())
            entry_hash = kernel_events[-1]["hash"] if kernel_events else "0" * 64
        except (json.JSONDecodeError, KeyError, IndexError):
            entry_hash = "0" * 64

        seq = len(self._domain) + 1
        self._domain.append(AuditEntry(
            seq            = seq,
            candidate_id   = candidate_id,
            decision       = decision,
            confidence     = round(confidence, 6),
            policy_allowed = policy_allowed,
            policy_reason  = policy_reason,
            timestamp_ns   = ts_ns,
            timestamp_iso  = ts_iso,
            entry_hash     = entry_hash,
        ))
        return True

    # ── Verification ───────────────────────────────────────────────────────────

    def verify_chain(self) -> bool:
        """
        Verify hash-chain integrity.  Delegates to the Rust kernel.

        Returns True iff every event's SHA-256 matches the expected value
        computed from the chain prefix.  Any mutation in any event field or
        hash is detected.
        """
        return self._inner.verify_chain()

    # ── Accessors ──────────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return self._inner.len()

    def head_hash(self) -> str:
        """64-char hex string of the most recent event's kernel hash."""
        return self._inner.head_hash()

    def events(self) -> Iterator[AuditEntry]:
        return iter(self._domain)

    # ── Export ─────────────────────────────────────────────────────────────────

    def to_json(self) -> dict:
        """
        Return a dict combining kernel metadata with domain-enriched entries.

        "entry_hash" in each entry is the Rust kernel's canonical SHA-256.
        "chain_valid" and "head_hash" are from verify_chain() / head_hash().
        """
        return {
            "audit_log": {
                "total_entries":  len(self._domain),
                "chain_valid":    self.verify_chain(),
                "head_hash":      self.head_hash(),
                "max_capacity":   MAX_AUDIT_EVENTS,
                "hash_format":    "SHA-256/Lux-kernel-canonical",
            },
            "entries": [asdict(e) for e in self._domain],
        }

    def save_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_json(), f, indent=2)

    def save_csv(self, path: str) -> None:
        if not self._domain:
            return
        fields = list(AuditEntry.__dataclass_fields__.keys())
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for e in self._domain:
                writer.writerow(asdict(e))
