"""
policy_gate.py — Lux governance policy gate for lending decisions.

Three-layer fail-closed check (mirrors hiring policy_gate.py):
  1. Exact match against PROTECTED_ATTRS
  2. Substring alias scan (catches income_age_adj, disability_flag, etc.)
  3. Approved-feature allowlist

Any violation → DENY with reason logged. Fail-closed: unknown feature = block.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Dict, Any

log = logging.getLogger(__name__)

PROTECTED_ATTRS: frozenset = frozenset(
    {"age", "gender", "race", "marital_status", "disability"}
)

_PROTECTED_SUBSTRINGS: tuple = (
    "age",
    "gender",
    "race",
    "ethnicity",
    "sex",
    "marital",
    "disability",
    "handicap",
)

APPROVED_FEATURES: frozenset = frozenset(
    {
        "income",
        "credit_score",
        "employment_history",
        "debt_to_income",
        "collateral_value",
    }
)


@dataclasses.dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    reason: str
    violations: tuple = dataclasses.field(default_factory=tuple)


class PolicyGate:
    """Fail-closed feature filter for lending model inputs."""

    def check(self, features_used: Dict[str, Any]) -> PolicyResult:
        # Rule 1: exact match.
        protected_violations = [k for k in features_used if k in PROTECTED_ATTRS]
        if protected_violations:
            msg = f"Protected attribute(s) in features: {protected_violations}"
            log.warning("PolicyGate DENY — %s", msg)
            return PolicyResult(
                allowed=False,
                reason=msg,
                violations=tuple(protected_violations),
            )

        # Rule 2: alias / substring scan.
        alias_violations = [
            k
            for k in features_used
            if any(sub in k.lower() for sub in _PROTECTED_SUBSTRINGS)
        ]
        if alias_violations:
            msg = f"Alias of protected attribute detected: {alias_violations}"
            log.warning("PolicyGate DENY — %s", msg)
            return PolicyResult(
                allowed=False,
                reason=msg,
                violations=tuple(alias_violations),
            )

        # Rule 3: approved-feature allowlist.
        unknown = [k for k in features_used if k not in APPROVED_FEATURES]
        if unknown:
            msg = f"Unknown / unapproved feature(s): {unknown}"
            log.warning("PolicyGate DENY — %s", msg)
            return PolicyResult(
                allowed=False,
                reason=msg,
                violations=tuple(unknown),
            )

        return PolicyResult(
            allowed=True,
            reason=(
                "All features present in approved set; "
                "no protected attributes detected."
            ),
            violations=(),
        )
