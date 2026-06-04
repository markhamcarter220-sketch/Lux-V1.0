"""
policy_gate.py — Lux-inspired capability gate for hiring decisions.

Before any decision is finalised the gate verifies:
  1. No protected attribute appears in the feature vector.
  2. Every feature present is in the approved set.

ALLOW → decision may proceed.
DENY  → decision is blocked; audit entry records the reason.

This mirrors Lux Kernel's Invariant 2 (Capability-Gated): no operation
proceeds without a valid, scoped token.  Here the "token" is the assurance
that only approved features were used.
"""

from dataclasses import dataclass, field
from typing import List

PROTECTED_ATTRS: frozenset = frozenset({"age", "gender", "race"})

APPROVED_FEATURES: frozenset = frozenset({
    "years_experience",
    "education_level",
    "technical_skills",
    "communication_score",
    "problem_solving",
    "fit_score",
})


@dataclass
class PolicyResult:
    allowed: bool
    reason: str
    violations: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        status = "ALLOW" if self.allowed else "DENY"
        return f"{status}: {self.reason}"


class PolicyGate:
    """
    Stateless gate with accumulated statistics.
    Call check() for each decision; inspect stats() when done.
    """

    def __init__(self):
        self._checks = 0
        self._denied = 0

    def check(self, features_used: dict) -> PolicyResult:
        """
        Returns ALLOW if features_used contains only approved features and no
        protected attributes.  Returns DENY otherwise.
        """
        self._checks += 1

        # Invariant A: no protected attribute in the feature vector.
        protected_violations = [k for k in features_used if k in PROTECTED_ATTRS]
        if protected_violations:
            self._denied += 1
            return PolicyResult(
                allowed=False,
                reason=f"Protected attribute(s) detected in feature vector: {protected_violations}",
                violations=protected_violations,
            )

        # Invariant B: every key is in the approved feature set.
        unknown = [k for k in features_used if k not in APPROVED_FEATURES]
        if unknown:
            self._denied += 1
            return PolicyResult(
                allowed=False,
                reason=f"Unapproved feature(s) in decision vector: {unknown}",
                violations=unknown,
            )

        return PolicyResult(
            allowed=True,
            reason="All approved features present; no protected attributes",
            violations=[],
        )

    def stats(self) -> dict:
        return {
            "total_checks": self._checks,
            "allowed":      self._checks - self._denied,
            "denied":       self._denied,
        }
