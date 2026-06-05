"""
policy_gate.py — Thin Python wrapper around the Lux Kernel's PyPolicyGate.

The gate logic (three invariants, fail-closed) is implemented entirely in Rust
(src/python/policy.rs) and delegated via the lux_kernel.PyPolicyGate binding.

This wrapper:
  - Preserves the domain API used by phase2.py (check(features_used: dict)).
  - Converts the Rust gate's dict result to a PolicyResult dataclass.
  - Tracks per-session statistics (total_checks, allowed, denied) — this is
    observability only, not enforcement logic.

# What changed from the Python mock

- All three gate invariants (exact protected-attribute match, substring alias
  scan, unapproved feature check) now run in Rust.
- Denial reason strings are canonical static &'static str values from the kernel.
- The gate is now stateless for enforcement (statistics are tracked here).
- Unknown feature names passed at construction raise ValueError immediately
  (fail-closed at construction time, not silently ignored).

See docs/PYTHON_INTEGRATION.md for the full edge analysis and resolution map.
"""

from dataclasses import dataclass, field
from typing import List

from lux_kernel import PyPolicyGate  # Rust extension

# ── Constants (kept for backward compat / documentation) ─────────────────────

APPROVED_FEATURES: frozenset = frozenset({
    "years_experience",
    "education_level",
    "technical_skills",
    "communication_score",
    "problem_solving",
    "fit_score",
})

PROTECTED_ATTRS: frozenset = frozenset({"age", "gender", "race"})
_PROTECTED_SUBSTRINGS: tuple = ("age", "gender", "race", "ethnicity", "sex")


@dataclass
class PolicyResult:
    """Result of a policy gate check.  API-compatible with the old implementation."""
    allowed:    bool
    reason:     str
    violations: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        status = "ALLOW" if self.allowed else "DENY"
        return f"{status}: {self.reason}"


class PolicyGate:
    """
    Capability gate for hiring decisions, backed by the Lux Kernel's PyPolicyGate.

    Enforcement logic (invariants A, A2, B) runs in Rust.
    Statistics are tracked here for reporting.
    """

    def __init__(self) -> None:
        # Construct the Rust gate.  Both lists are validated against compile-time
        # static tables in the kernel; unknown strings raise ValueError here.
        self._inner = PyPolicyGate(
            approved_features=sorted(APPROVED_FEATURES),
            blocked_attrs=list(_PROTECTED_SUBSTRINGS),
        )
        self._checks = 0
        self._denied = 0

    def check(self, features_used: dict) -> PolicyResult:
        """
        Check the feature vector against the policy gate.

        Parameters
        ----------
        features_used : dict
            The feature dict for a hiring decision.  Only the keys are checked
            (values are not relevant to the gate).

        Returns
        -------
        PolicyResult
            .allowed   : True iff all invariants pass.
            .reason    : canonical reason string from the Rust kernel.
            .violations: list of offending feature names (if any).
        """
        self._checks += 1

        result = self._inner.check(list(features_used.keys()))
        allowed = result["allowed"]
        reason  = result["reason"]

        if not allowed:
            self._denied += 1
            # Extract violations from the reason (best-effort for backward compat).
            violations = [k for k in features_used.keys()
                          if not _is_approved(k)]
            return PolicyResult(allowed=False, reason=reason, violations=violations)

        return PolicyResult(allowed=True, reason=reason, violations=[])

    def stats(self) -> dict:
        return {
            "total_checks": self._checks,
            "allowed":      self._checks - self._denied,
            "denied":       self._denied,
        }


def _is_approved(name: str) -> bool:
    """True iff name is in APPROVED_FEATURES and has no protected-attr substring."""
    if name in PROTECTED_ATTRS:
        return False
    lower = name.lower()
    if any(sub in lower for sub in _PROTECTED_SUBSTRINGS):
        return False
    return name in APPROVED_FEATURES
