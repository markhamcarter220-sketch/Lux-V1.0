"""
policy_gate.py — Lux governance policy gate for recidivism risk assessments.

Three-layer fail-closed check:
  1. Exact match against PROTECTED_ATTRS
  2. Substring alias scan (catches race_category, gender_code, ethnic_group, etc.)
  3. Approved-feature allowlist

Prior drug convictions is explicitly blocked as a known racial proxy
(documented in COMPAS bias research, ProPublica 2016).
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Dict, Any

log = logging.getLogger(__name__)

PROTECTED_ATTRS: frozenset = frozenset({
    "race",
    "gender",
    "ethnicity",
    "national_origin",
    "disability",
    "prior_drug_convictions",   # racial proxy — blocked explicitly
})

_PROTECTED_SUBSTRINGS: tuple = (
    "race",
    "gender",
    "sex",
    "ethnic",
    "national_origin",
    "nationality",
    "disability",
    "handicap",
    "drug_conv",   # prior_drug_convictions alias pattern
    "religion",
    "color",
)

APPROVED_FEATURES: frozenset = frozenset({
    "prior_convictions",
    "age_at_arrest",
    "employment_status",
    "substance_abuse_history",
    "family_support",
})


@dataclasses.dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    reason: str
    violations: tuple = dataclasses.field(default_factory=tuple)


class PolicyGate:
    """Fail-closed feature filter for recidivism model inputs."""

    def check(self, features_used: Dict[str, Any]) -> PolicyResult:
        # Rule 1: exact match against protected set.
        protected_violations = [k for k in features_used if k in PROTECTED_ATTRS]
        if protected_violations:
            msg = f"Protected attribute(s) in features: {protected_violations}"
            log.warning("PolicyGate DENY — %s", msg)
            return PolicyResult(allowed=False, reason=msg,
                                violations=tuple(protected_violations))

        # Rule 2: alias / substring scan.
        alias_violations = [
            k for k in features_used
            if any(sub in k.lower() for sub in _PROTECTED_SUBSTRINGS)
        ]
        if alias_violations:
            msg = f"Alias of protected attribute detected: {alias_violations}"
            log.warning("PolicyGate DENY — %s", msg)
            return PolicyResult(allowed=False, reason=msg,
                                violations=tuple(alias_violations))

        # Rule 3: approved-feature allowlist.
        unknown = [k for k in features_used if k not in APPROVED_FEATURES]
        if unknown:
            msg = f"Unknown / unapproved feature(s): {unknown}"
            log.warning("PolicyGate DENY — %s", msg)
            return PolicyResult(allowed=False, reason=msg,
                                violations=tuple(unknown))

        return PolicyResult(
            allowed=True,
            reason="All features present in approved criminological set; "
                   "no protected attributes or racial proxies detected.",
            violations=(),
        )
