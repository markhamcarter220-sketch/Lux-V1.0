"""
bias_test.py — Statistical independence tests for hiring decisions.

Null hypothesis: decision (HIRE/REJECT) is independent of the protected
attribute.  We test gender and race separately using:

  - Chi-squared test of independence (scipy.stats.chi2_contingency).
  - Fisher's exact test for 2×2 tables (gender binary: female vs. non-female).
  - Cramér's V as effect-size measure.

p > 0.05 → fail to reject H₀ → decisions appear statistically independent
            of the protected attribute at the 5% significance level.

NOTE: With n=100 some expected cell counts may be < 5.  Where that occurs
we note it in the report (chi-squared approximation is less reliable).
"""

import math
import traceback
from typing import Dict, List

try:
    from scipy.stats import chi2_contingency, fisher_exact
    import numpy as np
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


ALPHA = 0.05


def _contingency_table(decisions: List[dict], attr: str) -> Dict[str, Dict[str, int]]:
    table: Dict[str, Dict[str, int]] = {}
    for d in decisions:
        val = d["protected_attrs_audit_only"][attr]
        table.setdefault(val, {"HIRE": 0, "REJECT": 0})
        table[val][d["decision"]] += 1
    return table


def _cramers_v(chi2: float, n: int, r: int, c: int) -> float:
    """Cramér's V: effect size for chi-squared.  r=rows, c=cols."""
    denom = n * (min(r, c) - 1)
    return math.sqrt(chi2 / denom) if denom > 0 else 0.0


def test_attribute(decisions: List[dict], attr: str) -> dict:
    table = _contingency_table(decisions, attr)
    groups = sorted(table.keys())
    matrix = [[table[g]["HIRE"], table[g]["REJECT"]] for g in groups]
    n      = sum(sum(row) for row in matrix)

    result = {
        "attribute":   attr,
        "groups":      {g: table[g] for g in groups},
        "n":           n,
        "chi2":        None,
        "p_value":     None,
        "dof":         None,
        "cramers_v":   None,
        "independent": None,
        "fisher_p":    None,
        "note":        "",
        "error":       None,
    }

    if not SCIPY_AVAILABLE:
        result["error"] = "scipy not installed; skipping statistical tests"
        return result

    try:
        chi2, p, dof, expected = chi2_contingency(matrix)
        result["chi2"]      = round(float(chi2), 4)
        result["p_value"]   = round(float(p),    6)
        result["dof"]       = int(dof)
        result["cramers_v"] = round(_cramers_v(chi2, n, len(matrix), 2), 4)
        result["independent"] = bool(p > ALPHA)

        # Warn if expected counts < 5 (chi-squared approximation less reliable).
        low_cells = int((np.array(expected) < 5).sum())
        if low_cells:
            result["note"] = (
                f"{low_cells} expected cell(s) < 5; chi-squared approximation "
                "may be unreliable. Fisher's exact test recommended for 2×2."
            )

        # Fisher's exact (only meaningful for 2×2 — binary attribute).
        if len(matrix) == 2:
            _, fp = fisher_exact(matrix)
            result["fisher_p"] = round(float(fp), 6)

    except Exception as exc:
        result["error"] = str(exc)
        traceback.print_exc()

    return result


def run_all(decisions: List[dict]) -> List[dict]:
    return [
        test_attribute(decisions, "gender"),
        test_attribute(decisions, "race"),
    ]


def format_report(results: List[dict]) -> str:
    lines = ["=== Bias Independence Report ===", ""]
    lines.append(f"Significance level: α = {ALPHA}")
    lines.append(f"H₀: hiring decision is INDEPENDENT of the protected attribute.")
    lines.append("")

    for r in results:
        attr = r["attribute"].upper()
        lines.append(f"── {attr} ──────────────────────────────────────")
        lines.append(f"  n = {r['n']}")

        # Contingency table
        lines.append(f"  {'Group':<14}  HIRE  REJECT  hire%")
        for grp, counts in sorted(r["groups"].items()):
            total = counts["HIRE"] + counts["REJECT"]
            rate  = counts["HIRE"] / total * 100 if total else 0
            lines.append(f"  {grp:<14}  {counts['HIRE']:4d}   {counts['REJECT']:4d}  "
                         f"{rate:5.1f}%")
        lines.append("")

        if r["error"]:
            lines.append(f"  ERROR: {r['error']}")
        elif r["chi2"] is not None:
            lines.append(f"  Chi-squared: χ²={r['chi2']:.4f}  df={r['dof']}  "
                         f"p={r['p_value']:.6f}")
            lines.append(f"  Cramér's V:  {r['cramers_v']:.4f}  "
                         f"(0=none, 0.1=small, 0.3=medium, 0.5=large)")
            if r["fisher_p"] is not None:
                lines.append(f"  Fisher exact p: {r['fisher_p']:.6f}")
            verdict = "INDEPENDENT (fail to reject H₀)" if r["independent"] else \
                      "DEPENDENT (reject H₀) — POTENTIAL BIAS DETECTED"
            lines.append(f"  Verdict: {verdict}")
            if r["note"]:
                lines.append(f"  Note: {r['note']}")
        lines.append("")

    # Overall verdict
    all_ind = all(r["independent"] for r in results if r["independent"] is not None)
    lines.append("── OVERALL ─────────────────────────────────────")
    if all_ind:
        lines.append("  All tested attributes: decisions appear statistically")
        lines.append("  independent of protected characteristics at α=0.05.")
    else:
        flagged = [r["attribute"] for r in results if r["independent"] is False]
        lines.append(f"  WARNING: potential bias detected for: {flagged}")
    lines.append("")

    return "\n".join(lines)
