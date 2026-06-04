"""
bias_test.py — Statistical fairness tests for lending decisions.

Tests:
  1. Chi-squared independence (scipy) for each protected attribute vs decision.
     H0: decision is independent of the protected attribute.
     α = 0.05. p > 0.05 → fail to reject H0 (independent).
  2. Cramér's V effect size.
  3. 4/5ths (80%) disparate impact rule (binary groups where applicable):
     approval_rate_group / approval_rate_best_group < 0.80 → flag.

Fair Lending context:
  ECOA (15 U.S.C. § 1691) — prohibits credit discrimination on protected bases.
  FHA  (42 U.S.C. § 3605) — prohibits discriminatory residential lending.
"""

from __future__ import annotations

import logging
import math
import sys
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy.stats import chi2_contingency

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

PROTECTED_ATTRS = ["age", "gender", "race", "marital_status", "disability"]
ALPHA = 0.05
DISPARATE_IMPACT_THRESHOLD = 0.80


def cramers_v(contingency: pd.DataFrame) -> float:
    chi2, _, _, _ = chi2_contingency(contingency, correction=False)
    n = contingency.values.sum()
    r, k = contingency.shape
    phi2 = chi2 / n
    phi2_corr = max(0, phi2 - (k - 1) * (r - 1) / (n - 1))
    r_corr = r - (r - 1) ** 2 / (n - 1)
    k_corr = k - (k - 1) ** 2 / (n - 1)
    denom = min(k_corr - 1, r_corr - 1)
    if denom <= 0:
        return 0.0
    return math.sqrt(phi2_corr / denom)


def chi_squared_test(
    df: pd.DataFrame, attr: str
) -> Tuple[float, float, bool, float]:
    contingency = pd.crosstab(df[attr], df["decision"])
    chi2, p, dof, expected = chi2_contingency(contingency, correction=False)
    independent = p > ALPHA
    v = cramers_v(contingency)
    return float(chi2), float(p), independent, float(v)


def disparate_impact(df: pd.DataFrame, attr: str) -> List[Dict]:
    """
    Compute approval rate per group and flag any group whose rate is
    < 80% of the best-performing group.
    """
    group_rates = (
        df.groupby(attr)["decision"]
        .apply(lambda s: (s == "APPROVE").mean())
        .reset_index(name="approval_rate")
    )
    best_rate = group_rates["approval_rate"].max()
    if best_rate == 0:
        return []
    group_rates["ratio"] = group_rates["approval_rate"] / best_rate
    group_rates["flagged"] = group_rates["ratio"] < DISPARATE_IMPACT_THRESHOLD
    return group_rates.to_dict("records")


def _add_age_band(df: pd.DataFrame) -> pd.DataFrame:
    """Map age → labelled decade band for the 4/5ths rule."""
    bins = [17, 24, 34, 44, 54, 64, 100]
    labels = ["18-24", "25-34", "35-44", "45-54", "55-64", "65+"]
    df = df.copy()
    df["age_band"] = pd.cut(df["age"], bins=bins, labels=labels)
    return df


def run_bias_tests(applicants_csv: str, decisions_csv: str) -> str:
    try:
        applicants = pd.read_csv(applicants_csv)
        decisions = pd.read_csv(decisions_csv)
    except Exception as exc:
        log.error("Failed to load data: %s", exc)
        return f"ERROR: {exc}"

    merged = decisions.merge(
        applicants[["applicant_id"] + PROTECTED_ATTRS], on="applicant_id", how="left"
    )
    merged = _add_age_band(merged)

    lines = []
    lines.append("=== Lux Lending Bias Report ===")
    lines.append(
        "Regulatory framework: ECOA (15 U.S.C. § 1691), FHA (42 U.S.C. § 3605)\n"
    )
    lines.append(f"Total decisions: {len(merged)}")
    lines.append(
        f"  APPROVE: {(merged['decision'] == 'APPROVE').sum()}"
        f"  |  DENY: {(merged['decision'] == 'DENY').sum()}"
    )
    lines.append(f"  Overall approval rate: {(merged['decision'] == 'APPROVE').mean():.1%}\n")

    lines.append("--- Chi-squared Independence Tests (α = 0.05) ---")
    lines.append(
        f"{'Attribute':<20} {'χ²':>8} {'p-value':>10} {'V':>6} {'Result'}"
    )
    lines.append("-" * 60)

    all_independent = True
    for attr in PROTECTED_ATTRS:
        try:
            chi2, p, independent, v = chi_squared_test(merged, attr)
            result = "INDEPENDENT" if independent else "DEPENDENT ⚠"
            if not independent:
                all_independent = False
            lines.append(
                f"{attr:<20} {chi2:>8.3f} {p:>10.4f} {v:>6.4f}  {result}"
            )
        except Exception as exc:
            lines.append(f"{attr:<20} ERROR: {exc}")

    lines.append("")
    if all_independent:
        lines.append(
            "VERDICT: All protected attributes are statistically independent "
            "of the credit decision at α = 0.05."
        )
    else:
        lines.append(
            "VERDICT: At least one protected attribute shows statistical dependence "
            "with the credit decision. Investigate before deployment."
        )

    lines.append("\n--- 4/5ths Disparate Impact Analysis ---")
    lines.append(f"Threshold: group approval rate / best group rate < {DISPARATE_IMPACT_THRESHOLD:.0%}")
    lines.append("(Age tested on 10-year bands; individual years have n<5 cells)\n")

    any_flagged = False
    disparate_attrs = [a if a != "age" else "age_band" for a in PROTECTED_ATTRS]
    for attr in disparate_attrs:
        display = "age (bands)" if attr == "age_band" else attr
        try:
            rows = disparate_impact(merged, attr)
            lines.append(f"  {display}:")
            for row in rows:
                flag = " ← FLAGGED" if row["flagged"] else ""
                lines.append(
                    f"    {str(row[attr]):<20} "
                    f"rate={row['approval_rate']:.1%}  "
                    f"ratio={row['ratio']:.3f}{flag}"
                )
                if row["flagged"]:
                    any_flagged = True
        except Exception as exc:
            lines.append(f"  {display}: ERROR — {exc}")
        lines.append("")

    if any_flagged:
        lines.append(
            "4/5ths VERDICT: One or more groups fall below the 80% threshold. "
            "ECOA/FHA disparate impact review recommended."
        )
    else:
        lines.append(
            "4/5ths VERDICT: All groups meet or exceed the 80% disparate impact threshold."
        )

    lines.append(
        "\nNote: Statistical tests on n=200 are indicative. "
        "Cells with expected count < 5 reduce chi-squared reliability."
    )

    return "\n".join(lines)


def main() -> int:
    report = run_bias_tests("output/applicants.csv", "output/decisions.csv")
    print(report)
    try:
        with open("output/bias_report.txt", "w") as fh:
            fh.write(report + "\n")
        log.info("Wrote output/bias_report.txt")
        return 0
    except Exception as exc:
        log.error("Failed to write bias report: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
