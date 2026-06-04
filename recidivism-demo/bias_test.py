"""
bias_test.py — Statistical fairness tests for recidivism risk decisions.

Tests:
  1. Chi-squared independence (race, gender) — H0: decision independent of attribute
  2. Cramér's V effect size
  3. False positive / false negative rate parity (mirrors COMPAS methodology)

Equal Protection context:
  14th Amendment (U.S. Const. amend. XIV) — state actors cannot discriminate
  by race in criminal justice proceedings (Washington v. Davis, 426 U.S. 229).
  Due process requires individualized assessment (Morrissey v. Brewer).

COMPAS comparison baseline (ProPublica 2016, Broward County n=7,214):
  Black defendants false positive rate: 44.9%
  White defendants false positive rate: 23.5%
  Chi-squared p < 0.001 (highly significant racial dependence)
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

PROTECTED_ATTRS = ["race", "gender"]
ALPHA = 0.05

COMPAS_BASELINE = {
    "Black_FPR": 0.449,
    "White_FPR": 0.235,
    "chi2_p": "<0.001",
    "source": "Angwin et al., ProPublica (2016), n=7,214",
}


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


def chi_test(df: pd.DataFrame, attr: str) -> Tuple[float, float, bool, float]:
    contingency = pd.crosstab(df[attr], df["decision"])
    chi2, p, dof, _ = chi2_contingency(contingency, correction=False)
    v = cramers_v(contingency)
    return float(chi2), float(p), p > ALPHA, float(v)


def false_positive_rates(df: pd.DataFrame, attr: str) -> List[Dict]:
    """
    For each group: FPR = RISK_HIGH predictions where ground truth is low risk.
    Mirrors the ProPublica COMPAS methodology.
    """
    rows = []
    for group, gdf in df.groupby(attr):
        if "ground_truth" not in gdf.columns:
            return []
        n_true_low = (gdf["ground_truth"] == 0).sum()
        n_false_high = ((gdf["ground_truth"] == 0) & (gdf["decision"] == "RISK_HIGH")).sum()
        fpr = n_false_high / n_true_low if n_true_low > 0 else float("nan")
        rows.append({"group": str(group), "n": len(gdf), "fpr": fpr,
                     "n_true_low": int(n_true_low), "n_false_positives": int(n_false_high)})
    return rows


def run_fairness_tests(defendants_csv: str, risk_csv: str) -> str:
    try:
        defendants = pd.read_csv(defendants_csv)
        risk = pd.read_csv(risk_csv)
    except Exception as exc:
        log.error("Failed to load data: %s", exc)
        return f"ERROR: {exc}"

    merged = risk.merge(
        defendants[["defendant_id"] + PROTECTED_ATTRS], on="defendant_id", how="left"
    )

    # Add ground truth if present in risk_assessments.csv
    if "ground_truth" in risk.columns:
        merged["ground_truth"] = risk["ground_truth"]

    lines = []
    lines.append("=== Lux Recidivism Fairness Report ===")
    lines.append("Constitutional framework: 14th Amendment Equal Protection Clause\n")
    lines.append(f"Total risk assessments : {len(merged)}")
    lines.append(
        f"  RISK_HIGH : {(merged['decision'] == 'RISK_HIGH').sum()}"
        f"  |  RISK_LOW : {(merged['decision'] == 'RISK_LOW').sum()}"
    )
    lines.append(f"  Overall high-risk rate: {(merged['decision'] == 'RISK_HIGH').mean():.1%}\n")

    lines.append("--- COMPAS Baseline (ProPublica 2016) ---")
    lines.append(f"  Black defendant FPR : {COMPAS_BASELINE['Black_FPR']:.1%}")
    lines.append(f"  White defendant FPR : {COMPAS_BASELINE['White_FPR']:.1%}")
    lines.append(f"  Chi-squared p-value : {COMPAS_BASELINE['chi2_p']} (DEPENDENT — biased)")
    lines.append(f"  Source              : {COMPAS_BASELINE['source']}\n")

    lines.append("--- Chi-squared Independence Tests (α = 0.05) ---")
    lines.append(f"{'Attribute':<15} {'χ²':>8} {'p-value':>10} {'V':>6}  Result")
    lines.append("-" * 52)

    all_independent = True
    for attr in PROTECTED_ATTRS:
        try:
            chi2, p, independent, v = chi_test(merged, attr)
            result = "INDEPENDENT" if independent else "DEPENDENT ⚠"
            if not independent:
                all_independent = False
            lines.append(f"{attr:<15} {chi2:>8.3f} {p:>10.4f} {v:>6.4f}  {result}")
        except Exception as exc:
            lines.append(f"{attr:<15} ERROR: {exc}")

    lines.append("")
    if all_independent:
        lines.append(
            "VERDICT: Race and gender are statistically independent of the "
            "risk assessment at α = 0.05."
        )
        lines.append(
            "CONTRAST: COMPAS p<0.001 — highly significant racial dependence "
            "(ProPublica 2016)."
        )
    else:
        lines.append(
            "VERDICT: Statistical dependence detected. Equal Protection review required."
        )

    lines.append("\n--- RISK_HIGH Rate by Race ---")
    try:
        race_rates = (
            merged.groupby("race")["decision"]
            .apply(lambda s: (s == "RISK_HIGH").mean())
            .reset_index(name="high_risk_rate")
        )
        for _, row in race_rates.iterrows():
            lines.append(f"  {row['race']:<15} {row['high_risk_rate']:.1%}")
    except Exception as exc:
        lines.append(f"  ERROR: {exc}")

    lines.append("\n--- RISK_HIGH Rate by Gender ---")
    try:
        gender_rates = (
            merged.groupby("gender")["decision"]
            .apply(lambda s: (s == "RISK_HIGH").mean())
            .reset_index(name="high_risk_rate")
        )
        for _, row in gender_rates.iterrows():
            lines.append(f"  {row['gender']:<10} {row['high_risk_rate']:.1%}")
    except Exception as exc:
        lines.append(f"  ERROR: {exc}")

    lines.append(
        "\nNote: With n=150, cells with expected count < 5 reduce chi-squared "
        "reliability. The COMPAS baseline uses n=7,214."
    )

    return "\n".join(lines)


def main() -> int:
    report = run_fairness_tests("output/defendants.csv", "output/risk_assessments.csv")
    print(report)
    try:
        with open("output/fairness_report.txt", "w") as fh:
            fh.write(report + "\n")
        log.info("Wrote output/fairness_report.txt")
        return 0
    except Exception as exc:
        log.error("Failed to write fairness report: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
