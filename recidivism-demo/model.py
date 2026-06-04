"""
model.py — Logistic regression recidivism risk model.

Trains on 5 criminological features only. Protected attributes — including
prior_drug_convictions (a known COMPAS proxy for race) — are never seen.

Output labels: RISK_HIGH / RISK_LOW
"""

import json
import logging
import sys

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import MinMaxScaler

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

MODEL_FEATURES = [
    "prior_convictions",
    "age_at_arrest",
    "employment_status",
    "substance_abuse_history",
    "family_support",
]
PROTECTED_ATTRS = [
    "race", "gender", "ethnicity", "national_origin",
    "disability", "prior_drug_convictions",
]
LABEL_COL = "high_risk"
RISK_THRESHOLD = 0.50

# Ground-truth scoring weights (criminological literature basis):
#   prior record > substance abuse > youth > unemployment > isolation
_WEIGHTS = {
    "prior_convictions": 0.35,
    "age_at_arrest_inv": 0.20,   # lower age → higher risk
    "employment_status_inv": 0.15,  # unemployed → higher risk
    "substance_abuse_history": 0.20,
    "family_support_inv": 0.10,   # no support → higher risk
}


def _build_labels(df: pd.DataFrame) -> np.ndarray:
    scaler = MinMaxScaler()
    normed = scaler.fit_transform(df[MODEL_FEATURES])
    n = pd.DataFrame(normed, columns=MODEL_FEATURES)
    score = (
        _WEIGHTS["prior_convictions"] * n["prior_convictions"]
        + _WEIGHTS["age_at_arrest_inv"] * (1.0 - n["age_at_arrest"])
        + _WEIGHTS["employment_status_inv"] * (1.0 - n["employment_status"])
        + _WEIGHTS["substance_abuse_history"] * n["substance_abuse_history"]
        + _WEIGHTS["family_support_inv"] * (1.0 - n["family_support"])
    )
    return (score >= RISK_THRESHOLD).astype(int).values


def train_and_predict(df: pd.DataFrame) -> dict:
    labels = _build_labels(df)
    df = df.copy()
    df[LABEL_COL] = labels

    X = df[MODEL_FEATURES].values
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    scaler = MinMaxScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    X_all_s = scaler.transform(X)

    clf = LogisticRegression(max_iter=1000, random_state=42, C=1.0)
    clf.fit(X_train_s, y_train)

    acc = clf.score(X_test_s, y_test)
    report = classification_report(y_test, clf.predict(X_test_s), output_dict=True)
    log.info("Test accuracy: %.1f%%", acc * 100)

    proba = clf.predict_proba(X_all_s)
    decisions = []
    for i, row in df.iterrows():
        risk_prob = float(proba[i][1])
        decision = "RISK_HIGH" if risk_prob >= RISK_THRESHOLD else "RISK_LOW"
        decisions.append({
            "defendant_id": int(row["defendant_id"]),
            "decision": decision,
            "risk_score": round(risk_prob, 6),
            "features_used": {f: float(row[f]) for f in MODEL_FEATURES},
        })

    n_high = sum(1 for d in decisions if d["decision"] == "RISK_HIGH")
    n_low = len(decisions) - n_high
    log.info("Decisions: %d RISK_HIGH / %d RISK_LOW", n_high, n_low)

    coef_map = {f: round(float(v), 6) for f, v in zip(MODEL_FEATURES, clf.coef_[0])}

    return {
        "decisions": decisions,
        "test_accuracy": round(acc, 4),
        "classification_report": report,
        "n_high": n_high,
        "n_low": n_low,
        "model_coefficients": coef_map,
    }


def main() -> int:
    try:
        df = pd.read_csv("output/defendants.csv")
        result = train_and_predict(df)

        with open("output/model_decisions.json", "w") as fh:
            json.dump(result["decisions"], fh, indent=2)

        with open("output/model_report.txt", "w") as fh:
            fh.write("=== Lux Recidivism Model — Phase 1 Report ===\n\n")
            fh.write(f"Total defendants : {len(result['decisions'])}\n")
            fh.write(f"RISK_HIGH        : {result['n_high']}\n")
            fh.write(f"RISK_LOW         : {result['n_low']}\n")
            fh.write(f"Test accuracy    : {result['test_accuracy'] * 100:.1f}%\n\n")
            fh.write("Logistic regression coefficients (scaled features):\n")
            for feat, coef in sorted(result["model_coefficients"].items(), key=lambda x: -abs(x[1])):
                fh.write(f"  {feat:<30} {coef:+.4f}\n")
            fh.write("\nClassification report (test set):\n")
            for label, vals in result["classification_report"].items():
                if isinstance(vals, dict):
                    fh.write(
                        f"  {label:<12} precision={vals['precision']:.2f}"
                        f"  recall={vals['recall']:.2f}"
                        f"  f1={vals['f1-score']:.2f}\n"
                    )
            fh.write("\nModel features (approved): " + ", ".join(MODEL_FEATURES) + "\n")
            fh.write("Protected attributes excluded: " + ", ".join(PROTECTED_ATTRS) + "\n")

        log.info("Wrote output/model_decisions.json and output/model_report.txt")
        return 0
    except Exception as exc:
        log.error("model.py failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
