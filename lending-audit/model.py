"""
model.py — RandomForestClassifier for credit decisions.

Trains on 5 financial features only. Protected attributes are never seen
by the model. Ground-truth label: creditworthy if score >= 0.50.
"""

import json
import logging
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import MinMaxScaler

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

MODEL_FEATURES = [
    "income",
    "credit_score",
    "employment_history",
    "debt_to_income",
    "collateral_value",
]
PROTECTED_ATTRS = ["age", "gender", "race", "marital_status", "disability"]
LABEL_COL = "creditworthy"

# Scoring weights for ground-truth label generation.
_WEIGHTS = {
    "income": 0.30,
    "credit_score": 0.35,
    "employment_history": 0.15,
    "debt_to_income_inv": 0.10,   # lower DTI is better
    "collateral_value": 0.10,
}
APPROVE_THRESHOLD = 0.50


def _build_labels(df: pd.DataFrame) -> np.ndarray:
    scaler = MinMaxScaler()
    normed = scaler.fit_transform(df[MODEL_FEATURES])
    n_df = pd.DataFrame(normed, columns=MODEL_FEATURES)

    score = (
        _WEIGHTS["income"] * n_df["income"]
        + _WEIGHTS["credit_score"] * n_df["credit_score"]
        + _WEIGHTS["employment_history"] * n_df["employment_history"]
        + _WEIGHTS["debt_to_income_inv"] * (1.0 - n_df["debt_to_income"])
        + _WEIGHTS["collateral_value"] * n_df["collateral_value"]
    )
    return (score >= APPROVE_THRESHOLD).astype(int).values


def train_and_predict(df: pd.DataFrame) -> dict:
    labels = _build_labels(df)
    df = df.copy()
    df[LABEL_COL] = labels

    X = df[MODEL_FEATURES].values
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=6,
        min_samples_leaf=3,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    acc = clf.score(X_test, y_test)
    report = classification_report(y_test, clf.predict(X_test), output_dict=True)
    log.info("Test accuracy: %.1f%%", acc * 100)

    # Predict on all 200 applicants.
    proba = clf.predict_proba(X)
    decisions = []
    for i, row in df.iterrows():
        approve_prob = float(proba[i][1])
        decision = "APPROVE" if approve_prob >= 0.50 else "DENY"
        decisions.append(
            {
                "applicant_id": int(row["applicant_id"]),
                "decision": decision,
                "confidence": round(approve_prob, 6),
                "features_used": {f: float(row[f]) for f in MODEL_FEATURES},
            }
        )

    n_approve = sum(1 for d in decisions if d["decision"] == "APPROVE")
    n_deny = len(decisions) - n_approve
    log.info("Decisions: %d APPROVE / %d DENY", n_approve, n_deny)

    return {
        "decisions": decisions,
        "test_accuracy": round(acc, 4),
        "classification_report": report,
        "n_approve": n_approve,
        "n_deny": n_deny,
        "feature_importances": {
            f: round(float(v), 6)
            for f, v in zip(MODEL_FEATURES, clf.feature_importances_)
        },
    }


def main() -> int:
    try:
        df = pd.read_csv("output/applicants.csv")
        result = train_and_predict(df)

        with open("output/model_decisions.json", "w") as fh:
            json.dump(result["decisions"], fh, indent=2)

        with open("output/model_report.txt", "w") as fh:
            fh.write("=== Lux Credit Model — Phase 1 Report ===\n\n")
            fh.write(f"Total applicants : 200\n")
            fh.write(f"APPROVE          : {result['n_approve']}\n")
            fh.write(f"DENY             : {result['n_deny']}\n")
            fh.write(f"Test accuracy    : {result['test_accuracy'] * 100:.1f}%\n\n")
            fh.write("Feature importances (RandomForest):\n")
            for feat, imp in sorted(
                result["feature_importances"].items(), key=lambda x: -x[1]
            ):
                fh.write(f"  {feat:<25} {imp:.4f}\n")
            fh.write("\nClassification report (test set):\n")
            cr = result["classification_report"]
            for label, vals in cr.items():
                if isinstance(vals, dict):
                    fh.write(
                        f"  {label:<12} precision={vals['precision']:.2f}"
                        f"  recall={vals['recall']:.2f}"
                        f"  f1={vals['f1-score']:.2f}\n"
                    )
            fh.write("\nModel features used: " + ", ".join(MODEL_FEATURES) + "\n")
            fh.write("Protected attrs excluded: " + ", ".join(PROTECTED_ATTRS) + "\n")

        log.info(
            "Wrote output/model_decisions.json and output/model_report.txt"
        )
        return 0
    except Exception as exc:
        log.error("model.py failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
