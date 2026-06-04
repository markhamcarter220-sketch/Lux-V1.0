"""
model.py — Decision tree hiring model.

INPUT:  Non-protected candidate features only.
OUTPUT: HIRE / REJECT decision with confidence score and feature provenance.

Protected attributes (age, gender, race) are explicitly stripped before any
model interaction — they never appear in X_train or X_predict.
"""

import json
import os
import traceback

from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import numpy as np

MODEL_FEATURES = [
    "years_experience",
    "education_level",
    "technical_skills",
    "communication_score",
    "problem_solving",
    "fit_score",
]

PROTECTED_ATTRS = ["age", "gender", "race"]

HIRE_THRESHOLD = 0.5   # probability >= threshold → HIRE


def extract_features(candidates):
    """Return feature matrix and candidate IDs; protected attrs are never included."""
    X, ids = [], []
    for c in candidates:
        row = [c[f] for f in MODEL_FEATURES]
        X.append(row)
        ids.append(c["candidate_id"])
    return np.array(X, dtype=float), ids


def synthesise_labels(X):
    """
    Create ground-truth labels from a deterministic scoring rule that uses
    only non-protected features.  This is the 'hiring manager proxy' the
    model learns from — it is transparent and auditable.

    Rule: score = 0.3*norm(years_exp) + 0.2*norm(edu) + 0.2*norm(tech)
                + 0.15*norm(comm) + 0.15*norm(ps)
    HIRE if score >= 0.5
    """
    years_exp = X[:, 0]
    edu       = X[:, 1]
    tech      = X[:, 2]
    comm      = X[:, 3]
    ps        = X[:, 4]
    # fit_score deliberately excluded from label-generation rule (intentional
    # demonstration that fit_score alone is not determinative).

    def norm(arr, lo, hi):
        return (arr - lo) / (hi - lo)

    score = (
        0.30 * norm(years_exp, 0, 30) +
        0.20 * norm(edu,       0,  4) +
        0.20 * norm(tech,      0, 100) +
        0.15 * norm(comm,      0, 100) +
        0.15 * norm(ps,        0, 100)
    )
    return (score >= 0.50).astype(int)


def train_model(X, y):
    """Train a shallow decision tree; returns fitted model and train/test split."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    clf = DecisionTreeClassifier(
        max_depth=4,
        min_samples_leaf=3,
        random_state=42,
    )
    clf.fit(X_train, y_train)
    return clf, X_train, X_test, y_train, y_test


def make_decisions(clf, candidates, X, ids):
    """Return a list of decision records for all 100 candidates."""
    proba = clf.predict_proba(X)          # shape (n, 2): [P(REJECT), P(HIRE)]
    preds = clf.predict(X)

    decisions = []
    for i, cid in enumerate(ids):
        c = candidates[i]
        hire_prob = float(proba[i, 1]) if proba.shape[1] > 1 else float(proba[i, 0])
        decision  = "HIRE" if preds[i] == 1 else "REJECT"

        decisions.append({
            "candidate_id":   cid,
            "decision":       decision,
            "hire_probability": round(hire_prob, 4),
            # Feature values used — protected attrs explicitly excluded
            "features_used": {f: c[f] for f in MODEL_FEATURES},
            # Protected attrs recorded for audit purposes only
            "protected_attrs_audit_only": {a: c[a] for a in PROTECTED_ATTRS},
        })
    return decisions


def run(candidates_path="output/candidates.json",
        decisions_path="output/model_decisions.json",
        report_path="output/model_report.txt"):
    try:
        with open(candidates_path) as f:
            candidates = json.load(f)
        print(f"Loaded {len(candidates)} candidates.")

        X, ids = extract_features(candidates)
        y = synthesise_labels(X)

        clf, X_train, X_test, y_train, y_test = train_model(X, y)

        # Evaluation report on held-out test set.
        y_pred = clf.predict(X_test)
        report = classification_report(y_test, y_pred, target_names=["REJECT", "HIRE"])

        os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
        with open(report_path, "w") as f:
            f.write("=== Decision Tree — Test Set Report ===\n\n")
            f.write(report)
            f.write("\n=== Tree Structure ===\n\n")
            f.write(export_text(clf, feature_names=MODEL_FEATURES))
        print("Model evaluation report written.")

        # Decisions for ALL 100 candidates.
        decisions = make_decisions(clf, candidates, X, ids)

        hire_count   = sum(1 for d in decisions if d["decision"] == "HIRE")
        reject_count = sum(1 for d in decisions if d["decision"] == "REJECT")
        print(f"Decisions: {hire_count} HIRE, {reject_count} REJECT "
              f"({hire_count/len(decisions)*100:.1f}% hire rate)")

        output = {
            "model": {
                "type":     "DecisionTreeClassifier",
                "max_depth": 4,
                "features":  MODEL_FEATURES,
                "protected_attrs_excluded": PROTECTED_ATTRS,
                "note": "Protected attributes (age, gender, race) were NEVER passed "
                        "to the model at train or predict time.",
            },
            "summary": {
                "total":        len(decisions),
                "hired":        hire_count,
                "rejected":     reject_count,
                "hire_rate_pct": round(hire_count / len(decisions) * 100, 1),
            },
            "decisions": decisions,
        }

        with open(decisions_path, "w") as f:
            json.dump(output, f, indent=2)
        print(f"Decisions written to {decisions_path}")

    except Exception:
        print("[ERROR] model.run() failed:")
        traceback.print_exc()


if __name__ == "__main__":
    run()
