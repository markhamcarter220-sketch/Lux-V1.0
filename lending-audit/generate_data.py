"""
generate_data.py — Synthetic loan applicant data (200 applicants).

Financial features (model inputs):
  income, credit_score, employment_history, debt_to_income, collateral_value

Protected attributes (excluded from model, sampled independently):
  age, gender, race, marital_status, disability
"""

import json
import logging
import sys

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

SEED = 42
N = 200

GENDER_VALUES = ["M", "F", "NB"]
RACE_VALUES = ["White", "Black", "Hispanic", "Asian", "Other"]
MARITAL_VALUES = ["Single", "Married", "Divorced", "Widowed"]


def generate_applicants(n: int = N, seed: int = SEED) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    # Financial features — varied backgrounds and income levels.
    income = rng.uniform(30_000, 200_000, n).round(2)
    credit_score = rng.integers(300, 851, n)
    employment_history = rng.uniform(0, 40, n).round(1)
    debt_to_income = rng.uniform(0.05, 0.90, n).round(4)
    collateral_value = rng.uniform(0, 500_000, n).round(2)

    # Protected attributes — sampled independently, no correlation with financials.
    age = rng.integers(18, 76, n)
    gender = rng.choice(GENDER_VALUES, n, p=[0.48, 0.48, 0.04])
    race = rng.choice(
        RACE_VALUES, n, p=[0.60, 0.13, 0.18, 0.06, 0.03]
    )
    marital_status = rng.choice(MARITAL_VALUES, n, p=[0.35, 0.45, 0.15, 0.05])
    disability = rng.choice([True, False], n, p=[0.12, 0.88])

    df = pd.DataFrame(
        {
            "applicant_id": range(1, n + 1),
            "income": income,
            "credit_score": credit_score,
            "employment_history": employment_history,
            "debt_to_income": debt_to_income,
            "collateral_value": collateral_value,
            "age": age,
            "gender": gender,
            "race": race,
            "marital_status": marital_status,
            "disability": disability.tolist(),
        }
    )
    return df


def main() -> int:
    try:
        df = generate_applicants()
        df.to_csv("output/applicants.csv", index=False)
        df.to_json("output/applicants.json", orient="records", indent=2)
        log.info("Generated %d applicants → output/applicants.csv", len(df))
        return 0
    except Exception as exc:
        log.error("generate_data failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
