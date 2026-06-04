"""
generate_data.py — Synthetic defendant profiles (150 defendants).

Model features (criminological, ECHR/Equal Protection-permissible):
  prior_convictions, age_at_arrest, employment_status,
  substance_abuse_history, family_support

Protected attributes (masked before any model call):
  race, gender, ethnicity, national_origin, disability

Proxy feature (also masked — known to correlate with race in COMPAS):
  prior_drug_convictions
"""

import json
import logging
import sys

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

SEED = 42
N = 150

RACE_VALUES = ["White", "Black", "Hispanic", "Asian", "Other"]
GENDER_VALUES = ["M", "F", "NB"]
ETHNICITY_VALUES = ["Non-Hispanic", "Hispanic", "Latino", "Other"]
NATIONAL_ORIGIN_VALUES = ["US", "Foreign-born"]


def generate_defendants(n: int = N, seed: int = SEED) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    # Criminological features — independent of protected attributes.
    prior_convictions = rng.integers(0, 11, n)
    age_at_arrest = rng.integers(18, 66, n)
    employment_status = rng.integers(0, 2, n)          # 0=unemployed, 1=employed
    substance_abuse_history = rng.integers(0, 2, n)   # 0=no, 1=yes
    family_support = rng.integers(0, 2, n)             # 0=no, 1=yes

    # Prior drug convictions — excluded from model (known COMPAS proxy for race).
    prior_drug_convictions = rng.integers(0, 6, n)

    # Protected attributes — sampled independently; zero correlation with features.
    race = rng.choice(RACE_VALUES, n, p=[0.44, 0.28, 0.18, 0.06, 0.04])
    gender = rng.choice(GENDER_VALUES, n, p=[0.49, 0.49, 0.02])
    ethnicity = rng.choice(ETHNICITY_VALUES, n, p=[0.55, 0.20, 0.20, 0.05])
    national_origin = rng.choice(NATIONAL_ORIGIN_VALUES, n, p=[0.86, 0.14])
    disability = rng.choice([True, False], n, p=[0.09, 0.91])

    df = pd.DataFrame({
        "defendant_id": range(1, n + 1),
        "prior_convictions": prior_convictions,
        "age_at_arrest": age_at_arrest,
        "employment_status": employment_status,
        "substance_abuse_history": substance_abuse_history,
        "family_support": family_support,
        "prior_drug_convictions": prior_drug_convictions,
        "race": race,
        "gender": gender,
        "ethnicity": ethnicity,
        "national_origin": national_origin,
        "disability": disability.tolist(),
    })
    return df


def main() -> int:
    try:
        df = generate_defendants()
        df.to_csv("output/defendants.csv", index=False)
        df.to_json("output/defendants.json", orient="records", indent=2)
        log.info("Generated %d defendant profiles → output/defendants.csv", len(df))
        return 0
    except Exception as exc:
        log.error("generate_data failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
