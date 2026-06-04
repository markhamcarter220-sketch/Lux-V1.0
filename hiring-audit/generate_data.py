"""
generate_data.py — Synthetic candidate profiles for AI hiring audit.

100 profiles with:
  - Non-protected features (used by model): years_experience, education_level,
    technical_skills, communication_score, problem_solving_score, fit_score
  - Protected attributes (recorded, NOT passed to model): age, gender, race

Education levels: 0=High School, 1=Associate, 2=Bachelor, 3=Master, 4=PhD
"""

import json
import csv
import random
import os

SEED = 42
random.seed(SEED)

GENDERS = ["male", "female", "non-binary"]
RACES   = ["white", "black", "hispanic", "asian", "other"]
EDUCATION_LABELS = {0: "high_school", 1: "associate", 2: "bachelor", 3: "master", 4: "phd"}

def clamp(val, lo, hi):
    return max(lo, min(hi, val))

def gauss_int(mu, sigma, lo, hi):
    return clamp(int(round(random.gauss(mu, sigma))), lo, hi)

def gauss_float(mu, sigma, lo, hi):
    return clamp(round(random.gauss(mu, sigma), 2), lo, hi)

def generate_candidate(candidate_id):
    # Protected attributes — intentionally NOT correlated with model features
    # (ensured by sampling them independently).
    age    = gauss_int(35, 10, 22, 65)
    gender = random.choice(GENDERS)
    race   = random.choice(RACES)

    # Non-protected model features — drawn from distributions that reflect
    # realistic variance, NOT systematically influenced by protected attrs.
    years_experience    = gauss_int(7, 5, 0, 30)
    education_level     = random.choices([0, 1, 2, 3, 4], weights=[5, 10, 40, 30, 15], k=1)[0]
    technical_skills    = gauss_float(65, 18, 0, 100)   # 0-100 score
    communication_score = gauss_float(70, 15, 0, 100)
    problem_solving     = gauss_float(68, 17, 0, 100)
    fit_score           = gauss_float(72, 14, 0, 100)

    return {
        # Identity
        "candidate_id": candidate_id,

        # Protected (audit-only, never passed to model)
        "age":    age,
        "gender": gender,
        "race":   race,

        # Model features
        "years_experience":    years_experience,
        "education_level":     education_level,
        "education_label":     EDUCATION_LABELS[education_level],
        "technical_skills":    technical_skills,
        "communication_score": communication_score,
        "problem_solving":     problem_solving,
        "fit_score":           fit_score,
    }


def generate_dataset(n=100):
    candidates = [generate_candidate(i + 1) for i in range(n)]

    # Verify demographic diversity.
    genders_seen = {c["gender"] for c in candidates}
    races_seen   = {c["race"]   for c in candidates}
    assert len(genders_seen) >= 2, "Insufficient gender diversity"
    assert len(races_seen)   >= 3, "Insufficient racial diversity"

    return candidates


def save_csv(candidates, path):
    if not candidates:
        return
    fieldnames = list(candidates[0].keys())
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(candidates)


def save_json(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


if __name__ == "__main__":
    os.makedirs("output", exist_ok=True)
    candidates = generate_dataset(100)
    save_csv(candidates, "output/candidates.csv")
    save_json(candidates, "output/candidates.json")
    print(f"Generated {len(candidates)} candidate profiles.")
    print(f"  Gender distribution: { {g: sum(1 for c in candidates if c['gender']==g) for g in GENDERS} }")
    print(f"  Race distribution:   { {r: sum(1 for c in candidates if c['race']==r) for r in RACES} }")
