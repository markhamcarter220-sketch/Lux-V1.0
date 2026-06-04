"""
main.py — Phase 1 orchestrator: generate candidates, run model, export results.

No panics: all failures are caught and logged cleanly.
"""

import sys
import os
import traceback

# Ensure we can import sibling modules regardless of cwd.
sys.path.insert(0, os.path.dirname(__file__))

import generate_data
import model as hiring_model


def run_phase1():
    errors = []

    # ── Step 1: Generate synthetic candidates ─────────────────────────────────
    try:
        os.makedirs("output", exist_ok=True)
        candidates = generate_data.generate_dataset(100)
        generate_data.save_csv(candidates, "output/candidates.csv")
        generate_data.save_json(candidates, "output/candidates.json")
        print(f"[OK] Generated {len(candidates)} candidate profiles.")

        gender_dist = {}
        race_dist   = {}
        for c in candidates:
            gender_dist[c["gender"]] = gender_dist.get(c["gender"], 0) + 1
            race_dist[c["race"]]     = race_dist.get(c["race"],   0) + 1
        print(f"     Gender: {gender_dist}")
        print(f"     Race:   {race_dist}")
        print(f"     Age range: {min(c['age'] for c in candidates)}–"
              f"{max(c['age'] for c in candidates)}")

    except Exception as exc:
        msg = f"[FAIL] Candidate generation: {exc}"
        errors.append(msg)
        print(msg)
        traceback.print_exc()
        candidates = None

    # ── Step 2: Train model and make decisions ─────────────────────────────────
    if candidates is not None:
        try:
            hiring_model.run(
                candidates_path="output/candidates.json",
                decisions_path="output/model_decisions.json",
                report_path="output/model_report.txt",
            )
        except Exception as exc:
            msg = f"[FAIL] Model run: {exc}"
            errors.append(msg)
            print(msg)
            traceback.print_exc()

    # ── Step 3: Summary ────────────────────────────────────────────────────────
    print()
    if errors:
        print(f"Phase 1 completed with {len(errors)} error(s):")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)
    else:
        print("Phase 1 complete. Output files:")
        for name in ["output/candidates.csv", "output/candidates.json",
                     "output/model_decisions.json", "output/model_report.txt"]:
            size = os.path.getsize(name) if os.path.exists(name) else 0
            print(f"  {name}  ({size:,} bytes)")


if __name__ == "__main__":
    run_phase1()
