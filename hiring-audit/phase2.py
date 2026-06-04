"""
phase2.py — Phase 2 orchestrator: policy gate + audit log + bias tests.

Steps:
  1. Load the 100 decisions from Phase 1 output.
  2. For each decision:
     a. Run PolicyGate.check(features_used) → ALLOW / DENY.
     b. Append to AuditLog (SHA-256 hash-chained).
  3. Export decisions.csv and audit_log.json / audit_log.csv.
  4. Verify audit chain integrity.
  5. Run statistical bias tests (chi-squared) on gender and race.
  6. Export bias_report.txt.

No panics: all errors caught and logged.
"""

import csv
import json
import os
import sys
import traceback
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))

import policy_gate as pg
import audit_log   as al
import bias_test   as bt

DECISIONS_IN  = "output/model_decisions.json"
DECISIONS_CSV = "output/decisions.csv"
AUDIT_JSON    = "output/audit_log.json"
AUDIT_CSV     = "output/audit_log.csv"
BIAS_REPORT   = "output/bias_report.txt"

MODEL_FEATURES = [
    "years_experience", "education_level", "technical_skills",
    "communication_score", "problem_solving", "fit_score",
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def load_decisions(path: str) -> list:
    with open(path) as f:
        data = json.load(f)
    return data["decisions"]


def write_decisions_csv(decisions: list, gate_results: list, path: str) -> None:
    fieldnames = (
        ["candidate_id", "decision", "confidence"]
        + MODEL_FEATURES
        + ["protected_age_masked", "protected_gender_masked", "protected_race_masked"]
        + ["policy_check_result"]
    )
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d, gr in zip(decisions, gate_results):
            row = {
                "candidate_id": d["candidate_id"],
                "decision":     d["decision"],
                "confidence":   d["hire_probability"],
            }
            for feat in MODEL_FEATURES:
                row[feat] = d["features_used"][feat]
            row["protected_age_masked"]    = "[MASKED]"
            row["protected_gender_masked"] = "[MASKED]"
            row["protected_race_masked"]   = "[MASKED]"
            row["policy_check_result"]     = "ALLOW" if gr.allowed else f"DENY: {gr.reason}"
            writer.writerow(row)


# ── Main ─────────────────────────────────────────────────────────────────────

def run_phase2() -> int:
    errors = []
    os.makedirs("output", exist_ok=True)

    # ── Step 1: Load Phase 1 decisions ───────────────────────────────────────
    try:
        decisions = load_decisions(DECISIONS_IN)
        print(f"[OK] Loaded {len(decisions)} decisions from Phase 1.")
    except Exception as exc:
        print(f"[FAIL] Could not load decisions: {exc}")
        traceback.print_exc()
        return 1

    # ── Step 2: Policy gate + audit log ──────────────────────────────────────
    gate = pg.PolicyGate()
    log  = al.AuditLog()

    gate_results = []
    append_failures = 0

    for d in decisions:
        try:
            result = gate.check(d["features_used"])
            gate_results.append(result)

            ok = log.append(
                candidate_id   = d["candidate_id"],
                decision       = d["decision"],
                confidence     = d["hire_probability"],
                policy_allowed = result.allowed,
                policy_reason  = result.reason,
            )
            if not ok:
                append_failures += 1
                errors.append(f"Audit log full at candidate {d['candidate_id']}")

        except Exception as exc:
            msg = f"[FAIL] Gate/audit for candidate {d.get('candidate_id')}: {exc}"
            errors.append(msg)
            print(msg)
            traceback.print_exc()

    gate_stats = gate.stats()
    print(f"[OK] Policy gate: {gate_stats['allowed']} ALLOW, "
          f"{gate_stats['denied']} DENY out of {gate_stats['total_checks']} checks.")
    print(f"[OK] Audit log: {len(log)} entries appended.")
    if append_failures:
        print(f"[WARN] {append_failures} append failure(s) (log capacity exceeded).")

    # ── Step 3: Export decisions.csv ─────────────────────────────────────────
    try:
        write_decisions_csv(decisions, gate_results, DECISIONS_CSV)
        print(f"[OK] {DECISIONS_CSV} written ({len(decisions)} rows).")
    except Exception as exc:
        msg = f"[FAIL] decisions.csv: {exc}"
        errors.append(msg)
        print(msg)
        traceback.print_exc()

    # ── Step 4: Export audit log ──────────────────────────────────────────────
    try:
        log.save_json(AUDIT_JSON)
        log.save_csv(AUDIT_CSV)
        print(f"[OK] {AUDIT_JSON} written.")
        print(f"[OK] {AUDIT_CSV} written.")
    except Exception as exc:
        msg = f"[FAIL] audit export: {exc}"
        errors.append(msg)
        print(msg)
        traceback.print_exc()

    # ── Step 5: Verify audit chain integrity ─────────────────────────────────
    try:
        chain_ok = log.verify_chain()
        if chain_ok:
            print(f"[OK] Hash chain verified ({len(log)} entries, head={log.head_hash()[:16]}…).")
        else:
            msg = "[FAIL] Hash chain verification FAILED — audit log may be tampered."
            errors.append(msg)
            print(msg)
    except Exception as exc:
        msg = f"[FAIL] verify_chain: {exc}"
        errors.append(msg)
        print(msg)
        traceback.print_exc()

    # ── Step 6: Statistical bias tests ───────────────────────────────────────
    try:
        bias_results = bt.run_all(decisions)
        report_text  = bt.format_report(bias_results)

        with open(BIAS_REPORT, "w") as f:
            f.write(report_text)

        print(f"[OK] {BIAS_REPORT} written.")
        print()
        print(report_text)

    except Exception as exc:
        msg = f"[FAIL] bias tests: {exc}"
        errors.append(msg)
        print(msg)
        traceback.print_exc()

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("── Phase 2 Summary ─────────────────────────────────────────────────")
    print(f"  Decisions processed : {len(decisions)}")
    print(f"  Audit entries       : {len(log)} / {len(decisions)}")
    print(f"  Chain intact        : {log.verify_chain()}")
    print(f"  Policy gate ALLOW   : {gate_stats['allowed']}")
    print(f"  Policy gate DENY    : {gate_stats['denied']}")

    if errors:
        print(f"\n  Errors ({len(errors)}):")
        for e in errors:
            print(f"    {e}")
        return 1

    print("\n  Phase 2 complete — no errors.")
    return 0


if __name__ == "__main__":
    sys.exit(run_phase2())
