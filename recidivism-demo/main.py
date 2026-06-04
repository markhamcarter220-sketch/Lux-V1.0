"""
main.py — Full orchestrator for the Lux Recidivism Risk Assessment Demo.

Phases:
  1. Generate 150 defendant profiles
  2. Train logistic regression, produce 150 risk decisions
  3. Run every decision through the policy gate
  4. Append all decisions to SHA-256 audit log; export 50-entry demo subset
  5. Run statistical fairness tests
"""

import csv
import json
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

AUDIT_DEMO_SIZE = 50   # first N decisions exported to audit_log.json


def main() -> int:
    try:
        # Phase 1: generate data.
        log.info("=== Phase 1: Generate defendant profiles ===")
        from generate_data import main as gen_main
        if gen_main() != 0:
            return 1

        # Phase 2: train model + predict.
        log.info("=== Phase 2: Train model and produce risk decisions ===")
        from model import main as model_main
        if model_main() != 0:
            return 1

        # Phase 3+4: policy gate + audit log.
        log.info("=== Phase 3: Policy gate + audit log ===")
        import pandas as pd
        from policy_gate import PolicyGate
        from audit_log import AuditLog
        from bias_test import run_fairness_tests

        with open("output/model_decisions.json") as fh:
            decisions = json.load(fh)
        defendants = pd.read_csv("output/defendants.csv")
        log.info("Loaded %d decisions", len(decisions))

        gate = PolicyGate()
        audit = AuditLog()

        rows = []
        all_allowed = True
        for d in decisions:
            pr = gate.check(d["features_used"])
            ok = audit.append(
                defendant_id=d["defendant_id"],
                decision=d["decision"],
                risk_score=d["risk_score"],
                policy_allowed=pr.allowed,
                policy_reason=pr.reason,
            )
            if not ok:
                log.error("Audit append failed for defendant %d", d["defendant_id"])
                return 1
            if not pr.allowed:
                all_allowed = False
                log.warning("PolicyGate DENY defendant=%d reason=%s",
                            d["defendant_id"], pr.reason)
            rows.append({
                "defendant_id": d["defendant_id"],
                "decision": d["decision"],
                "risk_score": d["risk_score"],
                "policy_allowed": pr.allowed,
                "policy_reason": pr.reason,
            })

        # Verify hash chain.
        if not audit.verify_chain():
            log.error("CRITICAL: Audit chain verification FAILED")
            return 1
        log.info("Audit chain verified: %d entries, head=%s...",
                 len(audit), audit.head_hash()[:16])

        if all_allowed:
            log.info("All %d decisions passed PolicyGate (ALLOW)", len(decisions))

        # Write risk_assessments.csv (all 150).
        with open("output/risk_assessments.csv", "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=[
                "defendant_id", "decision", "risk_score",
                "policy_allowed", "policy_reason",
            ])
            writer.writeheader()
            writer.writerows(rows)

        # Write audit_log.json — first 50 entries (demo subset).
        demo_log = AuditLog()
        for d in decisions[:AUDIT_DEMO_SIZE]:
            pr = gate.check(d["features_used"])
            demo_log.append(
                defendant_id=d["defendant_id"],
                decision=d["decision"],
                risk_score=d["risk_score"],
                policy_allowed=pr.allowed,
                policy_reason=pr.reason,
            )
        if not demo_log.verify_chain():
            log.error("CRITICAL: Demo audit chain verification FAILED")
            return 1
        demo_log.save_json("output/audit_log.json")
        demo_log.save_csv("output/audit_log.csv")
        log.info(
            "Wrote output/risk_assessments.csv (%d rows), "
            "output/audit_log.json (%d entries demo subset)",
            len(rows), AUDIT_DEMO_SIZE,
        )

        # Phase 5: fairness tests.
        log.info("=== Phase 5: Statistical fairness tests ===")
        report = run_fairness_tests("output/defendants.csv",
                                    "output/risk_assessments.csv")
        with open("output/fairness_report.txt", "w") as fh:
            fh.write(report + "\n")
        print(report)
        log.info("Wrote output/fairness_report.txt")

        log.info("Demo complete.")
        return 0

    except Exception as exc:
        log.error("main failed: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
