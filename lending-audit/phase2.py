"""
phase2.py — Phase 2+3 orchestrator: policy gate + audit log + bias tests.

Loads output/model_decisions.json produced by Phase 1.
For each decision:
  - Runs PolicyGate.check() on features_used
  - Appends to AuditLog
Verifies hash chain integrity.
Exports decisions.csv, audit_log.json, audit_log.csv, bias_report.txt.
"""

import csv
import json
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def main() -> int:
    try:
        from policy_gate import PolicyGate
        from audit_log import AuditLog
        from bias_test import run_bias_tests

        with open("output/model_decisions.json") as fh:
            decisions = json.load(fh)
        log.info("Loaded %d decisions", len(decisions))

        gate = PolicyGate()
        audit = AuditLog()

        rows = []
        all_allowed = True
        for d in decisions:
            pr = gate.check(d["features_used"])
            ok = audit.append(
                applicant_id=d["applicant_id"],
                decision=d["decision"],
                confidence=d["confidence"],
                policy_allowed=pr.allowed,
                policy_reason=pr.reason,
            )
            if not ok:
                log.error("Audit append failed for applicant %d", d["applicant_id"])
                return 1
            if not pr.allowed:
                all_allowed = False
                log.warning(
                    "PolicyGate DENY applicant=%d reason=%s",
                    d["applicant_id"],
                    pr.reason,
                )
            rows.append(
                {
                    "applicant_id": d["applicant_id"],
                    "decision": d["decision"],
                    "confidence": d["confidence"],
                    "policy_allowed": pr.allowed,
                    "policy_reason": pr.reason,
                }
            )

        # Verify chain integrity.
        if not audit.verify_chain():
            log.error("CRITICAL: Audit chain verification FAILED")
            return 1
        log.info(
            "Audit chain verified: %d entries, head=%s",
            len(audit),
            audit.head_hash()[:16] + "...",
        )

        if all_allowed:
            log.info("All %d decisions passed PolicyGate (ALLOW)", len(decisions))
        else:
            log.warning("Some decisions were blocked by PolicyGate — see audit log")

        # Write outputs.
        with open("output/decisions.csv", "w", newline="") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=[
                    "applicant_id",
                    "decision",
                    "confidence",
                    "policy_allowed",
                    "policy_reason",
                ],
            )
            writer.writeheader()
            writer.writerows(rows)

        audit.save_json("output/audit_log.json")
        audit.save_csv("output/audit_log.csv")
        log.info(
            "Wrote output/decisions.csv, output/audit_log.json, output/audit_log.csv"
        )

        # Phase 3: bias tests.
        log.info("=== Phase 3: Statistical bias tests ===")
        report = run_bias_tests("output/applicants.csv", "output/decisions.csv")
        with open("output/bias_report.txt", "w") as fh:
            fh.write(report + "\n")
        print(report)
        log.info("Wrote output/bias_report.txt")

        log.info("Phase 2+3 complete.")
        return 0

    except Exception as exc:
        log.error("phase2 failed: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
