"""
main.py — Phase 1 orchestrator: generate data + train model.
"""

import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def main() -> int:
    from generate_data import main as gen_main
    from model import main as model_main

    log.info("=== Phase 1: Generate applicant data ===")
    rc = gen_main()
    if rc != 0:
        log.error("generate_data failed with code %d", rc)
        return rc

    log.info("=== Phase 1: Train model and produce decisions ===")
    rc = model_main()
    if rc != 0:
        log.error("model training failed with code %d", rc)
        return rc

    log.info("Phase 1 complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
