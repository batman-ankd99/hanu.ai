from collectors.ec2_collector import collect_ec2_data
from collectors.sg_collector import collect_sg_data
from collectors.s3_collector import collect_s3_data
from collectors.iampolicy_collector import collect_iampolicy_data
from collectors.iampolicystatements_collector import collect_iampolicystatements_data
from collectors.iam_mfa_collector import collect_iam_mfa_data

from core.rule_engine import evaluate_all
from core.rule_engine import save_finding_to_db

from db import db

import time
import logging

logging.basicConfig(level=logging.INFO)


# ---------------- MAIN PIPELINE ----------------
def collect_all():

    try:
        start = time.time()
        logging.info("Starting data collection...")

        # ---------------- COLLECT AWS DATA ----------------
        ec2 = collect_ec2_data()
        sg = collect_sg_data()
        s3 = collect_s3_data()
        iam = collect_iampolicy_data()
        iam_stmt = collect_iampolicystatements_data()
        iam_mfa = collect_iam_mfa_data()

        # ---------------- RUN RULE ENGINE ----------------
        all_findings = evaluate_all(
            ec2_data=ec2,
            sg_data=sg,
            s3_data=s3,
            iam_data=iam
        )

        logging.info(f"TOTAL FINDINGS GENERATED: {len(all_findings)}")

        # ---------------- SAVE FINDINGS ----------------
        for f in all_findings:
            save_finding_to_db(f)

        db.session.commit()

        results = {
            "ec2": ec2,
            "sg": sg,
            "s3": s3,
            "iampolicy": iam,
            "iampolicy_statements": iam_stmt,
            "iam_mfa": iam_mfa
        }

        duration = round(time.time() - start, 2)
        logging.info(f"Collection complete in {duration}s")

        return {
            "status": "success",
            "details": results,
            "findings_count": len(all_findings)
        }

    except Exception as e:
        logging.error(f"Collector failed: {e}")
        db.session.rollback()
        return {
            "status": "error",
            "message": str(e)
        }


if __name__ == "__main__":
    print(collect_all())
