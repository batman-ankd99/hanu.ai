from collectors.ec2_collector import collect_ec2_data
from collectors.sg_collector import collect_sg_data
from collectors.s3_collector import collect_s3_data
from collectors.iampolicy_collector import collect_iampolicy_data
from collectors.iampolicystatements_collector import collect_iampolicystatements_data
from collectors.iam_mfa_collector import collect_iam_mfa_data

from db import db
from models import Finding

import time
import logging

logging.basicConfig(level=logging.INFO)


# ---------------- SAVE FINDINGS ----------------
def save_findings(findings):
    """
    Stores SG + S3 findings in DB (SQLAlchemy).
    Dedup should be handled via DB constraint OR here.
    """

    for f in findings:

        record = Finding(
            service=f["service"],
            resource_type=f["resource_type"],
            resource_id=f["resource_id"],
            finding=f["finding"],
            severity=f["severity"],
            status=f.get("status", "open")
        )

        db.session.add(record)

    db.session.commit()


# ---------------- MAIN PIPELINE ----------------
def collect_all():

    try:
        start = time.time()
        logging.info("Starting data collection...")

        # ---------------- COLLECTORS ----------------
        ec2 = collect_ec2_data()
        sg = collect_sg_data()
        s3 = collect_s3_data()
        iam = collect_iampolicy_data()
        iam_stmt = collect_iampolicystatements_data()
        iam_mfa = collect_iam_mfa_data()

        # ---------------- FINDINGS PIPELINE ----------------
        all_findings = []

        # only rule-engine based outputs
        if sg.get("data"):
            all_findings.extend(sg["data"])

        if s3.get("data"):
            all_findings.extend(s3["data"])

        # ---------------- SAVE TO DB ----------------
        if all_findings:
            save_findings(all_findings)

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
        return {"status": "error", "message": str(e)}


if __name__ == "__main__":
    collect_all()
