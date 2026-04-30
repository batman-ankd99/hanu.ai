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


# ---------------- SAFE FINDINGS EXTRACTOR ----------------
def extract_findings(obj):
    """
    Handles multiple possible response formats safely
    """
    if not obj:
        return []

    if isinstance(obj, list):
        return obj

    if isinstance(obj, dict):
        return (
            obj.get("data")
            or obj.get("findings")
            or obj.get("results")
            or []
        )

    return []


# ---------------- SAVE FINDINGS ----------------
def save_findings(findings):

    for f in findings:

        record = Finding(
            service=f.get("service"),
            resource_type=f.get("resource_type"),
            resource_id=f.get("resource_id"),
            finding=f.get("finding"),
            severity=f.get("severity"),
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

        # ---------------- DEBUG (VERY IMPORTANT) ----------------
        logging.info(f"SG OUTPUT: {sg}")
        logging.info(f"S3 OUTPUT: {s3}")

        # ---------------- FINDINGS ----------------
        all_findings = []

        sg_findings = extract_findings(sg)
        s3_findings = extract_findings(s3)

        all_findings.extend(sg_findings)
        all_findings.extend(s3_findings)

        logging.info(f"TOTAL FINDINGS TO SAVE: {len(all_findings)}")

        # ---------------- SAVE ----------------
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
