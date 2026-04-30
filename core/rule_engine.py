from datetime import datetime
from db import db
from models import Finding

# ---------------- RULES ----------------
RULES = [
    {
        "id": "S3_PUBLIC_BUCKET",
        "severity": "HIGH",
        "description": "S3 bucket is publicly accessible",
        "resource_type": "s3",
        "recommendation": "Block public access on S3 bucket"
    },
    {
        "id": "SG_OPEN_WORLD",
        "severity": "HIGH",
        "description": "Security Group open to 0.0.0.0/0",
        "resource_type": "sg",
        "recommendation": "Restrict inbound rules"
    },
    {
        "id": "IAM_STAR_ACTION",
        "severity": "CRITICAL",
        "description": "IAM policy allows wildcard actions (*)",
        "resource_type": "iam_policy",
        "recommendation": "Apply least privilege"
    }
]

# ---------------- FINDING FORMAT ----------------
def make_finding(rule, service, resource_id):
    return {
        "service": service,
        "resource_type": service,
        "resource_id": resource_id,
        "finding": rule["description"],
        "severity": rule["severity"],
        "status": "open",
        "recommendation": rule.get("recommendation", ""),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }


# =========================================================
# 1. REAL-TIME EVALUATION (USED BY COLLECTORS)
# =========================================================
def evaluate_finding(resource_type, resource_id, attributes):
    findings = []

    for rule in RULES:

        if rule["resource_type"] != resource_type:
            continue

        # ---------------- S3 ----------------
        if rule["id"] == "S3_PUBLIC_BUCKET":
            if attributes.get("public_access") == "public":
                findings.append(make_finding(rule, resource_type, resource_id))

        # ---------------- SG ----------------
        if rule["id"] == "SG_OPEN_WORLD":
            for r in attributes.get("inbound_rules", []):
                if r.get("cidr") == "0.0.0.0/0":
                    findings.append(make_finding(rule, resource_type, resource_id))
                    break

        # ---------------- IAM ----------------
        if rule["id"] == "IAM_STAR_ACTION":
            if attributes.get("is_action_star"):
                findings.append(make_finding(rule, resource_type, resource_id))

    return findings


# =========================================================
# 2. DB SAVE (DEDUP SAFE)
# =========================================================
def save_finding_to_db(f):

    existing = Finding.query.filter_by(
        service=f["service"],
        resource_type=f["resource_type"],
        resource_id=f["resource_id"],
        finding=f["finding"]
    ).first()

    if existing:
        return

    db.session.add(Finding(
        service=f["service"],
        resource_type=f["resource_type"],
        resource_id=f["resource_id"],
        finding=f["finding"],
        severity=f["severity"],
        status=f["status"]
    ))


# =========================================================
# 3. BATCH SCAN ENGINE (/scan)
# =========================================================
def evaluate_all(ec2_data=None, sg_data=None, s3_data=None, iam_data=None):

    all_findings = []

    # ---------------- S3 ----------------
    if s3_data:
        for bucket in s3_data.get("records", []):
            all_findings.extend(
                evaluate_finding(
                    "s3",
                    bucket.get("bucket_name"),
                    {"public_access": bucket.get("public_access")}
                )
            )

    # ---------------- SG ----------------
    if sg_data:
        for sg in sg_data.get("data", []):   # FIXED KEY
            all_findings.extend(
                evaluate_finding(
                    "sg",
                    sg.get("group_id"),
                    {"inbound_rules": sg.get("inbound_rules", [])}
                )
            )

    # ---------------- IAM ----------------
    if iam_data:
        for iam in iam_data.get("records", []):
            all_findings.extend(
                evaluate_finding(
                    "iam_policy",
                    iam.get("policy_arn"),
                    {"is_action_star": iam.get("is_action_star", False)}
                )
            )

    # ---------------- SAVE ----------------
    for f in all_findings:
        save_finding_to_db(f)

    db.session.commit()

    return all_findings
