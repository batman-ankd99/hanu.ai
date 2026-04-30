from datetime import datetime
from db import db
from models import Finding


# -------------------------
# RULE DEFINITIONS
# -------------------------
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
        "recommendation": "Restrict inbound rules to specific IP ranges"
    },
    {
        "id": "IAM_STAR_ACTION",
        "severity": "CRITICAL",
        "description": "IAM policy allows wildcard actions (*)",
        "resource_type": "iam_policy",
        "recommendation": "Replace wildcard actions with least privilege permissions"
    },
]


# =========================================================
# INTERNAL ENGINE (CORE LOGIC)
# =========================================================
def _evaluate_finding_internal(resource_type, resource_id, attributes):
    findings = []

    for rule in RULES:

        if rule["resource_type"] != resource_type:
            continue

        # ---------------- S3 ----------------
        if rule["id"] == "S3_PUBLIC_BUCKET":
            if attributes.get("public_access") == "public":
                findings.append(_make_finding(rule, "s3", resource_id))

        # ---------------- SG ----------------
        elif rule["id"] == "SG_OPEN_WORLD":
            inbound = attributes.get("inbound_rules", [])
            for r in inbound:
                if r.get("cidr") == "0.0.0.0/0":
                    findings.append(_make_finding(rule, "sg", resource_id))
                    break

        # ---------------- IAM ----------------
        elif rule["id"] == "IAM_STAR_ACTION":
            if attributes.get("is_action_star"):
                findings.append(_make_finding(rule, "iam_policy", resource_id))

    return findings


# =========================================================
# BACKWARD COMPATIBILITY WRAPPER (IMPORTANT FIX)
# =========================================================
def evaluate_finding(resource_type, resource_id, attributes):
    """
    Used by collectors (SG/S3) → MUST NOT BREAK IMPORTS
    """
    return _evaluate_finding_internal(resource_type, resource_id, attributes)


# =========================================================
# FINDING BUILDER
# =========================================================
def _make_finding(rule, service, resource_id):
    return {
        "service": service,
        "resource_type": rule["resource_type"],
        "resource_id": resource_id,
        "finding": rule["description"],
        "severity": rule["severity"],
        "status": "open",
        "recommendation": rule.get("recommendation", ""),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }


# =========================================================
# DB SAVE
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

    record = Finding(
        service=f["service"],
        resource_type=f["resource_type"],
        resource_id=f["resource_id"],
        finding=f["finding"],
        severity=f["severity"],
        status=f["status"]
    )

    db.session.add(record)


# =========================================================
# MAIN SCAN ENGINE
# =========================================================
def evaluate_all(ec2_data=None, sg_data=None, s3_data=None, iam_data=None):

    all_findings = []

    # ---------------- SG ----------------
    if sg_data and sg_data.get("findings"):
        for sg in sg_data["findings"]:
            all_findings.extend(
                evaluate_finding(
                    "sg",
                    sg.get("resource_id"),
                    sg
                )
            )

    # ---------------- S3 ----------------
    if s3_data and s3_data.get("findings"):
        for bucket in s3_data["findings"]:
            all_findings.extend(
                evaluate_finding(
                    "s3",
                    bucket.get("resource_id"),
                    bucket
                )
            )

    # ---------------- IAM ----------------
    if iam_data and iam_data.get("iam_data"):
        for iam in iam_data["iam_data"]:
            all_findings.extend(
                evaluate_finding(
                    "iam_policy",
                    iam.get("policy_arn"),
                    iam
                )
            )

    # ---------------- SAVE ----------------
    for f in all_findings:
        save_finding_to_db(f)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    return all_findings
