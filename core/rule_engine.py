from datetime import datetime
from db import db
from models import Finding


# -------------------------
# CENTRAL RULE DEFINITIONS
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


# -------------------------
# FINDING BUILDER
# -------------------------
def make_finding(rule, service, resource_id):
    return {
        "dedup_key": f"{service}-{resource_id}-{rule['id']}",
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


# -------------------------
# SAVE TO DB (NEW FIX)
# -------------------------
def save_finding_to_db(f):

    existing = Finding.query.filter_by(dedup_key=f["dedup_key"]).first()

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


# -------------------------
# RULE ENGINE
# -------------------------
def evaluate_finding(resource_type, resource_id, attributes):
    findings = []

    for rule in RULES:

        if rule["resource_type"] != resource_type:
            continue

        # ---- S3 RULE ----
        if rule["id"] == "S3_PUBLIC_BUCKET":
            if attributes.get("public_access") == "public":
                findings.append(make_finding(rule, resource_type, resource_id))

        # ---- SG RULE ----
        if rule["id"] == "SG_OPEN_WORLD":
            inbound = attributes.get("inbound_rules", [])
            for r in inbound:
                if r.get("cidr") == "0.0.0.0/0":
                    findings.append(make_finding(rule, resource_type, resource_id))
                    break

        # ---- IAM RULE ----
        if rule["id"] == "IAM_STAR_ACTION":
            if attributes.get("is_action_star") is True:
                findings.append(make_finding(rule, resource_type, resource_id))

    return findings


# -------------------------
# BATCH EVALUATOR (FIXED)
# -------------------------
def evaluate_all(ec2_data=None, sg_data=None, s3_data=None, iam_data=None):

    all_findings = []

    # ---------------- S3 ----------------
    if s3_data:
        for bucket in s3_data.get("records", []):
            results = evaluate_finding(
                "s3",
                bucket.get("bucket_name"),
                {
                    "public_access": bucket.get("public_access")
                }
            )
            all_findings.extend(results)

    # ---------------- SG ----------------
    if sg_data:
        for sg in sg_data.get("records", []):
            results = evaluate_finding(
                "sg",
                sg.get("group_id"),
                {
                    "inbound_rules": sg.get("inbound_rules", [])
                }
            )
            all_findings.extend(results)

    # ---------------- IAM ----------------
    if iam_data:
        for iam in iam_data.get("records", []):
            results = evaluate_finding(
                "iam_policy",
                iam.get("policy_arn"),
                {
                    "is_action_star": iam.get("is_action_star", False)
                }
            )
            all_findings.extend(results)

    # ---------------- SAVE TO DB (CRITICAL FIX) ----------------
    for f in all_findings:
        save_finding_to_db(f)

    db.session.commit()

    return all_findings
