from datetime import datetime

# -------------------------
# CENTRAL RULE DEFINITIONS
# -------------------------
RULES = [
    {
        "id": "S3_PUBLIC_BUCKET",
        "severity": "HIGH",
        "description": "S3 bucket is publicly accessible",
        "resource_type": "s3",
    },
    {
        "id": "SG_OPEN_WORLD",
        "severity": "HIGH",
        "description": "Security Group open to 0.0.0.0/0",
        "resource_type": "sg",
    },
    {
        "id": "IAM_STAR_ACTION",
        "severity": "CRITICAL",
        "description": "IAM policy allows wildcard actions (*)",
        "resource_type": "iam_policy",
    },
]


# -------------------------
# GENERIC EVALUATOR
# -------------------------
def evaluate_finding(resource_type, resource_id, attributes):
    findings = []

    for rule in RULES:

        if rule["resource_type"] != resource_type:
            continue

        # ---- S3 RULE ----
        if rule["id"] == "S3_PUBLIC_BUCKET":
            if attributes.get("public_access") == "public":
                findings.append(make_finding(rule, resource_id))

        # ---- SG RULE ----
        if rule["id"] == "SG_OPEN_WORLD":
            inbound = attributes.get("inbound_rules", [])
            for r in inbound:
                if r.get("cidr") == "0.0.0.0/0":
                    findings.append(make_finding(rule, resource_id))
                    break

        # ---- IAM RULE ----
        if rule["id"] == "IAM_STAR_ACTION":
            if attributes.get("is_action_star") is True:
                findings.append(make_finding(rule, resource_id))

    return findings


def make_finding(rule, resource_id):
    return {
        "rule_id": rule["id"],
        "severity": rule["severity"],
        "description": rule["description"],
        "resource_id": resource_id,
        "detected_at": datetime.utcnow()
    }

def evaluate_all(ec2_data=None, sg_data=None, s3_data=None, iam_data=None):
    findings = []

    # ---------------- S3 ----------------
    if s3_data:
        for bucket in s3_data.get("records", []):
            findings.extend(
                evaluate_finding(
                    "s3",
                    bucket.get("bucket_name"),
                    {
                        "public_access": bucket.get("public_access")
                    }
                )
            )

    # ---------------- SG ----------------
    if sg_data:
        for sg in sg_data.get("records", []):
            findings.extend(
                evaluate_finding(
                    "sg",
                    sg.get("group_id"),
                    {
                        "inbound_rules": sg.get("inbound_rules", [])
                    }
                )
            )

    # ---------------- IAM ----------------
    if iam_data:
        for iam in iam_data.get("records", []):
            findings.extend(
                evaluate_finding(
                    "iam_policy",
                    iam.get("policy_arn"),
                    {
                        "is_action_star": iam.get("is_action_star", False)
                    }
                )
            )

    return findings    
