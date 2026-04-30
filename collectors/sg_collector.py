import boto3
from core.rule_engine import evaluate_finding


def collect_sg_data():
    """
    Collect Security Groups and run rule engine only.
    No DB writes here.
    """

    ec2_client = boto3.client("ec2")
    sg_response = ec2_client.describe_security_groups()

    findings = []

    for sg in sg_response.get("SecurityGroups", []):

        group_id = sg.get("GroupId")

        inbound_rules = []
        outbound_rules = []

        # ---------------- INBOUND ----------------
        for entry in sg.get("IpPermissions", []):
            for cidr in entry.get("IpRanges", []):
                inbound_rules.append({
                    "cidr": cidr.get("CidrIp")
                })

        # ---------------- OUTBOUND ----------------
        for entry in sg.get("IpPermissionsEgress", []):
            for cidr in entry.get("IpRanges", []):
                outbound_rules.append({
                    "cidr": cidr.get("CidrIp")
                })

        # ---------------- RULE ENGINE ----------------
        sg_findings = evaluate_finding(
            "sg",
            group_id,
            {
                "inbound_rules": inbound_rules,
                "outbound_rules": outbound_rules
            }
        )

        findings.extend(sg_findings)

    return {
        "status": "success",
        "count": len(sg_response.get("SecurityGroups", [])),
        "findings": len(findings),
        "data": findings   # 🔥 IMPORTANT: helps debugging/UI later
    }


if __name__ == "__main__":
    print(collect_sg_data())
