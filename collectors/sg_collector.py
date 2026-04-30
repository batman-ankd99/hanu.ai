import boto3
from datetime import datetime
from core.rule_engine import evaluate_finding


def collect_sg_data():

    ec2_client = boto3.client("ec2")
    sg_response = ec2_client.describe_security_groups()

    results = []

    for sg in sg_response.get("SecurityGroups", []):

        group_id = sg["GroupId"]

        inbound_rules = []
        outbound_rules = []

        for entry in sg.get("IpPermissions", []):
            for cidr in entry.get("IpRanges", []):
                inbound_rules.append({
                    "cidr": cidr["CidrIp"]
                })

        for entry in sg.get("IpPermissionsEgress", []):
            for cidr in entry.get("IpRanges", []):
                outbound_rules.append({
                    "cidr": cidr["CidrIp"]
                })

        # ONLY RULE ENGINE (NO DB HERE)
        results.extend(
            evaluate_finding(
                "sg",
                group_id,
                {
                    "inbound_rules": inbound_rules,
                    "outbound_rules": outbound_rules
                }
            )
        )

    return {
        "status": "success",
        "count": len(sg_response.get("SecurityGroups", [])),
        "findings": len(results)
    }


if __name__ == "__main__":
    collect_sg_data()
