import boto3


def collect_sg_data():
    """
    ONLY fetch AWS Security Groups.
    NO rule engine.
    NO DB writes.
    """

    ec2_client = boto3.client("ec2")
    sg_response = ec2_client.describe_security_groups()

    sg_data = []

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

        sg_data.append({
            "group_id": group_id,
            "inbound_rules": inbound_rules,
            "outbound_rules": outbound_rules
        })

    return {
        "status": "success",
        "count": len(sg_data),
        "data": sg_data
    }


if __name__ == "__main__":
    print(collect_sg_data())
