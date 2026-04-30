import boto3


def collect_sg_data():
    """
    ONLY fetch AWS Security Groups.
    NO rule engine.
    NO DB writes.
    PURE data collector.
    """

    ec2_client = boto3.client("ec2")

    response = ec2_client.describe_security_groups()

    sg_data = []

    for sg in response.get("SecurityGroups", []):

        group_id = sg.get("GroupId")

        inbound_rules = []
        outbound_rules = []

        # ---------------- INBOUND RULES ----------------
        for entry in sg.get("IpPermissions", []):
            for cidr in entry.get("IpRanges", []):
                cidr_value = cidr.get("CidrIp")
                if cidr_value:
                    inbound_rules.append({"cidr": cidr_value})

        # ---------------- OUTBOUND RULES ----------------
        for entry in sg.get("IpPermissionsEgress", []):
            for cidr in entry.get("IpRanges", []):
                cidr_value = cidr.get("CidrIp")
                if cidr_value:
                    outbound_rules.append({"cidr": cidr_value})

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
