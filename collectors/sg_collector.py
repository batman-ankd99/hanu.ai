import boto3
from datetime import datetime
from db_utils import get_db_connection
from core.rule_engine import evaluate_finding


def collect_sg_data():

    ec2_client = boto3.client("ec2")
    sg_response = ec2_client.describe_security_groups()

    findings = []

    for sg in sg_response.get("SecurityGroups", []):

        group_id = sg.get("GroupId")

        inbound_rules = []
        outbound_rules = []

        for entry in sg.get("IpPermissions", []):
            for cidr in entry.get("IpRanges", []):
                inbound_rules.append({
                    "cidr": cidr.get("CidrIp")
                })

        for entry in sg.get("IpPermissionsEgress", []):
            for cidr in entry.get("IpRanges", []):
                outbound_rules.append({
                    "cidr": cidr.get("CidrIp")
                })

        sg_findings = evaluate_finding(
            "sg",
            group_id,
            {
                "inbound_rules": inbound_rules,
                "outbound_rules": outbound_rules
            }
        )

        findings.extend(sg_findings)

    # ---------------- SAVE TO DB ----------------
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        print("DB connected")

        insert_query = """
        INSERT INTO findings (
            dedup_key,
            service,
            resource_type,
            resource_id,
            finding,
            severity,
            status,
            recommendation,
            created_at,
            updated_at
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,now(),now())
        ON CONFLICT (dedup_key) DO NOTHING;
        """

        for f in findings:
            cursor.execute(insert_query, (
                f["dedup_key"],
                f["service"],
                f["resource_type"],
                f["resource_id"],
                f["finding"],
                f["severity"],
                f.get("status", "open"),
                f.get("recommendation", "")
            ))

        conn.commit()

        print("SG findings saved (dedup enabled)")

    except Exception as e:
        print("DB error:", e)

    finally:
        cursor.close()
        conn.close()

    return {
        "status": "success",
        "count": len(findings),
        "findings": findings
    }
