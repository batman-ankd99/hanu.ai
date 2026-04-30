import boto3
import psycopg2
from datetime import datetime
from dotenv import load_dotenv
import os
import json

from core.rule_engine import evaluate_finding
from db_utils import get_db_connection


def collect_sg_data():
    """Collect AWS Security Group details and store findings properly."""

    load_dotenv(".env.prod")

    ec2_client = boto3.client("ec2")
    sg_response = ec2_client.describe_security_groups()

    sgs = []
    sg_live_list = []
    findings = []

    for sg in sg_response.get("SecurityGroups", []):

        group_id = sg["GroupId"]
        group_name = sg["GroupName"]
        description = sg.get("Description", "")
        scan_time = datetime.utcnow()

        inbound_rules = []
        outbound_rules = []

        # inbound
        for entry in sg.get("IpPermissions", []):
            for cidr in entry.get("IpRanges", []):
                inbound_rules.append({
                    "cidr": cidr["CidrIp"],
                    "protocol": entry.get("IpProtocol"),
                    "from_port": entry.get("FromPort"),
                    "to_port": entry.get("ToPort")
                })

        # outbound
        for entry in sg.get("IpPermissionsEgress", []):
            for cidr in entry.get("IpRanges", []):
                outbound_rules.append({
                    "cidr": cidr["CidrIp"],
                    "protocol": entry.get("IpProtocol"),
                    "from_port": entry.get("FromPort"),
                    "to_port": entry.get("ToPort")
                })

        sgs.append((
            group_id,
            group_name,
            description,
            json.dumps(inbound_rules),
            json.dumps(outbound_rules),
            scan_time
        ))

        sg_live_list.append(group_id)

        # rule engine
        sg_findings = evaluate_finding(
            "sg",
            group_id,
            {
                "inbound_rules": inbound_rules,
                "outbound_rules": outbound_rules
            }
        )

        findings.extend(sg_findings)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        print("✅ DB connected")

        # -------------------------
        # SECURITY GROUP TABLE
        # -------------------------
        insert_sg = """
        INSERT INTO security_groups
        (group_id, group_name, description, inbound_rules, outbound_rules, scan_time)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (group_id)
        DO UPDATE SET
            group_name = EXCLUDED.group_name,
            description = EXCLUDED.description,
            inbound_rules = EXCLUDED.inbound_rules,
            outbound_rules = EXCLUDED.outbound_rules,
            scan_time = EXCLUDED.scan_time;
        """

        for row in sgs:
            cursor.execute(insert_sg, row)

        # cleanup old SGs
        if sg_live_list:
            cursor.execute("""
                DELETE FROM security_groups
                WHERE group_id NOT IN %s
            """, (tuple(sg_live_list),))
        else:
            cursor.execute("DELETE FROM security_groups;")

        # -------------------------
        # FINDINGS INSERT (FIXED)
        # -------------------------
        insert_finding = """
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
        """

        for f in findings:
            cursor.execute(insert_finding, (
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

        print("✅ SG + findings inserted successfully")

    except Exception as e:
        print("❌ DB error:", e)

    finally:
        cursor.close()
        conn.close()

    return {
        "status": "success",
        "count": len(sgs),
        "findings": len(findings)
    }


if __name__ == "__main__":
    collect_sg_data()
