import boto3
import psycopg2
from datetime import datetime
from dotenv import load_dotenv
import os
import uuid
from db_utils import get_db_connection

def analytics_sg():

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        select_query = """
         SELECT
            group_id,
            group_name,
            inbound_rules,
            outbound_rules
         FROM security_groups
         WHERE
            inbound_rules @> '[{"cidr": "0.0.0.0/0"}]'::jsonb
            OR
            outbound_rules @> '[{"cidr": "0.0.0.0/0"}]'::jsonb
            OR
            inbound_rules @> '[{"protocol": "-1"}]'::jsonb
            OR
            outbound_rules @> '[{"protocol": "-1"}]'::jsonb;
        """

        cursor.execute(select_query)

        rows = cursor.fetchall()
        colnames = [desc[0] for desc in cursor.description]

        findings = []

        for row in rows:
            record = dict(zip(colnames, row))

            inbound = str(record.get("inbound_rules"))
            outbound = str(record.get("outbound_rules"))

            # 🔍 Determine severity
            if '"protocol": "-1"' in inbound or '"protocol": "-1"' in outbound:
                severity = "CRITICAL"
                issue = "Allows all protocols"
            elif '"0.0.0.0/0"' in inbound:
                severity = "HIGH"
                issue = "Open to world (inbound)"
            elif '"0.0.0.0/0"' in outbound:
                severity = "MEDIUM"
                issue = "Open to world (outbound)"
            else:
                severity = "LOW"
                issue = "Potential misconfiguration"

            # 🧩 Build finding
            finding = {
                "id": str(uuid.uuid4()),
                "service": "ec2",
                "resource_type": "security_group",
                "resource_id": record.get("group_id"),
                "finding": f"Security Group {record.get('group_name')} is risky: {issue}",
                "severity": severity,
                "status": "OPEN",
                "recommendation": "Restrict CIDR ranges and avoid allowing all protocols",
                "created_at": datetime.utcnow().isoformat()
            }

            findings.append(finding)

        return {
            "status": "success",
            "count": len(findings),
            "findings": findings
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()


# Allow direct run
if __name__ == "__main__":
    print(analytics_sg())
