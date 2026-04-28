import boto3
import psycopg2
from datetime import datetime
from dotenv import load_dotenv
import os
from db_utils import get_db_connection
from tabulate import tabulate
import uuid

def analytics_iam():

    findings = []
    conn = None
    cursor = None
    rows = []
    colnames = []

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        select_query = """
        SELECT
            s.id,
            s.effect,
            s.principal,
            s.actions,
            p.policy_name,
            p.attached_entities
        FROM iam_policy_statements AS s
        JOIN iam_policies AS p
            ON s.policy_arn = p.policy_arn
        WHERE (s.is_action_star = TRUE OR s.is_principal_star = TRUE)
          AND s.effect = 'Allow';
        """

        cursor.execute(select_query)
        rows = cursor.fetchall()
        colnames = [desc[0] for desc in cursor.description]

        print("\nPolicies that are at risk:")
        print(tabulate(rows, headers=colnames, tablefmt="psql"))

    except Exception as e:
        print("❌ Database operation failed:", e)

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    # ---------------- SAFE PROCESSING OUTSIDE TRY ----------------
    for row in rows:

        record = dict(zip(colnames, row))

        # severity logic
        if record.get("principal") == "*" and record.get("actions") == "*":
            severity = "CRITICAL"
        elif record.get("principal") == "*" or record.get("actions") == "*":
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        findings.append({
            "id": str(uuid.uuid4()),
            "service": "iam",
            "resource_type": "iam_policy",
            "resource_id": record.get("policy_name"),
            "finding": f"Policy allows overly permissive access (Principal: {record.get('principal')}, Actions: {record.get('actions')})",
            "severity": severity,
            "status": "OPEN",
            "recommendation": "Restrict '*' in Principal or Actions to least privilege",
            "created_at": datetime.utcnow().isoformat()
        })

    return {
        "status": "success",
        "count": len(findings),
        "findings": findings
    }


if __name__ == "__main__":
    analytics_iam()
