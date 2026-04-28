import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os
from db_utils import get_db_connection
from tabulate import tabulate
import uuid

def analytics_iam():

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

        # Execute the query
        cursor.execute(select_query)

        # Fetch all rows
        rows = cursor.fetchall() #all rows fetched from select query are brought into python memory, as a tuple
        colnames = [desc[0] for desc in cursor.description] #after query, cursor.description gives metadata about each returned column, so desc[0] only fetches column name
        #its a list of tuples - (('id', ...), ('effect', ...), ('principal', ...), ('actions', ...), ...)

        print("\nPolicies that are at risk, opening star in either principal or Action:")
        print(tabulate(rows, headers=colnames, tablefmt="psql"))

    except Exception as e:
        print("❌ Database operation failed:", e)

    # Cleanup
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
    findings = []
    for row in rows:
    record = dict(zip(colnames, row))

    # Determine severity
    if record.get("principal") == "*" and record.get("actions") == "*":
        severity = "CRITICAL"
    elif record.get("principal") == "*" or record.get("actions") == "*":
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    finding = {
        "id": str(uuid.uuid4()),
        "service": "iam",
        "resource_type": "iam_policy",
        "resource_id": record.get("policy_name"),
        "finding": f"Policy allows overly permissive access (Principal: {record.get('principal')}, Actions: {record.get('actions')})",
        "severity": severity,
        "status": "OPEN",
        "recommendation": "Restrict '*' in Principal or Actions to least privilege",
        "created_at": datetime.utcnow().isoformat()
    }

    findings.append(finding)

    return {
    "status": "success",
    "count": len(findings),
    "findings": findings
    }


# Allow direct run
if __name__ == "__main__":
    analytics_iam()
