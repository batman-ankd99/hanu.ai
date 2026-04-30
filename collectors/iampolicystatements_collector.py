import boto3
from datetime import datetime
import json
from psycopg2.extras import Json
from db_utils import get_db_connection


def collect_iampolicystatements_data():
    """
    Collect IAM policy statements and store in PostgreSQL.
    Clean, safe, and consistent collector.
    """

    iam = boto3.client("iam")

    # ---------------- LIST POLICIES ----------------
    response = iam.list_policies(Scope="Local")
    policies = response.get("Policies", [])

    policy_arns = [p.get("Arn") for p in policies if p.get("Arn")]

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        print("DB connected")

    except Exception as e:
        print("DB connection failed:", e)
        return {"status": "db_failed"}

    insert_query = """
        INSERT INTO iam_policy_statements
        (
            policy_arn,
            policy_name,
            statement_id,
            effect,
            principal,
            is_principal_star,
            is_action_star,
            actions,
            resources,
            conditions,
            raw_statement,
            scan_time
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (policy_arn, statement_id)
        DO UPDATE SET
            policy_name = EXCLUDED.policy_name,
            effect = EXCLUDED.effect,
            principal = EXCLUDED.principal,
            is_principal_star = EXCLUDED.is_principal_star,
            is_action_star = EXCLUDED.is_action_star,
            actions = EXCLUDED.actions,
            resources = EXCLUDED.resources,
            conditions = EXCLUDED.conditions,
            raw_statement = EXCLUDED.raw_statement,
            scan_time = EXCLUDED.scan_time;
    """

    count = 0

    try:
        for policy_arn in policy_arns:

            try:
                policy_detail = iam.get_policy(PolicyArn=policy_arn)
                policy_name = policy_detail["Policy"]["PolicyName"]

                version_id = policy_detail["Policy"]["DefaultVersionId"]

                policy_version = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )

                statements = policy_version["PolicyVersion"]["Document"].get("Statement", [])

                if not isinstance(statements, list):
                    statements = [statements]

            except Exception as e:
                print(f"Skipping policy {policy_arn}: {e}")
                continue

            # ---------------- PROCESS STATEMENTS ----------------
            for idx, st in enumerate(statements):

                sid = st.get("Sid") or f"auto-{version_id}-{idx}"
                effect = st.get("Effect")

                principal = st.get("Principal")
                actions = st.get("Action", [])
                resources = st.get("Resource", [])
                conditions = st.get("Condition")

                # normalize
                if isinstance(actions, str):
                    actions = [actions]

                if isinstance(resources, str):
                    resources = [resources]

                is_principal_star = (
                    principal == "*"
                    or (isinstance(principal, dict) and "*" in str(principal))
                )

                is_action_star = any(a == "*" or a.endswith(":*") for a in actions)

                raw_statement = json.dumps(st)
                scan_time = datetime.utcnow()

                cur.execute(insert_query, (
                    policy_arn,
                    policy_name,
                    sid,
                    effect,
                    Json(principal) if principal else None,
                    is_principal_star,
                    is_action_star,
                    Json(actions),
                    Json(resources),
                    Json(conditions) if conditions else None,
                    raw_statement,
                    scan_time
                ))

                count += 1

        conn.commit()
        print(f"IAM policy statements inserted: {count}")

    except Exception as e:
        conn.rollback()
        print("Insert failed:", e)

    finally:
        cur.close()
        conn.close()

    return {
        "status": "success",
        "count": count
    }


if __name__ == "__main__":
    print(collect_iampolicystatements_data())
