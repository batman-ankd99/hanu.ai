import boto3
from datetime import datetime
import json
from db_utils import get_db_connection


def collect_iampolicy_data():
    """
    Collect IAM policy metadata and store in PostgreSQL.
    Clean + consistent with SG/S3 pipeline.
    """

    iam = boto3.client("iam")

    response = iam.list_policies(Scope="All")
    policies = response.get("Policies", [])

    iam_data = []

    for policy in policies:

        policy_arn = policy.get("Arn")
        policy_name = policy.get("PolicyName")
        policy_id = policy.get("PolicyId")
        create_date = policy.get("CreateDate")
        update_date = policy.get("UpdateDate")
        scan_time = datetime.utcnow()

        is_aws_managed = policy_arn.startswith("arn:aws:iam::aws:policy/")

        # ---------------- ATTACHED ENTITIES ----------------
        try:
            entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
        except Exception:
            entities = {
                "PolicyGroups": [],
                "PolicyUsers": [],
                "PolicyRoles": []
            }

        attached_groups = [g.get("GroupName") for g in entities.get("PolicyGroups", [])]
        attached_users = [u.get("UserName") for u in entities.get("PolicyUsers", [])]
        attached_roles = [r.get("RoleName") for r in entities.get("PolicyRoles", [])]

        entity_list = {
            "Groups": attached_groups,
            "Users": attached_users,
            "Roles": attached_roles
        }

        iam_data.append((
            policy_arn,
            policy_name,
            policy_id,
            json.dumps(entity_list),
            create_date,
            update_date,
            is_aws_managed,
            scan_time
        ))

    # ---------------- DB WRITE ----------------
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        print("DB connected")

        insert_query = """
        INSERT INTO iam_policies (
            policy_arn,
            policy_name,
            policy_id,
            attached_entities,
            create_date,
            update_date,
            is_aws_managed,
            scan_time
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (policy_arn)
        DO UPDATE SET
            attached_entities = EXCLUDED.attached_entities,
            create_date = EXCLUDED.create_date,
            update_date = EXCLUDED.update_date,
            is_aws_managed = EXCLUDED.is_aws_managed,
            scan_time = EXCLUDED.scan_time;
        """

        for record in iam_data:
            cursor.execute(insert_query, record)

        conn.commit()

        print("IAM policy data saved successfully")

    except Exception as e:
        print("DB error:", e)

    finally:
        cursor.close()
        conn.close()

    return {
        "status": "success",
        "count": len(iam_data)
    }


if __name__ == "__main__":
    print(collect_iampolicy_data())
