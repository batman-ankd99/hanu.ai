import boto3
from datetime import datetime
from dotenv import load_dotenv
import os
import json
import psycopg2

def collect_iam_data():
    """Collect AWS IAM Policy details and store them in PostgreSQL."""
    load_dotenv(".env.prod")

    # Postgres DB connection details
    db_host = os.getenv("DB_HOST")
    db_name = os.getenv("DB_NAME")
    db_user = os.getenv("DB_USER")
    db_pass = os.getenv("DB_PASS")

    iam = boto3.client('iam')

    response = iam.list_policies(Scope='All')
    policy_list_allinfo = response['Policies']

    iam_data = []

    for policy in policy_list_allinfo:
        policy_arn = policy['Arn']
        policy_name = policy['PolicyName']
        policy_id = policy['PolicyId']
        create_date = policy.get('CreateDate')
        update_date = policy.get('UpdateDate')
        scan_time = datetime.now()

        # Determine AWS-managed vs customer-managed - True or False
        is_aws_managed = policy_arn.startswith("arn:aws:iam::aws:policy/")

        # Collect attached entities (groups, users, roles)
        entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
        attached_groups = [g['GroupName'] for g in entities['PolicyGroups']]
        attached_users = [u['UserName'] for u in entities['PolicyUsers']]
        attached_roles = [r['RoleName'] for r in entities['PolicyRoles']]

        entity_list = {
            "Groups": attached_groups,
            "Users": attached_users,
            "Roles": attached_roles
        }

        # Append tuple for DB insert
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

    # Print collected data
    for record in iam_data:
        print(record)

    try:
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_pass
        )
        cursor = conn.cursor()
        print("✅ Database connected successfully")

        # insert query to push data to table
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

        for policy_info in iam_data:
            cursor.execute(insert_query, tuple(policy_info))

        conn.commit()
        print("✅ IAM policy data inserted/updated successfully")

    except Exception as e:
        print("❌ Database operation failed:", e)

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Allow direct run
if __name__ == "__main__":
    collect_iam_data()
