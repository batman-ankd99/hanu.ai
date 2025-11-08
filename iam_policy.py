import boto3
from datetime import datetime
from dotenv import load_dotenv
import os
import json

def collect_s3_data():
    """Collect AWS S3 bucket details and store them in PostgreSQL."""
    load_dotenv(".env.prod")

    ##Postgres DB connections details
    db_host = os.getenv("DB_HOST")
    db_name = os.getenv("DB_NAME")
    db_user = os.getenv("DB_USER")
    db_pass = os.getenv("DB_PASS")

    iam = boto3.client('iam')

    response = iam.list_policies(Scope='All')

    policy_list = []
    iam_data = []

    policy_list_allinfo = response['Policies']

    for policy in policy_list_allinfo:
        policy_arn = policy['Arn']
        policy_name = policy['PolicyName']
        policy_id = policy['PolicyId']
        create_date = policy.get('CreateDate')
        update_date = policy.get('UpdateDate')
        scan_time = datetime.now()

        # Determine policy type
        if policy_arn.startswith("arn:aws:iam::aws:policy/"):
            is_aws_managed = True
        else:
            is_aws_managed = False

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

        # Append tuple of policy info
        iam_data.append((
            policy_arn,
            policy_name,
            policy_id,
            policy_type,
            json.dumps(entity_list),
            create_date,
            update_date,
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

        insert_query = """
        INSERT INTO iam_policies (policy_arn, policy_name, policy_id, policy_type, attached_entities, create_date, update_date, is_aws_managed, scan_time)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (bucket_name)
        DO UPDATE SET
            region = EXCLUDED.region,
            public_access = EXCLUDED.public_access,
            encryption_enabled = EXCLUDED.encryption_enabled,
            creation_date = EXCLUDED.creation_date,
            scan_time = EXCLUDED.scan_time;
        """

        for bucket_info in s3_bucket_data:
            cursor.execute(insert_query, tuple(bucket_info))

        conn.commit()
        print("✅ S3 bucket data inserted/updated successfully")

    except Exception as e:
        print("❌ Database operation failed:", e)

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Allow running directly or from collector.py
if __name__ == "__main__":
    collect_s3_data()
