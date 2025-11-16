import boto3
from datetime import datetime
from dotenv import load_dotenv
import os
import json
import psycopg2
from db_utils import get_db_connection

def collect_iampolicystatements_data():
    """Collect AWS IAM Policy Statements details and store them in PostgreSQL."""
    load_dotenv(".env.prod")

    # Postgres DB connection details
    db_host = os.getenv("DB_HOST")
    db_name = os.getenv("DB_NAME")
    db_user = os.getenv("DB_USER")
    db_pass = os.getenv("DB_PASS")

    iampolicy = boto3.client('iam')
    response_iampolicy = iampolicy.list_policies(Scope='Local') #will fetch only customer managed, aws managed we are not getting since only a check for FULL policy aws we will put a check for security.

    # SQl Table fields -> id, policy_arn, sid, effect, is_principal_star, actions, resources, conditions, raw_Statement, scan time

    policy_st_allinfo = response_iampolicy['Policies'] #this is policy arn of all policies managed by customer

    policy_list_local = [] #arns of all policies to be appended

    for policy in policy_st_allinfo:
        policy_list_local.append(policy['Arn'])

    #print(policy_list_local)

    #now need some logic to fetch details of policy complete since we have policy arn

    try:
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_pass
        )
        cur = conn.cursor()

    except Exception as e:
        print("❌ Database connection failed:", e)
        return {"status": "db_failed"}

    for policy_arn in policy_list_local:
        policy_detail = iampolicy.get_policy(PolicyArn=policy_arn)

        policy_version = iampolicy.get_policy_version(PolicyArn = policy_arn,VersionId = policy_detail['Policy']['DefaultVersionId'])

#        print(json.dumps(policy_version['PolicyVersion']['Document']['Statement'], indent=4))

        statements = policy_version['PolicyVersion']['Document']['Statement']
        if not isinstance(statements, list):
            statements = [statements]  # handle single statement policies



        for st in statements:
            sid = st.get('Sid')
            effect = st.get('Effect')
            principal = st.get('Principal')
            actions = st.get('Action')
            resources = st.get('Resource')
            conditions = st.get('Condition')

            # Check for principal = "*"
            if principal is None:
                is_principal_star = False
            elif principal == "*" or (isinstance(principal, dict) and "*" in str(principal)):
                is_principal_star = True
            else:
                is_principal_star = False

    #sometimes we get list and sometimes string, when we get string we are making it seingle element array so we can inject in DB
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            is_action_star = any(a == "*" or a.endswith(":*") for a in actions)

            raw_statement = json.dumps(st)
            scan_time = datetime.utcnow()

            insert_query = """
                INSERT INTO iam_policy_statements
                (policy_arn, statement_id, effect, principal, is_principal_star, is_action_star,
                 actions, resources, conditions, raw_statement, scan_time)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);

                ON CONFLICT (policy_arn)
                DO UPDATE SET
                   statement_id = EXCLUDED.statement_id,
                   effect = EXCLUDED.effect,
                   principal = EXCLUDED.principal,
                   is_principal_star = EXCLUDED.is_principal_star,
                   is_action_star = EXCLUDED.is_action_star,
                   actions = EXCLUDED.actions;
                   resources = EXCLUDED.resources,
                   conditions = EXCLUDED.conditions,
                   raw_statement = EXCLUDED.raw_statement,
                   scan_time = EXCLUDED.scan_time;
            """

            cur.execute(insert_query, (
                policy_arn,
                sid,
                effect,
                json.dumps(principal) if principal else None,
                is_principal_star,
                is_action_star,
                actions,
                resources,
                json.dumps(conditions) if conditions else None,
                raw_statement,
                scan_time
            ))

            conn.commit()
            print(f"✅ Inserted statement for policy: {policy_arn}")
    cur.close()
    conn.close()

    return {
        "status": "success",
        "total_cust_managed_policies": len(policy_list_local)
    }

# Allow direct run
if __name__ == "__main__":
    collect_iampolicystatements_data()
