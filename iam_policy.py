import boto3
from datetime import datetime
from dotenv import load_dotenv
import os
import json

# Load environment variables
load_dotenv(".env.prod")

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
        policy_type = "aws_managed"
    else:
        policy_type = "customer_managed"

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
