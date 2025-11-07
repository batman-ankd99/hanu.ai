import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os


"""Collect AWS IAM Custom Policies details and store them in PostgreSQL."""
load_dotenv(".env.prod")

iam = boto3.client('iam')
response = iam.list_policies()

#print(response['Policies'])
policy_list = []
iam_data = []
policy_list_allinfo = response['Policies']
for policy in policy_list_allinfo:
    policy_arn = policy['Arn']
    policy_name = policy['PolicyName']
    policy_id = policy['PolicyId']
#    policy_create-date = policy['CreateDate']
#    policy_update-date = policy['UpdateDate']
    scan_time = datetime.now()

    policy_list.append(policy['PolicyId']) ##this list policy_id will contain all policy id

    if policy_arn.startswith("arn:aws:iam::aws:policy/"):
         policy_type = "aws_managed"
    else:
         policy_type = "customer_managed"

    entity_list = []
    entitiy_list.append(iam.list_entities_for_policy(PolicyArn=policy_arn)
    print(entity_policy)['PolicyGroups'])

    entitiy_list.append(iam.list_entities_for_policy(PolicyArn=policy_arn)
    print(entity_policy)['PolicyUsers'])

    entitiy_list.append(iam.list_entities_for_policy(PolicyArn=policy_arn)
    print(entity_policy)['PolicyRoles'])

    iam_data.append(policy_arn, policy_name, policy_id, policy_type, entity_list, scan_time)


print(iam_data)





#print(policy_list)
