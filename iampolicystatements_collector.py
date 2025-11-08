import boto3
from datetime import datetime
from dotenv import load_dotenv
import os
import json
import psycopg2

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

policy_st_allinfo = response_iampolicy['Policies']

print(policy_st_allinfo)
