import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os


"""Collect AWS IAM Custom Policies details and store them in PostgreSQL."""
load_dotenv(".env.prod")

iam = boto3.client('iam')
response = iam.list_policies()

print(response)
