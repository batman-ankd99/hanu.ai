import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os

"""Collect AWS Security Group details and store them in PostgreSQL."""

load_dotenv(".env.prod")        #loads key, value from .env.prod file in os env var


##Postgress DB connections details
db_host=os.getenv("DB_HOST")
db_name=os.getenv("DB_NAME")
db_user=os.getenv("DB_USER")
db_pass=os.getenv("DB_PASS")

ec2_client=boto3.client('ec2')

sg_response = ec2_client.describe_security_groups()
#print(sg_response)

sgs = []

for sg in sg_response['SecurityGroups']:
