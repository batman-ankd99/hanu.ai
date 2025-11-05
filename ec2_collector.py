import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os

"""Collect AWS EC2 details and store them in PostgreSQL."""
load_dotenv(".env.prod")        #loads key, value from .env.prod file in os env var


##Postgress DB connections details
db_host=os.getenv("DB_HOST")
db_name=os.getenv("DB_NAME")
db_user=os.getenv("DB_USER")
db_pass=os.getenv("DB_PASS")


##Fetch Ec2 details of account and push them to DB name

ec2_client=boto3.client('ec2') #to be used for ec2 and sg info

response = ec2_client.describe_instances()

instances = []
for reservation in response['Reservations']:
    for ec2 in reservation['Instances']:
        instance_id = ec2['InstanceId']
        ip_address =  ec2['PrivateIpAddress']
        region =   ec2_client.meta.region_name
        state = ec2['State']['Name']
        security_groups = []
        for sg in  ec2['SecurityGroups']:
            security_groups.append(sg['GroupName'])
        scan_time = datetime.now()

        instances.append((instance_id, ip_address, region, state, security_groups, scan_time, ip_address))
#print(instances)   ##double brackets means - for every instance all fields are added as a list in list instances

##Connect to DB now using above details
