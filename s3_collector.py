import boto3
import psycopg2  # to connect to postgres
from datetime import datetime
from dotenv import load_dotenv  # to load .env files key value in environment of app
import os

"""Collect AWS S3 bucket details and store them in PostgreSQL."""
load_dotenv(".env.prod")

##Postgres DB connections details
db_host = os.getenv("DB_HOST")
db_name = os.getenv("DB_NAME")
db_user = os.getenv("DB_USER")
db_pass = os.getenv("DB_PASS")

s3_client = boto3.client('s3')
s3_response = s3_client.list_buckets()

s3_bucket_data = []
