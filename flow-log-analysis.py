import boto3
from datetime import datetime
import os

s3 = boto3.resource('s3')

for bucket in s3.buckets.all():
    print(bucket.name)

def s3_file_download(year, month, day, bucket_name):

    filepath= f"vpc-flow-log-hanu/AWSLogs/426728253870/vpcflowlogs/us-east-1/{year}/{month}/{day}"

s3_file_download(2025, 11, 24, "vpc-flow-log-hanu")
