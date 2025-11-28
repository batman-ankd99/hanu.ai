import boto3
from datetime import datetime
import os

s3_vpc_flowlog_bucket = vpc-flow-log-hanu

s3 = boto3.resource('s3')
bucket= s3.Bucket('vpc-flow-log-hanu')

print(bucket)
