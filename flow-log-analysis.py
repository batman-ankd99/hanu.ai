import boto3
from datetime import datetime
import os

s3 = boto3.client('s3')

def s3_file_download(year, month, day, bucket_name, aws_ac_num):

    prefix = f"AWSLogs/{aws_ac_num}/vpcflowlogs/us-east-1/{year}/{month}/{day}/"
    local_folder = f"/opt/{year}-{month:02d}-{day:02d}"
    os.makedirs(local_folder, exist_ok=True)

    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    for obj in response['Contents']:
        key = obj['Key']
        filename= key.split("/")[-1]
        local_path = os.path.join(local_folder, filename)

        s3.download_file(bucket_name, key, local_path)

s3_file_download(2025, 11, 24, "vpc-flow-log-hanu", 426728253870)
