import boto3
import os
from datetime import datetime, timedelta

s3 = boto3.client('s3')

def collect_vpcflowlog_data(year, month, day, bucket_name, aws_ac_num):
    date_str = f"{year}/{month}/{day}"
    print = f"this will download vpc flow log of date -> {date_Str}"

    prefix = f"AWSLogs/{aws_ac_num}/vpcflowlogs/us-east-1/{year}/{month:02d}/{day:02d}/"
    local_folder = f"/opt/{year}-{month:02d}-{day:02d}"
    os.makedirs(local_folder, exist_ok=True)

    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

    if "Contents" not in response:
    print(f"No logs found for {year}-{month:02d}-{day:02d}")
    return

    for obj in response['Contents']:
        key = obj['Key']
        filename= key.split("/")[-1]
        local_path = os.path.join(local_folder, filename)

        print(f"Downloading {key} -> {local_path}")
        s3.download_file(bucket_name, key, local_path)
        print("Download complete")

    return {
    "status" : "success",
    
    }

if __name__ == "__main__":
    collect_vpcflowlog_data()
