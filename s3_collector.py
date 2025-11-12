import boto3
import psycopg2  # to connect to postgres
from datetime import datetime
from dotenv import load_dotenv  # to load .env files key value in environment of app
import os
from db_utils import get_db_connection

def collect_s3_data():
    """Collect AWS S3 bucket details and store them in PostgreSQL."""
#    load_dotenv(".env.prod")

    ##Postgres DB connections details
#    db_host = os.getenv("DB_HOST")
#    db_name = os.getenv("DB_NAME")
#    db_user = os.getenv("DB_USER")
#    db_pass = os.getenv("DB_PASS")

    s3_client = boto3.client('s3')
    s3_response = s3_client.list_buckets()

    s3_bucket_data = []

    # print(s3_response['Buckets'])
    for s3bucket in s3_response['Buckets']:
        bucket_name = s3bucket['Name']
        creation_date = s3bucket['CreationDate']

        # Get bucket region (handle None)
        region_res = s3_client.get_bucket_location(Bucket=bucket_name)
        region = region_res.get('LocationConstraint') or 'us-east-1'

        # Default: assume private (in case of error)
        s3_access_status = "private"

        # Check public access block configuration safely
        try:
            s3_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            config = s3_access_block['PublicAccessBlockConfiguration']
            is_public = not all(config.values())  # if any setting is False → bucket might be public
            s3_access_status = "public" if is_public else "private"
        except s3_client.exceptions.ClientError as e:
            # If the bucket has no access block config or access denied, assume possibly public
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchPublicAccessBlockConfiguration':
                s3_access_status = "public"
            else:
                print(f"⚠️ Skipping bucket {bucket_name}: {error_code}")

        # --- Encryption check block ---
        try:
            encryption_res = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption_res['ServerSideEncryptionConfiguration']['Rules']
            algo = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            # algo could be 'AES256' or 'aws:kms'
            encryption_enabled = f"enabled ({algo})"
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                encryption_enabled = "disabled"
            else:
                encryption_enabled = "unknown"

        scan_time = datetime.now()

        # Added encryption_enabled in tuple
        s3_bucket_data.append((bucket_name, region, s3_access_status, encryption_enabled, creation_date, scan_time))

        conn = get_connection()
        cursor = conn.cursor()

        print("✅ Database connected successfully")

        insert_query = """
        INSERT INTO s3_buckets (bucket_name, region, public_access, encryption_enabled, creation_date, scan_time)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (bucket_name)
        DO UPDATE SET
            region = EXCLUDED.region,
            public_access = EXCLUDED.public_access,
            encryption_enabled = EXCLUDED.encryption_enabled,
            creation_date = EXCLUDED.creation_date,
            scan_time = EXCLUDED.scan_time;
        """

        for bucket_info in s3_bucket_data:
            cursor.execute(insert_query, tuple(bucket_info))

        conn.commit()
        print("✅ S3 bucket data inserted/updated successfully")

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Allow running directly or from collector.py
if __name__ == "__main__":
    collect_s3_data()
