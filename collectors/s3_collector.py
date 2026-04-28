import boto3
import psycopg2  # to connect to postgres
from datetime import datetime
from dotenv import load_dotenv  # to load .env files key value in environment of app
import os
from db_utils import get_db_connection

# rule engine import
from core.rule_engine import evaluate_finding


def collect_s3_data():
    """Collect AWS S3 bucket details and store them in PostgreSQL."""

    s3_client = boto3.client('s3')
    s3_response = s3_client.list_buckets()

    s3_bucket_data = []
    bucket_live_list = []
    findings = []   # 🔥 step 5 - new list for findings

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
            encryption_enabled = f"enabled ({algo})"
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                encryption_enabled = "disabled"
            else:
                encryption_enabled = "unknown"

        scan_time = datetime.now()
        s3_bucket_data.append((bucket_name, region, s3_access_status, encryption_enabled, creation_date, scan_time))
        bucket_live_list.append(bucket_name)

        # 🔥 step 5 - rule engine call (minimal addition)
        bucket_attributes = {
            "public_access": s3_access_status
        }

        bucket_findings = evaluate_finding(
            "s3",
            bucket_name,
            bucket_attributes
        )

        findings.extend(bucket_findings)

    # --- Push to PostgreSQL ---
    try:
        conn = get_db_connection()
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

        print("✅ S3 bucket data inserted/updated successfully")

        s3_current = tuple(bucket_live_list)
        delete_query = """
        DELETE FROM s3_buckets
        WHERE bucket_name NOT IN %s;
        """

        if len(bucket_live_list) == 0:
            cursor.execute("DELETE FROM s3_buckets;")
        else:
            cursor.execute(delete_query, (s3_current,))

        #  insert findings (minimal addition)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY,
            rule_id TEXT,
            severity TEXT,
            description TEXT,
            resource_id TEXT,
            detected_at TIMESTAMP
        )
        """)

        insert_finding = """
        INSERT INTO findings
        (rule_id, severity, description, resource_id, detected_at)
        VALUES (%s, %s, %s, %s, %s)
        """

        for f in findings:
            cursor.execute(insert_finding, (
                f["rule_id"],
                f["severity"],
                f["description"],
                f["resource_id"],
                f["detected_at"]
            ))

        conn.commit()

    except Exception as e:
        print("❌ Database operation failed:", e)

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

    print("✅ S3 collector finished")

    return {
        "status": "success",
        "count": len(s3_bucket_data),
        "findings": len(findings)
    }


if __name__ == "__main__":
    collect_s3_data()
