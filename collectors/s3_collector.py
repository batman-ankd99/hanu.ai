import boto3
from datetime import datetime
from db_utils import get_db_connection
from core.rule_engine import evaluate_finding


def collect_s3_data():
    """Collect AWS S3 bucket details and store them in PostgreSQL."""

    s3_client = boto3.client('s3')
    s3_response = s3_client.list_buckets()

    s3_bucket_data = []
    bucket_live_list = []
    findings = []

    for bucket in s3_response.get('Buckets', []):

        bucket_name = bucket['Name']
        creation_date = bucket['CreationDate']

        # region
        region_res = s3_client.get_bucket_location(Bucket=bucket_name)
        region = region_res.get('LocationConstraint') or 'us-east-1'

        # public access check
        s3_access_status = "private"

        try:
            s3_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            config = s3_access_block['PublicAccessBlockConfiguration']
            is_public = not all(config.values())
            s3_access_status = "public" if is_public else "private"

        except Exception:
            s3_access_status = "public"

        # encryption check
        try:
            encryption_res = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption_res['ServerSideEncryptionConfiguration']['Rules']
            algo = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            encryption_enabled = f"enabled ({algo})"
        except Exception:
            encryption_enabled = "disabled"

        scan_time = datetime.utcnow()

        s3_bucket_data.append((
            bucket_name,
            region,
            s3_access_status,
            encryption_enabled,
            creation_date,
            scan_time
        ))

        bucket_live_list.append(bucket_name)

        # rule engine
        bucket_findings = evaluate_finding(
            "s3",
            bucket_name,
            {
                "public_access": s3_access_status,
                "encryption": encryption_enabled
            }
        )

        findings.extend(bucket_findings)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        print("✅ DB connected")

        # -------------------------
        # S3 TABLE INSERT
        # -------------------------
        insert_query = """
        INSERT INTO s3_buckets
        (bucket_name, region, public_access, encryption_enabled, creation_date, scan_time)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (bucket_name)
        DO UPDATE SET
            region = EXCLUDED.region,
            public_access = EXCLUDED.public_access,
            encryption_enabled = EXCLUDED.encryption_enabled,
            creation_date = EXCLUDED.creation_date,
            scan_time = EXCLUDED.scan_time;
        """

        for row in s3_bucket_data:
            cursor.execute(insert_query, row)

        # cleanup old buckets
        if bucket_live_list:
            cursor.execute("""
                DELETE FROM s3_buckets
                WHERE bucket_name NOT IN %s
            """, (tuple(bucket_live_list),))
        else:
            cursor.execute("DELETE FROM s3_buckets;")

        # -------------------------
        # FINDINGS INSERT (FIXED)
        # -------------------------
        insert_finding = """
        INSERT INTO findings (
            dedup_key,
            service,
            resource_type,
            resource_id,
            finding,
            severity,
            status,
            recommendation,
            created_at,
            updated_at
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,now(),now())
        """

        for f in findings:
            cursor.execute(insert_finding, (
                f["dedup_key"],
                f["service"],
                f["resource_type"],
                f["resource_id"],
                f["finding"],
                f["severity"],
                f.get("status", "open"),
                f.get("recommendation", "")
            ))

        conn.commit()

        print("✅ S3 + findings inserted successfully")

    except Exception as e:
        print("❌ DB error:", e)

    finally:
        cursor.close()
        conn.close()

    return {
        "status": "success",
        "buckets": len(s3_bucket_data),
        "findings": len(findings)
    }


if __name__ == "__main__":
    collect_s3_data()
