import boto3
from db_utils import get_db_connection
from core.rule_engine import evaluate_finding


def collect_s3_data():
    """
    Collect S3 bucket metadata, run rule engine,
    and store findings with dedup protection.
    """

    s3_client = boto3.client("s3")
    s3_response = s3_client.list_buckets()

    findings = []

    for bucket in s3_response.get("Buckets", []):

        bucket_name = bucket.get("Name")

        # ---------------- REGION ----------------
        try:
            region_res = s3_client.get_bucket_location(Bucket=bucket_name)
            region = region_res.get("LocationConstraint") or "us-east-1"
        except Exception:
            region = "unknown"

        # ---------------- PUBLIC ACCESS CHECK ----------------
        public_access = "private"

        try:
            block = s3_client.get_public_access_block(Bucket=bucket_name)
            config = block["PublicAccessBlockConfiguration"]

            is_public = not all(config.values())
            public_access = "public" if is_public else "private"

        except Exception:
            public_access = "public"

        # ---------------- ENCRYPTION CHECK ----------------
        try:
            enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            encryption = f"enabled ({algo})"
        except Exception:
            encryption = "disabled"

        # ---------------- RULE ENGINE ----------------
        bucket_findings = evaluate_finding(
            "s3",
            bucket_name,
            {
                "public_access": public_access,
                "encryption": encryption
            }
        )

        findings.extend(bucket_findings)

    # ---------------- DB SAVE (DEDUP SAFE) ----------------
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        print("DB connected")

        insert_query = """
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
        ON CONFLICT (dedup_key) DO NOTHING;
        """

        for f in findings:
            cursor.execute(insert_query, (
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

        print("S3 findings saved (dedup enabled)")

    except Exception as e:
        print("DB error:", e)

    finally:
        cursor.close()
        conn.close()

    return {
        "status": "success",
        "buckets": len(s3_response.get("Buckets", [])),
        "findings": findings
    }


if __name__ == "__main__":
    print(collect_s3_data())
