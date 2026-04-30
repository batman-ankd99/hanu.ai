import boto3
from datetime import datetime
from core.rule_engine import evaluate_finding


def collect_s3_data():
    """Collect S3 bucket metadata ONLY (no DB writes here)."""

    s3_client = boto3.client('s3')
    s3_response = s3_client.list_buckets()

    results = []

    for bucket in s3_response.get('Buckets', []):

        bucket_name = bucket['Name']

        # region
        try:
            region_res = s3_client.get_bucket_location(Bucket=bucket_name)
            region = region_res.get('LocationConstraint') or 'us-east-1'
        except Exception:
            region = "unknown"

        # public access check
        public_access = "private"

        try:
            block = s3_client.get_public_access_block(Bucket=bucket_name)
            config = block['PublicAccessBlockConfiguration']
            is_public = not all(config.values())
            public_access = "public" if is_public else "private"
        except Exception:
            public_access = "public"

        # encryption check
        try:
            enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = enc['ServerSideEncryptionConfiguration']['Rules']
            algo = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            encryption = f"enabled ({algo})"
        except Exception:
            encryption = "disabled"

        # ---------------- RULE ENGINE ONLY ----------------
        results.extend(
            evaluate_finding(
                "s3",
                bucket_name,
                {
                    "public_access": public_access,
                    "encryption": encryption
                }
            )
        )

    return {
        "status": "success",
        "buckets": len(s3_response.get('Buckets', [])),
        "findings": len(results)
    }


if __name__ == "__main__":
    collect_s3_data()
