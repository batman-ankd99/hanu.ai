import boto3
from core.rule_engine import evaluate_finding


def collect_s3_data():
    """
    Collect S3 bucket metadata and evaluate security rules.
    No DB writes, no Flask code.
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

            # if ANY block setting is False → bucket may be public
            is_public = not all(config.values())
            public_access = "public" if is_public else "private"

        except Exception:
            # if API fails, assume risky (safe side)
            public_access = "public"

        # ---------------- ENCRYPTION CHECK (optional future use) ----------------
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

    return {
        "status": "success",
        "buckets": len(s3_response.get("Buckets", [])),
        "findings": len(findings),
        "data": findings
    }


if __name__ == "__main__":
    print(collect_s3_data())
