import boto3
from core.rule_engine import evaluate_finding


def collect_s3_data():
    """
    ONLY fetch S3 metadata.
    NO DB writes.
    ONLY returns raw data for rule engine.
    """

    s3_client = boto3.client("s3")
    response = s3_client.list_buckets()

    buckets = []

    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]

        # ---------------- PUBLIC ACCESS CHECK ----------------
        try:
            block = s3_client.get_public_access_block(Bucket=bucket_name)
            config = block.get("PublicAccessBlockConfiguration", {})

            is_public = not all(config.values())
            public_access = "public" if is_public else "private"

        except Exception:
            # if config missing → assume risky
            public_access = "public"

        # ---------------- STORE RAW DATA ONLY ----------------
        buckets.append({
            "bucket_name": bucket_name,
            "public_access": public_access
        })

    # ---------------- RULE ENGINE ----------------
    findings = []

    for b in buckets:
        findings.extend(
            evaluate_finding(
                "s3",
                b["bucket_name"],
                {
                    "public_access": b["public_access"]
                }
            )
        )

    return {
        "status": "success",
        "buckets": len(buckets),
        "data": buckets,
        "findings": findings
    }


if __name__ == "__main__":
    print(collect_s3_data())
