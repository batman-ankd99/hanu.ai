def evaluate_all(ec2_data=None, sg_data=None, s3_data=None, iam_data=None):

    all_findings = []

    # ---------------- SG ----------------
    if sg_data and sg_data.get("data"):
        for sg in sg_data["data"]:

            all_findings.extend(
                evaluate_finding(
                    "sg",
                    sg.get("group_id"),
                    {
                        "inbound_rules": sg.get("inbound_rules", [])
                    }
                )
            )

    # ---------------- S3 ----------------
    if s3_data and s3_data.get("findings"):
        for bucket in s3_data["findings"]:

            all_findings.extend(
                evaluate_finding(
                    "s3",
                    bucket.get("resource_id") or bucket.get("bucket_name"),
                    {
                        "public_access": bucket.get("public_access")
                    }
                )
            )

    # ---------------- IAM ----------------
    if iam_data and iam_data.get("iam_data"):
        for iam in iam_data["iam_data"]:

            all_findings.extend(
                evaluate_finding(
                    "iam_policy",
                    iam.get("policy_arn"),
                    {
                        "is_action_star": iam.get("is_action_star", False)
                    }
                )
            )

    # ---------------- SAVE TO DB ----------------
    for f in all_findings:
        save_finding_to_db(f)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    return all_findings
