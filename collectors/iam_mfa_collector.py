import boto3
from datetime import datetime
from db_utils import get_db_connection


def collect_iam_mfa_data():
    """
    Collect IAM MFA status for users and store in DB.
    """

    iam = boto3.client("iam")
    users = iam.list_users()["Users"]

    results = []

    for user in users:
        username = user["UserName"]

        try:
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            mfa_enabled = len(mfa_devices) > 0
        except Exception:
            mfa_enabled = False

        results.append((
            username,
            mfa_enabled,
            datetime.utcnow()
        ))

    # ---------------- DB WRITE ----------------
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        insert_query = """
        INSERT INTO iam_mfa_status (username, mfa_enabled, scan_time)
        VALUES (%s, %s, %s)
        ON CONFLICT (username)
        DO UPDATE SET
            mfa_enabled = EXCLUDED.mfa_enabled,
            scan_time = EXCLUDED.scan_time;
        """

        for r in results:
            cursor.execute(insert_query, r)

        conn.commit()

        print("IAM MFA data saved successfully")

    except Exception as e:
        print("DB error:", e)

    finally:
        cursor.close()
        conn.close()

    return {
        "status": "success",
        "count": len(results)
    }


if __name__ == "__main__":
    print(collect_iam_mfa_data())
