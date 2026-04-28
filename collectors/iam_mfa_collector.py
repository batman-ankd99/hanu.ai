import boto3
from datetime import datetime
from db_utils import get_db_connection

def collect_iam_mfa_data():

    iam = boto3.client("iam")
    users = iam.list_users()["Users"]

    results = []

    for user in users:
        username = user["UserName"]

        # Check MFA devices
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

        mfa_enabled = len(mfa_devices) > 0

        results.append((
            username,
            mfa_enabled,
            datetime.utcnow()
        ))

    # store in DB
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS iam_mfa_status (
            username TEXT PRIMARY KEY,
            mfa_enabled BOOLEAN,
            scan_time TIMESTAMP
        )
        """)

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
        cursor.close()
        conn.close()

    except Exception as e:
        print("DB error:", e)

    return {
        "status": "success",
        "count": len(results)
    }


if __name__ == "__main__":
    collect_iam_mfa_data()
