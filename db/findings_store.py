import psycopg2
from datetime import datetime
from db_utils import get_db_connection


def save_findings(findings):

    conn = get_db_connection()
    cursor = conn.cursor()

    for f in findings:
        dedup_key = f"{f['service']}:{f['resource_id']}:{f['finding']}"

        query = """
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
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (dedup_key)
        DO UPDATE SET
            severity = EXCLUDED.severity,
            updated_at = EXCLUDED.updated_at;
        """

        cursor.execute(query, (
            dedup_key,
            f["service"],
            f["resource_type"],
            f["resource_id"],
            f["finding"],
            f["severity"],
            "OPEN",
            f["recommendation"],
            datetime.utcnow(),
            datetime.utcnow()
        ))

    conn.commit()
    cursor.close()
    conn.close()
