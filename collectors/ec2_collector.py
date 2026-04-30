import boto3
from datetime import datetime
from db_utils import get_db_connection


def collect_ec2_data():
    """
    Collect EC2 instances and sync with PostgreSQL.
    Clean + consistent with all collectors.
    """

    ec2_client = boto3.client("ec2")

    response = ec2_client.describe_instances()

    instances = []
    instance_live_list = []

    # ---------------- PARSE INSTANCES ----------------
    for reservation in response.get("Reservations", []):
        for ec2 in reservation.get("Instances", []):

            instance_id = ec2.get("InstanceId")

            # ---------------- NAME TAG ----------------
            instance_name = None
            for tag in ec2.get("Tags", []):
                if tag.get("Key") == "Name":
                    instance_name = tag.get("Value")

            ip_address = ec2.get("PrivateIpAddress")
            region = ec2_client.meta.region_name
            state = ec2.get("State", {}).get("Name")

            security_groups = [
                sg.get("GroupName") for sg in ec2.get("SecurityGroups", [])
            ]

            scan_time = datetime.utcnow()

            instances.append((
                instance_id,
                instance_name,
                state,
                region,
                security_groups,
                scan_time,
                ip_address
            ))

            instance_live_list.append(instance_id)

    # ---------------- DB OPERATIONS ----------------
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        print("DB connected")

        insert_query = """
        INSERT INTO ec2_instances (
            instance_id,
            instance_name,
            state,
            region,
            security_groups,
            scan_time,
            pvt_ip
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (instance_id)
        DO UPDATE SET
            instance_name = EXCLUDED.instance_name,
            state = EXCLUDED.state,
            region = EXCLUDED.region,
            security_groups = EXCLUDED.security_groups,
            scan_time = EXCLUDED.scan_time,
            pvt_ip = EXCLUDED.pvt_ip;
        """

        for instance in instances:
            cursor.execute(insert_query, instance)

        # ---------------- CLEANUP OLD INSTANCES ----------------
        if instance_live_list:
            delete_query = """
            DELETE FROM ec2_instances
            WHERE instance_id NOT IN %s;
            """
            cursor.execute(delete_query, (tuple(instance_live_list),))

        conn.commit()

        print("EC2 data synced successfully")

    except Exception as e:
        print("DB error:", e)

    finally:
        cursor.close()
        conn.close()

    return {
        "status": "success",
        "count": len(instances)
    }


if __name__ == "__main__":
    print(collect_ec2_data())
