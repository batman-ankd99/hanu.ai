import boto3
import psycopg2
from datetime import datetime
from dotenv import load_dotenv
import os
import json
#rule engine import
from core.rule_engine import evaluate_finding


def collect_sg_data():
    """Collect AWS Security Group details along with protocol + ports + CIDRs."""

    load_dotenv(".env.prod")

    db_host = os.getenv("DB_HOST")
    db_name = os.getenv("DB_NAME")
    db_user = os.getenv("DB_USER")
    db_pass = os.getenv("DB_PASS")

    ec2_client = boto3.client("ec2")
    sg_response = ec2_client.describe_security_groups()

    sgs = []
    sg_live_list = []

    # findings list
    findings = []

    for sg in sg_response['SecurityGroups']:

        group_id = sg['GroupId']
        group_name = sg['GroupName']
        description = sg.get('Description', "")
        scan_time = datetime.now()

        ################## outbound rules #################
        outbound_rules = []
        for entry in sg.get('IpPermissionsEgress', []):
            protocol = entry.get("IpProtocol", "")
            from_port = entry.get("FromPort")
            to_port = entry.get("ToPort")

            for cidr_block in entry.get("IpRanges", []):
                outbound_rules.append({
                    "cidr": cidr_block["CidrIp"],
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port
                })

        ################## inbound rules #################
        inbound_rules = []
        for entry in sg.get('IpPermissions', []):

            protocol = entry.get("IpProtocol", "")
            from_port = entry.get("FromPort")
            to_port = entry.get("ToPort")

            for cidr_block in entry.get("IpRanges", []):
                inbound_rules.append({
                    "cidr": cidr_block["CidrIp"],
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port
                })

        # add one row for this SG
        sgs.append((
            group_id,
            group_name,
            description,
            json.dumps(inbound_rules),
            json.dumps(outbound_rules),
            scan_time
        ))

        sg_live_list.append(group_id)

        # 🔥 step 6 - rule engine call (minimal addition)
        sg_attributes = {
            "inbound_rules": inbound_rules
        }

        sg_findings = evaluate_finding(
            "sg",
            group_id,
            sg_attributes
        )

        findings.extend(sg_findings)

    # db connection
    try:
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_pass
        )
        cursor = conn.cursor()
        print("Database connected")

    except Exception as e:
        print("Database connection failed:", e)
        return {"status": "error", "message": str(e)}

    insert_query_sg = """
        INSERT INTO security_groups
        (group_id, group_name, description, inbound_rules, outbound_rules, scan_time)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (group_id)
        DO UPDATE SET
            group_name = EXCLUDED.group_name,
            description = EXCLUDED.description,
            inbound_rules = EXCLUDED.inbound_rules,
            outbound_rules = EXCLUDED.outbound_rules,
            scan_time = EXCLUDED.scan_time;
    """

    for sg_info in sgs:
        cursor.execute(insert_query_sg, sg_info)

    # Delete old sg entry
    sg_current = tuple(sg_live_list)
    if len(sg_current) == 1:
        sg_current = (sg_current[0],)

    delete_query = """
        DELETE FROM security_groups
        WHERE group_id NOT IN %s;
    """
    cursor.execute(delete_query, (sg_current,))

    #  findings table insert (minimal addition)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id SERIAL PRIMARY KEY,
        rule_id TEXT,
        severity TEXT,
        description TEXT,
        resource_id TEXT,
        detected_at TIMESTAMP
    )
    """)

    insert_finding = """
    INSERT INTO findings
    (rule_id, severity, description, resource_id, detected_at)
    VALUES (%s, %s, %s, %s, %s)
    """

    for f in findings:
        cursor.execute(insert_finding, (
            f["rule_id"],
            f["severity"],
            f["description"],
            f["resource_id"],
            f["detected_at"]
        ))

    conn.commit()
    cursor.close()
    conn.close()

    return {
        "status": "success",
        "count": len(sgs),
        "findings": len(findings)
    }


# Allow running directly or importing in collector.py file
if __name__ == "__main__":
    collect_sg_data()
