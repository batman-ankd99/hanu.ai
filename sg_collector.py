import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os
from db_utils import get_db_connection

def collect_sg_data():
    """Collect AWS Security Group details and store them in PostgreSQL."""

    load_dotenv(".env.prod")        #loads key, value from .env.prod file in os env var


    ##Postgress DB connections details
    db_host=os.getenv("DB_HOST")
    db_name=os.getenv("DB_NAME")
    db_user=os.getenv("DB_USER")
    db_pass=os.getenv("DB_PASS")

    ec2_client=boto3.client('ec2')

    sg_response = ec2_client.describe_security_groups()
    #print(sg_response)

    sgs = []

    for sg in sg_response['SecurityGroups']:
            group_id=sg['GroupId']
            group_name=sg['GroupName']
            description=sg['Description']
            outbound_raw=sg['IpPermissionsEgress']
            inbound_raw=sg['IpPermissions']
            scan_time = datetime.now()

            outbound = []
            for entry in outbound_raw:
                for cidr in entry.get('IpRanges', []):
                    outbound.append(cidr['CidrIp'])
    #        print("cidr ip ye raha list k sath :", sg_cidr_out)

            inbound = []
            for in_entry in inbound_raw:
                for cidr_in in in_entry.get('IpRanges', []):
                    inbound.append(cidr_in['CidrIp'])

            scan_time = datetime.now()
            sgs.append((group_id, group_name, description, outbound, inbound, scan_time))
    #        print("grp id : ", group_id)
    #        print("group name: ", group_name)
    #        print("description: ", description)
    #        print("out rules :", outbound)
    #        print("inbound rule: ", inbound)
    #        print(" \n")


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
        print("Database connection failed",e)


    ##sql query
    #INSERT into security_groups (group_id, group_name, description, inbound_rules, outbound_rules, scan_time) VALUES ('sg-0067fc9415db35509', 'default', '', '[''0.0.0.0/0'']', '[''0.0.0.0/0'', ''106.219.165.46/32'']',  '2025-11-03 11:42:28')
    ##

    insert_query_sg = """
     INSERT into security_groups (group_id, group_name, description, inbound_rules, outbound_rules, scan_time) VALUES (%s, %s, %s, %s, %s, %s)

     ON CONFLICT (group_id)
     DO UPDATE SET
        group_id = EXCLUDED.group_id,
        group_name = EXCLUDED.group_name,
        description = EXCLUDED.description,
        inbound_rules = EXCLUDED.inbound_rules,
        outbound_rules = EXCLUDED.outbound_rules,
        scan_time = EXCLUDED.scan_time;
    """

    for sg_info in sgs:
        cursor.execute(insert_query_sg, tuple(sg_info))

    conn.commit()

    cursor.close()
    conn.close()

# Allow running directly or importing in collector.py file
if __name__ == "__main__":
    collect_sg_data()
