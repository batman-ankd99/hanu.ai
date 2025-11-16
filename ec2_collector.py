import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os
from db_utils import get_db_connection

def collect_ec2_data():
    """Collect AWS EC2 details and store them in PostgreSQL."""
    load_dotenv(".env.prod")        #loads key, value from .env.prod file in os env var


    ##Postgress DB connections details
    db_host=os.getenv("DB_HOST")
    db_name=os.getenv("DB_NAME")
    db_user=os.getenv("DB_USER")
    db_pass=os.getenv("DB_PASS")


    ##Fetch Ec2 details of account and push them to DB name

    ec2_client=boto3.client('ec2') #to be used for ec2 and sg info

    response = ec2_client.describe_instances()

    instances = []
    instance_live_list = []
    for reservation in response['Reservations']:
        for ec2 in reservation['Instances']:
            instance_id = ec2['InstanceId']
            ####instance name to be fetched from tags
            instance_name = None
            if 'Tags' in ec2:
                for tag in ec2['Tags']:
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
            ####            
            ip_address =  ec2['PrivateIpAddress']
            region =   ec2_client.meta.region_name
            state = ec2['State']['Name']
            security_groups = []
            for sg in  ec2['SecurityGroups']:
                security_groups.append(sg['GroupName'])
            scan_time = datetime.now()

            instances.append((instance_id, instance_name, state, region, security_groups, scan_time, ip_address))
    #print(instances)   ##double brackets means - for every instance all fields are added as a list in list instances
            instance_live_list.append(instance_id)
    ##Connect to DB now using above details
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
    #INSERT into ec2_instances (instance_id, instance_name, state, region, security_groups, scan_time, pvt_ip) VALUES ('asdhbs', 'nameiinstance', 'up', 'us-east-1', 'default',  '2025-11-03 11:42:28', '10.100.0.1')
    ##

    insert_query = """
     INSERT into ec2_instances (instance_id, instance_name, state, region, security_groups, scan_time, pvt_ip) VALUES (%s, %s, %s, %s, %s, %s, %s)

     ON CONFLICT (instance_id)
     DO UPDATE SET
        instance_name = EXCLUDED.instance_name,
        state = EXCLUDED.state,
        region = EXCLUDED.region,
        security_groups = EXCLUDED.security_groups,
        scan_time = EXCLUDED.scan_time,
        pvt_ip = EXCLUDED.pvt_ip;
    """

    for instance_info in instances:
        cursor.execute(insert_query, tuple(instance_info))

    ec2_current = tuple(instance_live_list)
    delete_query = """
    DELETE FROM ec2_instances
    WHERE instance_id NOT IN %s;
    """
    cursor.execute(delete_query, (ec2_current,))

    conn.commit()

    cursor.close()
    conn.close()

    return {"status": "success", "count": len(instances)}

# Allow running directly or importing in collector.py file
if __name__ == "__main__":
    collect_ec2_data()
