import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os
from db_utils import get_db_connection
from tabulate import tabulate

def analytics_sg():

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        select_query = """
         SELECT
            group_id,
            group_name,
            inbound_rules,
            outbound_rules
         FROM security_groups
         WHERE
            inbound_rules @> '[{"cidr": "0.0.0.0/0"}]'::jsonb
            OR
            outbound_rules @> '[{"cidr": "0.0.0.0/0"}]'::jsonb
            OR
            inbound_rules @> '[{"protocol": "-1"}]'::jsonb
            OR
            outbound_rules @> '[{"protocol": "-1"}]'::jsonb;
        """

        # Execute the query
        cursor.execute(select_query)

        # Fetch all rows
        rows = cursor.fetchall() #all rows fetched from select query are brought into python memory, as a tuple
        colnames = [desc[0] for desc in cursor.description] #after query, cursor.description gives metadata about each returned column, so desc[0] only fetches column name
        #its a list of tuples - (('id', ...), ('effect', ...), ('principal', ...), ('actions', ...), ...)

#        print("\n SG rules that contains traffic to go or come from anywhere, this puts Infra at risk. Are as below:")
#        print(tabulate(rows, headers=colnames, tablefmt="psql"))

        records = []
        for row in rows:
            item = {}
            for idx, col in enumerate(colnames):
                item[col] = row[idx]
            records.append(item)
        return {
            "status": "success",
            "count": len(records),
            "records": records
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

    # Cleanup
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# Allow direct run
if __name__ == "__main__":
    analytics_sg()
