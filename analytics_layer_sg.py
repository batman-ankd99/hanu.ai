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
         WHERE inbound_rules LIKE '%0.0.0.0/0%' OR
               outbound_rules LIKE '%0.0.0.0/0%';
        """

        # Execute the query
        cursor.execute(select_query)

        # Fetch all rows
        rows = cursor.fetchall() #all rows fetched from select query are brought into python memory, as a tuple
        colnames = [desc[0] for desc in cursor.description] #after query, cursor.description gives metadata about each returned column, so desc[0] only fetches column name
        #its a list of tuples - (('id', ...), ('effect', ...), ('principal', ...), ('actions', ...), ...)

        print("\n SG rules that contains traffic to go or come from anywhere, this puts Infra at risk. Are as below:")
        print(tabulate(rows, headers=colnames, tablefmt="psql"))

    except Exception as e:
        print("❌ Database operation failed:", e)

    # Cleanup
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

    return {"status": "success", "count": len(rows), "table": tabulate(rows, headers=colnames, tablefmt="psql")}

# Allow direct run
if __name__ == "__main__":
    analytics_sg()
