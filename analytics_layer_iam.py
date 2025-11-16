import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os
from db_utils import get_db_connection
from tabulate import tabulate

def analytics_iam():

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        select_query = """
         SELECT
             s.id,
             s.effect,
             s.principal,
             s.actions,
             p.policy_name,
             p.attached_entities
         FROM iam_policy_statements AS s
         JOIN iam_policies AS p
             ON s.policy_arn = p.policy_arn
         WHERE (s.is_action_star = 't' OR s.is_principal_star = 't')
           AND s.effect = 'Allow';
        """

        # Execute the query
        cursor.execute(select_query)

        # Fetch all rows
        rows = cursor.fetchall() #all rows fetched from select query are brought into python memory, as a tuple
        colnames = [desc[0] for desc in cursor.description] #after query, cursor.description gives metadata about each returned column, so desc[0] only fetches column name
        #its a list of tuples - (('id', ...), ('effect', ...), ('principal', ...), ('actions', ...), ...)

        print("\nPolicies that are at risk, opening star in either principal or Action:")
        print(tabulate(rows, headers=colnames, tablefmt="psql"))

    except Exception as e:
        print("❌ Database operation failed:", e)

    # Cleanup
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

    return {"status": "success", "count": len(rows)}

# Allow direct run
if __name__ == "__main__":
    analytics_iam()
