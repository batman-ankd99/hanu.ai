import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os
from db_utils import get_db_connection

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
rows = cursor.fetchall()

# Print the output in a readable format
print("\nQuery Results:")
for row in rows:
    print(row)

# Optional: get column names
colnames = [desc[0] for desc in cursor.description]
print("\nColumns:", colnames)

# Cleanup
cursor.close()
conn.close()
