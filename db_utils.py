import os
import psycopg2
from dotenv import load_dotenv

def get_db_connection(env_file=".env.prod"):
    """
    Establishes PostgreSQL database connection
    using credentials from the given environment file.
    """
    load_dotenv(env_file)

    db_host = os.getenv("DB_HOST")
    db_name = os.getenv("DB_NAME")
    db_user = os.getenv("DB_USER")
    db_pass = os.getenv("DB_PASS")

    try:
        conn = psycopg2.connect(
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_pass
        )
        print("✅ Database connected")
        return conn
    except Exception as e:
        print("❌ Database connection failed:", e)
        return None
