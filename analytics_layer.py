import boto3
import psycopg2 #to connect to postgres
from datetime import datetime
from dotenv import load_dotenv #to load .env files key value in enviroment of app
import os
from db_utils import get_db_connection

conn = get_db_connection()
cursor = conn.cursor()
