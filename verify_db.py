import sqlite3
import os

DB_PATH = 'project_management.db'

if not os.path.exists(DB_PATH):
    print("DATABASE FILE NOT FOUND")
    exit(1)

try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    print("Tables found:", tables)
    
    if 'users' in tables:
        cursor.execute("SELECT count(*) FROM users")
        count = cursor.fetchone()[0]
        print(f"Users found: {count}")
        
        cursor.execute("SELECT id, username, email, is_system FROM users")
        users = cursor.fetchall()
        for u in users:
            print(f"User: {u}")
    else:
        print("CRITICAL: 'users' table MISSING")
        
    if 'usertypes' in tables:
        cursor.execute("SELECT * FROM usertypes")
        uts = cursor.fetchall()
        print("User types:", uts)

    conn.close()
except Exception as e:
    print(f"Error: {e}")
