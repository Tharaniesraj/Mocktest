import sqlite3
import os
from datetime import datetime

def repair_database(db_path):
    # Backup the original database
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        # Create backup
        if os.path.exists(db_path):
            with open(db_path, 'rb') as source:
                with open(backup_path, 'wb') as target:
                    target.write(source.read())
            print(f"Backup created at: {backup_path}")

        # Try to create a new connection and force recovery
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Try to run a simple query to check if database is accessible
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        print("Available tables:", tables)
        
        # Perform integrity check
        cursor.execute("PRAGMA integrity_check")
        result = cursor.fetchone()
        print("Integrity check result:", result[0])
        
        conn.close()
        print("Database repair attempt completed.")
        
    except Exception as e:
        print(f"Error during repair: {str(e)}")
        print("You may need to restore from the backup or recreate the database.")

if __name__ == "__main__":
    db_path = "instance/mock_test.db"  # Adjust this path if your database is in a different location
    repair_database(db_path)
