import sqlite3

def apply_schema_changes():
    conn = sqlite3.connect('picchat.db')
    cursor = conn.cursor()
    
    # Add the created_at column to the conversations table
    cursor.execute('ALTER TABLE conversations ADD COLUMN created_at TEXT')
    
    conn.commit()
    conn.close()

apply_schema_changes()