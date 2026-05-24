import sqlite3
import os
import json

DEFAULT_DB_PATH = 'instance/wvs.db'
LEGACY_DB_PATH = 'instance/scans.db'

def init_sqlite_db(db_path=DEFAULT_DB_PATH):
    """Initialize the SQLite database with the required tables if using SQLite."""
    # Ensure the db directory exists
    if not os.path.exists('instance'):
        os.makedirs('instance')
    
    # Connect to the database
    conn = sqlite3.connect(db_path)
    
    # Enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON")
    
    cursor = conn.cursor()
    
    # Drop existing tables to ensure clean start
    cursor.execute("DROP TABLE IF EXISTS blocked_request")
    cursor.execute("DROP TABLE IF EXISTS scan_result")
    cursor.execute("DROP TABLE IF EXISTS malicious_site")
    cursor.execute("DROP TABLE IF EXISTS user")
    
    # Create users table first
    cursor.execute('''
    CREATE TABLE user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create scan results table with foreign key
    cursor.execute('''
    CREATE TABLE scan_result (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        findings TEXT NOT NULL,
        report_path TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES user(id)
    )
    ''')
    
    # Create malicious sites table
    cursor.execute('''
    CREATE TABLE malicious_site (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        url TEXT NOT NULL,
        reason TEXT DEFAULT '',
        source TEXT DEFAULT 'scan',
        date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create blocked requests log
    cursor.execute('''
    CREATE TABLE blocked_request (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reason TEXT
    )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX idx_malicious_domain ON malicious_site (domain)')
    cursor.execute('CREATE INDEX idx_scan_result_user ON scan_result (user_id)')
    cursor.execute('CREATE INDEX idx_scan_result_time ON scan_result (timestamp)')
    
    # Commit the schema changes
    conn.commit()
    
    # Create default admin user
    cursor.execute(
        "INSERT INTO user (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
        ('admin', 'pbkdf2:sha256:260000$IMEHfW0z$77cb53de21659c4dca2f5140b5ce7f3ce75d48e4c98fea91f1b6dbdc81ebe70a', 'admin@example.com', 1)
    )
    
    # Create initial blocked_sites.json file
    if not os.path.exists('blocked_sites.json'):
        with open('blocked_sites.json', 'w') as f:
            json.dump({
                'domains': [
                    'malware.com',
                    'phishing-site.org',
                    'suspicious.net'
                ],
                'patterns': [
                    ".*\\.suspicious\\.[a-z]+", 
                    "temporary-[0-9]+\\.scam"
                ]
            }, f)
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print(f"SQLite database initialized successfully at {db_path}.")
    print("Default admin user created:")
    print("  Username: admin")
    print("  Password: admin123")


def migrate_legacy_sqlite_data():
    """Move legacy scans.db rows into wvs.db when needed."""
    if not os.path.exists(LEGACY_DB_PATH):
        print("Legacy SQLite database not found; nothing to migrate.")
        return
    if not os.path.exists(DEFAULT_DB_PATH):
        init_sqlite_db(DEFAULT_DB_PATH)

    source = sqlite3.connect(LEGACY_DB_PATH)
    target = sqlite3.connect(DEFAULT_DB_PATH)
    source.row_factory = sqlite3.Row
    target.row_factory = sqlite3.Row

    try:
        target.execute("PRAGMA foreign_keys = ON")
        source.execute("PRAGMA foreign_keys = ON")

        target_users = {row["username"] for row in target.execute("SELECT username FROM user")}
        for row in source.execute("SELECT username, password, email, is_admin, created_on FROM user"):
            if row["username"] not in target_users:
                target.execute(
                    "INSERT INTO user (username, password, email, is_admin, created_on) VALUES (?, ?, ?, ?, ?)",
                    (row["username"], row["password"], row["email"], row["is_admin"], row["created_on"]),
                )

        target.commit()
        print(f"Legacy data migration completed from {LEGACY_DB_PATH} to {DEFAULT_DB_PATH}.")
    finally:
        source.close()
        target.close()

if __name__ == "__main__":
    init_sqlite_db()
