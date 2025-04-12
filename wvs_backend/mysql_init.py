#!/usr/bin/env python3
import mysql.connector
from mysql.connector import errorcode
import json
import getpass

def create_database(cursor, DB_NAME):
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME} DEFAULT CHARACTER SET 'utf8'")
        print(f"Database '{DB_NAME}' created successfully")
    except mysql.connector.Error as err:
        print(f"Failed creating database: {err}")
        exit(1)

def create_user(cnx, cursor, DB_NAME, username, password):
    try:
        # Create the user if it doesn't exist
        cursor.execute(f"CREATE USER IF NOT EXISTS '{username}'@'localhost' IDENTIFIED BY '{password}'")
        
        # Grant privileges
        cursor.execute(f"GRANT ALL PRIVILEGES ON {DB_NAME}.* TO '{username}'@'localhost'")
        
        # Apply changes
        cursor.execute("FLUSH PRIVILEGES")
        
        print(f"User '{username}' created and granted privileges")
    except mysql.connector.Error as err:
        print(f"Failed creating user: {err}")
        exit(1)

def initialize_database():
    # Default database settings
    DB_NAME = 'wvs_scanner'
    DB_USER = 'wvs_user'
    DB_PASS = 'wvs_password'
    
    # Connection settings
    config = {
        'host': 'localhost',
        'user': 'root',
        'charset': 'utf8mb4',
        'use_unicode': True,
        'get_warnings': True,
    }
    
    # Get root password
    root_password = getpass.getpass("Enter MySQL root password: ")
    config['password'] = root_password
    
    try:
        # Connect to MySQL server
        cnx = mysql.connector.connect(**config)
        cursor = cnx.cursor()
        
        # Create database
        create_database(cursor, DB_NAME)
        
        # Select database
        cursor.execute(f"USE {DB_NAME}")
        
        # Create user and grant privileges
        create_user(cnx, cursor, DB_NAME, DB_USER, DB_PASS)
        
        # Create tables
        tables = {}
        
        tables['user'] = (
            "CREATE TABLE IF NOT EXISTS `user` ("
            "  `id` int(11) NOT NULL AUTO_INCREMENT,"
            "  `username` varchar(50) NOT NULL,"
            "  `password` varchar(255) NOT NULL,"
            "  `email` varchar(100) NOT NULL,"
            "  `is_admin` tinyint(1) NOT NULL DEFAULT '0',"
            "  `created_on` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "  PRIMARY KEY (`id`),"
            "  UNIQUE KEY `username` (`username`),"
            "  UNIQUE KEY `email` (`email`)"
            ") ENGINE=InnoDB"
        )
        
        tables['scan_result'] = (
            "CREATE TABLE IF NOT EXISTS `scan_result` ("
            "  `id` int(11) NOT NULL AUTO_INCREMENT,"
            "  `url` varchar(500) NOT NULL,"
            "  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "  `findings` json NOT NULL,"
            "  `report_path` varchar(255) NOT NULL,"
            "  `user_id` int(11) NOT NULL,"
            "  PRIMARY KEY (`id`),"
            "  KEY `user_id` (`user_id`),"
            "  KEY `timestamp` (`timestamp`),"
            "  CONSTRAINT `scan_result_ibfk_1` FOREIGN KEY (`user_id`)"
            "     REFERENCES `user` (`id`) ON DELETE CASCADE"
            ") ENGINE=InnoDB"
        )
        
        tables['malicious_site'] = (
            "CREATE TABLE IF NOT EXISTS `malicious_site` ("
            "  `id` int(11) NOT NULL AUTO_INCREMENT,"
            "  `domain` varchar(255) NOT NULL,"
            "  `url` varchar(500) NOT NULL,"
            "  `reason` varchar(255) DEFAULT '',"
            "  `source` varchar(50) DEFAULT 'scan',"
            "  `date_added` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "  PRIMARY KEY (`id`),"
            "  UNIQUE KEY `domain` (`domain`),"
            "  KEY `idx_domain` (`domain`)"
            ") ENGINE=InnoDB"
        )
        
        tables['blocked_request'] = (
            "CREATE TABLE IF NOT EXISTS `blocked_request` ("
            "  `id` int(11) NOT NULL AUTO_INCREMENT,"
            "  `url` varchar(500) NOT NULL,"
            "  `ip_address` varchar(50) DEFAULT NULL,"
            "  `user_agent` varchar(500) DEFAULT NULL,"
            "  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "  `reason` varchar(255) DEFAULT NULL,"
            "  PRIMARY KEY (`id`),"
            "  KEY `timestamp` (`timestamp`)"
            ") ENGINE=InnoDB"
        )
        
        # Create each table
        for table_name, table_description in tables.items():
            try:
                print(f"Creating table {table_name}...", end='')
                cursor.execute(table_description)
                print(" OK")
            except mysql.connector.Error as err:
                if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                    print(" already exists")
                else:
                    print(f" {err.msg}")
        
        # Create default admin user
        from werkzeug.security import generate_password_hash
        
        admin_password = generate_password_hash('admin123')
        
        try:
            cursor.execute(
                "INSERT INTO user (username, password, email, is_admin) VALUES (%s, %s, %s, %s)",
                ('admin', admin_password, 'admin@example.com', 1)
            )
            cnx.commit()
            print("Default admin user created")
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_DUP_ENTRY:
                print("Admin user already exists")
            else:
                print(f"Error creating admin user: {err}")
        
        # Create initial blocked_sites.json file
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
        print("Created initial blocked_sites.json file")
        
        print("\nDatabase initialization completed successfully!")
        print("Default admin credentials:")
        print("  Username: admin")
        print("  Password: admin123")
        
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Access denied. Please check your username and password.")
        else:
            print(f"Error: {err}")
    finally:
        if 'cnx' in locals() and cnx.is_connected():
            cursor.close()
            cnx.close()
            print("MySQL connection closed")

if __name__ == "__main__":
    initialize_database()