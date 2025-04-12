#!/usr/bin/env python3
import requests
import json
from urllib.parse import urlparse
import os
import sys
import mysql.connector
from datetime import datetime

def fetch_domains_from_sources():
    """Fetch malicious domains from multiple sources"""
    print("[+] Fetching malicious domains from external sources...")
    
    sources = [
        {
            'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
            'type': 'text',
            'reason': 'Phishing site',
            'source': 'mitchellkrogza'
        },
        {
            'url': 'https://urlhaus.abuse.ch/downloads/text/',
            'type': 'text',
            'reason': 'Malware distribution',
            'source': 'urlhaus'
        },
        {
            'url': 'https://openphish.com/feed.txt',
            'type': 'text',
            'reason': 'Phishing site',
            'source': 'openphish'
        }
    ]
    
    domains = {}
    
    for source in sources:
        try:
            print(f"[*] Fetching from {source['url']}...")
            response = requests.get(source['url'], timeout=60)
            
            if response.status_code == 200:
                count = 0
                for line in response.text.splitlines():
                    line = line.strip().lower()
                    if not line or line.startswith('#'):
                        continue
                    
                    if '://' in line:
                        parsed = urlparse(line)
                        domain = parsed.netloc
                    else:
                        domain = line
                    
                    if domain and '.' in domain:
                        domains[domain] = {
                            'reason': source['reason'],
                            'source': source['source']
                        }
                        count += 1
                
                print(f"[+] Found {count} domains from {source['source']}")
        except Exception as e:
            print(f"[-] Error processing {source['url']}: {str(e)}")
    
    print(f"[+] Total unique domains: {len(domains)}")
    return domains

def update_mysql_database(domains):
    """Update the MySQL database with the fetched domains"""
    # Database connection parameters
    config = {
        'host': 'localhost',
        'user': 'wvs_user',
        'password': 'wvs_password',
        'database': 'wvs_scanner'
    }
    
    try:
        # Connect to MySQL
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        
        # Create the table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS malicious_site (
            id INT AUTO_INCREMENT PRIMARY KEY,
            domain VARCHAR(255) UNIQUE NOT NULL,
            url VARCHAR(500) NOT NULL,
            reason VARCHAR(255) DEFAULT '',
            source VARCHAR(50) DEFAULT 'scan',
            date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Create an index if it doesn't exist
        try:
            cursor.execute("CREATE INDEX idx_malicious_domain ON malicious_site (domain)")
        except:
            # Index might already exist
            pass
        
        # Commit the schema changes
        connection.commit()
        
        # Insert domains in batches to improve performance
        batch_size = 1000
        added = 0
        batch_domains = []
        
        for domain, info in domains.items():
            batch_domains.append((
                domain, 
                f"http://{domain}", 
                info['reason'], 
                info['source']
            ))
            
            if len(batch_domains) >= batch_size:
                try:
                    cursor.executemany(
                        "INSERT IGNORE INTO malicious_site (domain, url, reason, source) VALUES (%s, %s, %s, %s)",
                        batch_domains
                    )
                    connection.commit()
                    added += cursor.rowcount
                    print(f"[*] Added {added} domains so far...")
                    batch_domains = []
                except Exception as e:
                    print(f"[-] Error adding batch: {str(e)}")
                    connection.rollback()
        
        # Insert any remaining domains
        if batch_domains:
            try:
                cursor.executemany(
                    "INSERT IGNORE INTO malicious_site (domain, url, reason, source) VALUES (%s, %s, %s, %s)",
                    batch_domains
                )
                connection.commit()
                added += cursor.rowcount
            except Exception as e:
                print(f"[-] Error adding final batch: {str(e)}")
                connection.rollback()
        
        # Get all domains for the JSON file
        cursor.execute("SELECT domain FROM malicious_site")
        all_domains = [row[0] for row in cursor.fetchall()]
        
        # Create JSON file for quick access by MITM proxy
        with open('blocked_sites.json', 'w') as f:
            json.dump({
                'domains': all_domains,
                'patterns': [
                    ".*\\.suspicious\\.[a-z]+",
                    "temporary-[0-9]+\\.scam",
                    ".*\\.phishing\\.[a-z]+"
                ]
            }, f)
        
        print(f"[+] Added {added} new domains to the database")
        print(f"[+] Updated blocked_sites.json with {len(all_domains)} domains")
        
    except mysql.connector.Error as err:
        print(f"[-] MySQL Error: {err}")
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            print("[+] MySQL connection closed")

def main():
    print("[+] Web Vulnerability Scanner - Malicious Domain Updater")
    domains = fetch_domains_from_sources()
    update_mysql_database(domains)
    print("[+] Update completed successfully")

if __name__ == "__main__":
    main()