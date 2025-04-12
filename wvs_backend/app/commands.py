import click
from flask.cli import with_appcontext
from app import db
from app.models import MaliciousSite, User
import requests
import json
from datetime import datetime
from flask_migrate import Migrate
import os

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Create and initialize the database."""
    db.create_all()
    click.echo('Initialized the database.')

@click.command('create-admin')
@click.argument('username')
@click.argument('password')
@click.argument('email')
@with_appcontext
def create_admin_command(username, password, email):
    """Create an admin user."""
    user = User(username=username, email=email, is_admin=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f'Created admin user: {username}')

@click.command('update-blocklist')
@with_appcontext
def update_blocklist_command():
    """Update the malicious sites database from external sources."""
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
    
    total_added = 0
    for source in sources:
        added = 0
        try:
            click.echo(f"Fetching from {source['url']}...")
            response = requests.get(source['url'], timeout=60)
            
            if response.status_code == 200:
                domains = set()
                
                for line in response.text.splitlines():
                    line = line.strip().lower()
                    if not line or line.startswith('#'):
                        continue
                    
                    if '://' in line:
                        from urllib.parse import urlparse
                        parsed = urlparse(line)
                        domain = parsed.netloc
                    else:
                        domain = line
                    
                    if domain and '.' in domain:
                        domains.add(domain)
                
                for domain in domains:
                    existing = MaliciousSite.query.filter_by(domain=domain).first()
                    if not existing:
                        site = MaliciousSite(
                            domain=domain,
                            url=f"http://{domain}",
                            reason=source['reason'],
                            source=source['source'],
                            date_added=datetime.utcnow()
                        )
                        db.session.add(site)
                        added += 1
                        
                        # Commit in batches to avoid memory issues
                        if added % 1000 == 0:
                            db.session.commit()
                            click.echo(f"Added {added} domains so far...")
                
                db.session.commit()
                total_added += added
                click.echo(f"Added {added} domains from {source['source']}")
                
        except Exception as e:
            click.echo(f"Error processing {source['url']}: {str(e)}")
    
    # Update local JSON file for quick access by MITM proxy
    try:
        sites = MaliciousSite.query.all()
        domains = [site.domain for site in sites]
        
        with open('blocked_sites.json', 'w') as f:
            json.dump({
                'domains': domains,
                'patterns': [
                    ".*\\.suspicious\\.[a-z]+",
                    "temporary-[0-9]+\\.scam",
                    ".*\\.phishing\\.[a-z]+"
                ]
            }, f)
        
        click.echo(f"Updated blocked_sites.json with {len(domains)} domains")
    except Exception as e:
        click.echo(f"Error updating JSON file: {str(e)}")
    
    click.echo(f"Added a total of {total_added} new domains to the database")

def register_commands(app):
    app.cli.add_command(init_db_command)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(update_blocklist_command)