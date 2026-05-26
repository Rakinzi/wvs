import click
from flask import current_app
from flask.cli import with_appcontext
from app import db
from app.models import MaliciousSite, ScanResult, User
import requests
import json
from datetime import datetime, timedelta
import os
import sqlite3
from app.utils.time_utils import utc_now
from app.utils.ux_screenshot_manager import collect_screenshot_paths

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Create and initialize the database."""
    db.create_all()
    click.echo('Initialized the database.')

@click.command('migrate-legacy-sqlite')
@with_appcontext
def migrate_legacy_sqlite_command():
    """Import legacy instance/scans.db rows into the default SQLite database when present."""
    instance_dir = os.path.join(os.getcwd(), 'instance')
    legacy_path = os.path.join(instance_dir, 'scans.db')
    default_path = os.path.join(instance_dir, 'wvs.db')

    if not os.path.exists(legacy_path):
        click.echo('No legacy scans.db file found.')
        return
    if os.path.abspath(legacy_path) == os.path.abspath(default_path):
        click.echo('Legacy and default database paths are the same; nothing to do.')
        return

    legacy = sqlite3.connect(legacy_path)
    legacy.row_factory = sqlite3.Row

    try:
        imported_users = 0
        for row in legacy.execute("SELECT username, password, email, is_admin FROM user"):
            existing = User.query.filter_by(username=row["username"]).first()
            if existing:
                continue
            user = User(
                username=row["username"],
                password=row["password"],
                email=row["email"],
                is_admin=bool(row["is_admin"]),
            )
            db.session.add(user)
            imported_users += 1

        db.session.commit()
        click.echo(f'Imported {imported_users} users from legacy scans.db')
    finally:
        legacy.close()

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
                            date_added=utc_now()
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


@click.command('cleanup-report-artifacts')
@click.option('--dry-run', is_flag=True, help='Show what would be removed without deleting files or rows.')
@with_appcontext
def cleanup_report_artifacts_command(dry_run):
    """Remove expired scan results, orphaned screenshots, and missing-report references."""
    retention_days = int(current_app.config.get('SCAN_RESULT_RETENTION_DAYS', 90))
    screenshot_retention_days = int(current_app.config.get('SCREENSHOT_RETENTION_DAYS', 30))
    cutoff = utc_now() - timedelta(days=retention_days)
    screenshot_cutoff = utc_now() - timedelta(days=screenshot_retention_days)

    all_scans = ScanResult.query.all()
    referenced_screenshots = set()
    removed_scan_count = 0
    removed_file_count = 0

    for scan in all_scans:
        referenced_screenshots.update(collect_screenshot_paths(scan.findings or {}))

    expired_scans = ScanResult.query.filter(ScanResult.timestamp < cutoff).all()
    for scan in expired_scans:
        for path in collect_screenshot_paths(scan.findings or {}):
            if os.path.exists(path):
                click.echo(f"remove screenshot {path}")
                if not dry_run:
                    os.remove(path)
                removed_file_count += 1
        if scan.report_path and os.path.exists(scan.report_path):
            click.echo(f"remove report {scan.report_path}")
            if not dry_run:
                os.remove(scan.report_path)
            removed_file_count += 1
        click.echo(f"remove scan result {scan.public_id}")
        if not dry_run:
            db.session.delete(scan)
        removed_scan_count += 1

    screenshot_root = current_app.config.get('UX_SCAN_SCREENSHOT_DIR')
    if screenshot_root and os.path.isdir(screenshot_root):
        for name in os.listdir(screenshot_root):
            path = os.path.join(screenshot_root, name)
            if path in referenced_screenshots:
                continue
            if not os.path.isfile(path):
                continue
            modified_at = datetime.utcfromtimestamp(os.path.getmtime(path))
            if modified_at >= screenshot_cutoff:
                continue
            click.echo(f"remove orphan screenshot {path}")
            if not dry_run:
                os.remove(path)
            removed_file_count += 1

    if not dry_run:
        db.session.commit()

    click.echo(
        f"Cleanup complete. Removed {removed_scan_count} expired scan rows and {removed_file_count} files."
    )

def register_commands(app):
    app.cli.add_command(init_db_command)
    app.cli.add_command(migrate_legacy_sqlite_command)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(update_blocklist_command)
    app.cli.add_command(cleanup_report_artifacts_command)
