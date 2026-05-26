# app/tasks/ssl_checks.py
import socket
import ssl
import certifi
from urllib.parse import urlparse
from datetime import timedelta

from celery import shared_task
from sqlalchemy import cast, String
from app import db
from app.models import ScanResult

@shared_task(name='app.tasks.check_ssl_tls_updates')
def check_ssl_tls_updates():
    """
    Celery task that checks websites previously flagged as not having valid SSL/TLS
    certificates. If they now have valid certificates, they will be removed from the
    database as they are now secure.
    """
    # Find scan results with SSL issues from the last 30 days
    scan_results = ScanResult.query.filter(
        cast(ScanResult.findings['ssl']['valid'], String) == 'false'
    ).all()
    
    removed_count = 0
    
    for scan in scan_results:
        url = scan.url
        hostname = urlparse(url).netloc
        port = 443  # Default HTTPS port
        
        try:
            # Check if the site now has a valid SSL certificate
            ssl_valid, ssl_info = verify_ssl_certificate(hostname, port)
            
            if ssl_valid:
                # Site is now secure, remove from database
                db.session.delete(scan)
                removed_count += 1
                print(f"Removed {url} from database - now has valid SSL certificate")
        except Exception as e:
            print(f"Error checking SSL for {url}: {str(e)}")
            # Continue with the next site even if there's an error
    
    # Commit all changes at once
    if removed_count > 0:
        db.session.commit()
        print(f"Removed {removed_count} entries from the database that now have valid SSL certificates")
    
    return removed_count

def verify_ssl_certificate(hostname, port=443):
    """
    Verify SSL certificate for a given hostname and port.
    
    Returns:
        tuple: (is_valid, certificate_info) where:
            - is_valid (bool): True if certificate is valid, False otherwise
            - certificate_info (dict): Dictionary with certificate details or None on error
    """
    context = ssl.create_default_context(cafile=certifi.where())
    
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Certificate is valid if we got here
                cert_info = {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'expires': cert['notAfter'],
                    'protocol': ssock.version(),
                    'self_signed': dict(x[0] for x in cert['issuer']) == dict(x[0] for x in cert['subject'])
                }
                
                return True, cert_info
    
    except (socket.gaierror, socket.timeout):
        return False, {'error': 'Connection failed or timed out'}
    except ssl.SSLError as e:
        return False, {'error': f'SSL Error: {str(e)}'}
    except Exception as e:
        return False, {'error': str(e)}