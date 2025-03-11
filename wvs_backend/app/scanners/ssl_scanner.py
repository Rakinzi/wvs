import socket
import ssl
import certifi
from urllib.parse import urlparse

class SSLScanner:
    def check(self, url):
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return {'valid': False, 'error': 'Invalid URL'}

            context = ssl.create_default_context(cafile=certifi.where())
           
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expires': cert['notAfter'],
                        'protocol': ssock.version(),
                        'self_signed': dict(x[0] for x in cert['issuer']) == dict(x[0] for x in cert['subject'])
                    }
        except (socket.gaierror, socket.timeout):
            return {'valid': False, 'error': 'Connection failed or timed out'}
        except ssl.SSLError as e:
            return {'valid': False, 'error': f'SSL Error: {str(e)}'}
        except Exception as e:
            return {'valid': False, 'error': str(e)}