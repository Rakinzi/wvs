import requests
from urllib.parse import urlparse
from datetime import datetime
import idna
from OpenSSL import crypto
import socket
import ssl

class SSLScanner:
    def _get_certificate_from_url(self, url):
        try:
            # Disable SSL verification to get the certificate even if it's invalid
            response = requests.get(url, verify=False, timeout=10)
            
            # Get the certificate from the response
            cert_der = response.connection.sock.getpeercert(binary_form=True)
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
            
            # Get the protocol version
            protocol = response.connection.sock.version()
            
            return cert, protocol
        except Exception as e:
            # Fallback method using raw socket if requests fails
            try:
                hostname = urlparse(url).hostname
                context = ssl._create_unverified_context()
                with socket.create_connection((hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                        cert_der = ssl_sock.getpeercert(binary_form=True)
                        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
                        protocol = ssl_sock.version()
                        return cert, protocol
            except Exception as e2:
                raise ConnectionError(f"Failed to fetch certificate: {str(e2)}")

    def _get_component_dict(self, x509name):
        components = {}
        for key, value in x509name.get_components():
            try:
                key = key.decode('utf-8')
                value = value.decode('utf-8')
            except:
                # Handle binary data that can't be decoded
                continue
                
            if key == 'CN':
                components['commonName'] = value
            elif key == 'O':
                components['organizationName'] = value
            elif key == 'C':
                components['countryName'] = value
            elif key == 'OU':
                components['organizationalUnitName'] = value
        return components

    def check(self, url):
        try:
            if not url.startswith('http'):
                url = f'https://{url}'
                
            cert, protocol = self._get_certificate_from_url(url)
            
            # Get certificate details
            issuer = self._get_component_dict(cert.get_issuer())
            subject = self._get_component_dict(cert.get_subject())
            
            # Get validity dates
            not_before = datetime.strptime(
                cert.get_notBefore().decode('ascii'), 
                '%Y%m%d%H%M%SZ'
            )
            not_after = datetime.strptime(
                cert.get_notAfter().decode('ascii'), 
                '%Y%m%d%H%M%SZ'
            )
            
            # Check if certificate has expired
            now = datetime.utcnow()
            is_expired = now > not_after or now < not_before
            
            # Get serial number
            serial_number = hex(cert.get_serial_number())[2:]
            
            return {
                'valid': not is_expired,
                'issuer': issuer,
                'subject': subject,
                'expires': not_after.strftime('%Y%m%d%H%M%SZ'),
                'protocol': protocol,
                'self_signed': issuer == subject,
                'not_before': not_before.strftime('%Y%m%d%H%M%SZ'),
                'not_after': not_after.strftime('%Y%m%d%H%M%SZ'),
                'serial_number': serial_number
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)}


if __name__ == "__main__":
    # Disable SSL verification warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    scanner = SSLScanner()
    test_urls = [
        "https://github.com",
        "https://google.com",
        "https://expired.badssl.com"
    ]
    
    for url in test_urls:
        print(f"\nChecking {url}:")
        result = scanner.check(url)
        print(result)