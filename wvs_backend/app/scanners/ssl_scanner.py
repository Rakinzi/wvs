from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import certifi

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "IDEA", "EXPORT", "NULL", "ANON", "MD5",
    "RC2", "SEED", "CAMELLIA128", "DH",
}
# Ciphers without forward secrecy (RSA key exchange)
_NO_PFS_PATTERNS = {"TLS_RSA_WITH", "SSL_RSA_WITH"}
_EXPIRY_WARNING_DAYS = 30


def _parse_cert_dt(value: str) -> datetime:
    dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    return dt.replace(tzinfo=timezone.utc)


class SSLScanner:
    def check(self, url: str) -> dict:
        hostname = urlparse(url).hostname
        if not hostname:
            return {"valid": False, "error": "Invalid URL"}

        # Always probe on 443 for TLS details
        port = urlparse(url).port or 443

        # --- standard validation pass ---
        ctx = ssl.create_default_context(cafile=certifi.where())
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher_name, protocol, _ = ssock.cipher()
        except socket.gaierror:
            return {"valid": False, "error": "DNS resolution failed"}
        except socket.timeout:
            return {"valid": False, "error": "Connection timed out"}
        except ssl.SSLCertVerificationError as exc:
            # Still try to grab cert details with verification disabled
            return self._invalid_cert(hostname, port, str(exc))
        except ssl.SSLError as exc:
            return {"valid": False, "error": f"SSL error: {exc}"}
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_after = cert.get("notAfter", "")

        result: dict = {
            "valid": True,
            "issuer": issuer,
            "subject": subject,
            "expires": not_after,
            "protocol": protocol,
            "cipher": cipher_name,
            "self_signed": issuer == subject,
            "issues": [],
        }

        # Expiry
        try:
            expiry_dt = _parse_cert_dt(not_after)
            now = datetime.now(timezone.utc)
            days_left = (expiry_dt - now).days
            result["days_until_expiry"] = days_left
            if days_left < 0:
                result["valid"] = False
                result["issues"].append({
                    "name": "Certificate expired",
                    "severity": "Critical",
                    "evidence": f"Expired {abs(days_left)} day(s) ago ({not_after})",
                })
            elif days_left < _EXPIRY_WARNING_DAYS:
                result["issues"].append({
                    "name": "Certificate expiring soon",
                    "severity": "High",
                    "evidence": f"Expires in {days_left} day(s) ({not_after})",
                })
        except (ValueError, TypeError):
            pass

        # Self-signed
        if result["self_signed"]:
            result["issues"].append({
                "name": "Self-signed certificate",
                "severity": "High",
                "evidence": "Issuer and subject are the same — not trusted by browsers.",
            })

        # Weak protocol
        if protocol in _WEAK_PROTOCOLS:
            result["valid"] = False
            result["issues"].append({
                "name": f"Weak TLS protocol: {protocol}",
                "severity": "Critical",
                "evidence": f"Negotiated {protocol} — deprecated and vulnerable to known attacks.",
            })

        # Weak cipher
        cipher_upper = cipher_name.upper()
        for weak in _WEAK_CIPHERS:
            if weak in cipher_upper:
                result["issues"].append({
                    "name": f"Weak cipher suite: {cipher_name}",
                    "severity": "High",
                    "evidence": f"Cipher contains {weak} which is considered cryptographically weak.",
                })
                break

        # No forward secrecy (RSA key exchange)
        for pattern in _NO_PFS_PATTERNS:
            if cipher_upper.startswith(pattern):
                result["issues"].append({
                    "name": "No forward secrecy",
                    "severity": "Medium",
                    "evidence": f"{cipher_name} uses RSA key exchange — past sessions can be decrypted if the private key is compromised.",
                })
                break

        # TLS 1.3 not negotiated
        if protocol != "TLSv1.3":
            result["issues"].append({
                "name": "TLS 1.3 not negotiated",
                "severity": "Low",
                "evidence": f"Connection negotiated {protocol}. TLS 1.3 is faster and more secure; enable it on the server.",
            })

        # SAN hostname validation
        san_names: list[str] = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                san_names.append(san_value.lower())
        if san_names:
            hn = hostname.lower()
            matched = any(
                hn == s or (s.startswith("*.") and hn.endswith(s[1:]) and "." in hn)
                for s in san_names
            )
            if not matched:
                result["issues"].append({
                    "name": "Hostname not in SAN",
                    "severity": "High",
                    "evidence": f"{hostname} does not match any Subject Alternative Name: {', '.join(san_names[:5])}",
                })
        else:
            result["issues"].append({
                "name": "No Subject Alternative Names",
                "severity": "High",
                "evidence": "Certificate has no SANs — modern browsers require SANs and ignore the Common Name.",
            })

        # Weak signature algorithm
        sig_alg = cert.get("signatureAlgorithm", "")
        if "sha1" in sig_alg.lower():
            result["issues"].append({
                "name": "SHA-1 signature algorithm",
                "severity": "High",
                "evidence": f"Certificate signed with {sig_alg} — SHA-1 is cryptographically broken.",
            })
        elif "md5" in sig_alg.lower():
            result["issues"].append({
                "name": "MD5 signature algorithm",
                "severity": "Critical",
                "evidence": f"Certificate signed with {sig_alg} — MD5 is completely broken.",
            })

        # Key size (only available for RSA via public key bits)
        pub_key = cert.get("publicKey", {})
        key_size = pub_key.get("bits") if isinstance(pub_key, dict) else None
        if key_size and int(key_size) < 2048:
            result["issues"].append({
                "name": "Weak RSA key size",
                "severity": "Critical",
                "evidence": f"RSA key is {key_size} bits — minimum is 2048 bits.",
            })

        result["san_names"] = san_names

        if result["issues"] and result["valid"]:
            result["has_warnings"] = True

        return result

    def _invalid_cert(self, hostname: str, port: int, error: str) -> dict:
        # Try unverified to get cert metadata for the report
        ctx_nv = ssl.create_default_context()
        ctx_nv.check_hostname = False
        ctx_nv.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx_nv.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher_name, protocol, _ = ssock.cipher()
            issuer = dict(x[0] for x in cert.get("issuer", [])) if cert else {}
            subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
            return {
                "valid": False,
                "error": error,
                "issuer": issuer,
                "subject": subject,
                "expires": cert.get("notAfter") if cert else None,
                "protocol": protocol,
                "cipher": cipher_name,
                "self_signed": issuer == subject,
            }
        except Exception:
            return {"valid": False, "error": error}
