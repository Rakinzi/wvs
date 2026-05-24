from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import dns.exception

_SEVERITY_WEIGHT = {"High": 20, "Medium": 12, "Low": 5}

# Known DMARC policies and their risk
_DMARC_WEAK_POLICIES = {"none"}  # p=none only monitors, doesn't block spoofed mail

# Recommended SPF mechanisms — anything else warrants a note
_SPF_DANGEROUS_ALL = {"+all"}  # +all allows anyone to send mail as this domain

# DNSSEC trust anchors we can verify (resolver-level)
_DNSSEC_AD_FLAG = True


class DNSScanner:
    def __init__(self, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    def _query(self, name: str, rdtype: str) -> list[str]:
        try:
            answers = self.resolver.resolve(name, rdtype)
            return [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return []

    def _check_spf(self, domain: str, issues: list, recs: list) -> dict:
        txts = self._query(domain, "TXT")
        spf_records = [t.strip('"') for t in txts if t.strip('"').startswith("v=spf1")]

        if not spf_records:
            issues.append({
                "name": "No SPF record",
                "severity": "High",
                "evidence": f"No SPF TXT record found for {domain}. Attackers can send spoofed email appearing to come from this domain.",
            })
            recs.append("Add an SPF record: v=spf1 include:<your-mail-provider> -all")
            return {"present": False}

        if len(spf_records) > 1:
            issues.append({
                "name": "Multiple SPF records",
                "severity": "High",
                "evidence": f"Found {len(spf_records)} SPF records — RFC 7208 requires exactly one.",
            })
            recs.append("Consolidate all SPF records into a single TXT record.")

        spf = spf_records[0]
        result = {"present": True, "record": spf}

        if "+all" in spf:
            issues.append({
                "name": "SPF allows all senders (+all)",
                "severity": "High",
                "evidence": f"SPF ends with +all, which means any server can send email as {domain}.",
            })
            recs.append("Replace +all with -all (hard fail) or ~all (soft fail) in your SPF record.")

        if "~all" in spf:
            issues.append({
                "name": "SPF soft fail (~all)",
                "severity": "Low",
                "evidence": "~all marks unauthorized senders as suspicious but does not reject them. Use -all for enforcement.",
            })
            recs.append("Consider changing ~all to -all in your SPF record for strict enforcement.")

        # Count DNS lookups — SPF has a 10-lookup limit
        lookup_mechanisms = ["include:", "a:", "mx:", "exists:", "redirect=", "a ", "mx "]
        lookup_count = sum(spf.count(m) for m in lookup_mechanisms)
        if lookup_count > 10:
            issues.append({
                "name": "SPF lookup limit exceeded",
                "severity": "Medium",
                "evidence": f"Estimated {lookup_count} DNS lookups in SPF chain — RFC 7208 limit is 10. Excess lookups cause SPF to fail.",
            })
            recs.append("Flatten your SPF record to reduce DNS lookups below the 10-lookup limit.")

        return result

    def _check_dmarc(self, domain: str, issues: list, recs: list) -> dict:
        records = self._query(f"_dmarc.{domain}", "TXT")
        dmarc_records = [r.strip('"') for r in records if "v=DMARC1" in r]

        if not dmarc_records:
            issues.append({
                "name": "No DMARC record",
                "severity": "High",
                "evidence": f"No DMARC TXT record found at _dmarc.{domain}. Without DMARC, SPF and DKIM results are not enforced.",
            })
            recs.append("Add a DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com")
            return {"present": False}

        dmarc = dmarc_records[0]
        result = {"present": True, "record": dmarc}

        # Extract policy
        policy = ""
        for part in dmarc.split(";"):
            part = part.strip()
            if part.startswith("p="):
                policy = part[2:].strip().lower()
                break

        result["policy"] = policy

        if policy == "none":
            issues.append({
                "name": "DMARC policy set to none (monitor only)",
                "severity": "Medium",
                "evidence": f"p=none means spoofed emails are not rejected or quarantined — only reported.",
            })
            recs.append("Upgrade DMARC policy from p=none to p=quarantine, then p=reject once you have confirmed legitimate mail flows.")

        if "rua=" not in dmarc and "ruf=" not in dmarc:
            issues.append({
                "name": "DMARC has no reporting address",
                "severity": "Low",
                "evidence": "No rua or ruf tag — you will not receive aggregate or forensic failure reports.",
            })
            recs.append("Add rua=mailto:dmarc-reports@yourdomain.com to receive DMARC aggregate reports.")

        if "sp=" not in dmarc:
            issues.append({
                "name": "DMARC subdomain policy not set",
                "severity": "Low",
                "evidence": "Without sp=, subdomains inherit the root policy which may not be intended.",
            })
            recs.append("Add sp=reject to your DMARC record to apply the same policy to all subdomains.")

        return result

    def _check_dkim(self, domain: str, issues: list, recs: list) -> dict:
        # Check common selectors — we can't enumerate all selectors without zone transfer,
        # but checking the most common ones gives a reasonable signal.
        common_selectors = ["default", "google", "mail", "k1", "selector1", "selector2", "dkim", "email", "smtp"]
        found_selectors = []

        for sel in common_selectors:
            records = self._query(f"{sel}._domainkey.{domain}", "TXT")
            if any("v=DKIM1" in r for r in records):
                found_selectors.append(sel)

        result = {"selectors_found": found_selectors}

        if not found_selectors:
            issues.append({
                "name": "No DKIM record found (common selectors checked)",
                "severity": "Medium",
                "evidence": f"None of the common DKIM selectors ({', '.join(common_selectors)}) returned a DKIM1 record for {domain}.",
            })
            recs.append("Configure DKIM signing on your mail server and publish the public key as a TXT record at <selector>._domainkey.<domain>.")
        else:
            # Check key size for found selectors
            for sel in found_selectors:
                records = self._query(f"{sel}._domainkey.{domain}", "TXT")
                full = " ".join(r.strip('"') for r in records)
                if "p=" in full:
                    # Base64 key length — RSA 1024 is ~172 chars, 2048 is ~344
                    p_start = full.find("p=") + 2
                    p_end = full.find(";", p_start) if ";" in full[p_start:] else len(full)
                    key_b64 = full[p_start:p_end].replace(" ", "").strip()
                    if 0 < len(key_b64) < 216:
                        issues.append({
                            "name": f"DKIM key possibly weak (selector: {sel})",
                            "severity": "Medium",
                            "evidence": f"Base64 key length ({len(key_b64)} chars) suggests an RSA key shorter than 2048 bits.",
                        })
                        recs.append(f"Rotate DKIM key for selector '{sel}' to at least 2048-bit RSA.")

        return result

    def _check_dnssec(self, domain: str, issues: list, recs: list) -> dict:
        # Check for DS record at parent (presence indicates DNSSEC delegation is set up)
        ds_records = self._query(domain, "DS")
        dnskey_records = self._query(domain, "DNSKEY")

        if not ds_records and not dnskey_records:
            issues.append({
                "name": "DNSSEC not enabled",
                "severity": "Low",
                "evidence": f"No DS or DNSKEY records found for {domain}. DNSSEC prevents DNS cache poisoning attacks.",
            })
            recs.append("Enable DNSSEC for your domain — configure it at your DNS registrar and publish DS records.")
            return {"enabled": False}

        return {"enabled": True, "dnskey_count": len(dnskey_records)}

    def _check_mx(self, domain: str, issues: list, recs: list) -> dict:
        mx_records = self._query(domain, "MX")
        if not mx_records:
            return {"present": False, "records": []}

        # Check for null MX (RFC 7505) — intentionally no mail
        null_mx = [r for r in mx_records if r.strip().endswith(". 0 .") or " 0 ." in r]
        return {"present": True, "records": mx_records[:10], "null_mx": bool(null_mx)}

    def _check_caa(self, domain: str, issues: list, recs: list) -> dict:
        caa_records = self._query(domain, "CAA")
        if not caa_records:
            issues.append({
                "name": "No CAA record",
                "severity": "Low",
                "evidence": f"No CAA record for {domain}. Any CA can issue certificates for this domain.",
            })
            recs.append("Add CAA records to restrict which certificate authorities may issue certificates for your domain. Example: 0 issue \"letsencrypt.org\"")
            return {"present": False}

        return {"present": True, "records": caa_records}

    def check(self, url: str) -> dict[str, Any]:
        hostname = urlparse(url).hostname or ""
        # Strip www prefix to get registrable domain for DNS checks
        domain = hostname.lower()
        if domain.startswith("www."):
            domain = domain[4:]

        issues: list[dict] = []
        recs: list[str] = []

        spf = self._check_spf(domain, issues, recs)
        dmarc = self._check_dmarc(domain, issues, recs)
        dkim = self._check_dkim(domain, issues, recs)
        dnssec = self._check_dnssec(domain, issues, recs)
        mx = self._check_mx(domain, issues, recs)
        caa = self._check_caa(domain, issues, recs)

        seen: set[str] = set()
        deduped_recs = [r for r in recs if not (r in seen or seen.add(r))]

        penalty = sum(_SEVERITY_WEIGHT.get(i["severity"], 5) for i in issues)
        score = max(0, 100 - penalty)

        return {
            "status": "issues_found" if issues else "ok",
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "dnssec": dnssec,
            "mx": mx,
            "caa": caa,
            "issues": issues,
            "recommendations": deduped_recs,
            "score": score,
        }
