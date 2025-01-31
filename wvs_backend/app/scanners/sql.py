import requests
from bs4 import BeautifulSoup

class SQLInjectionScanner:
    def __init__(self):
        self.sql_errors = [
            'SQL syntax', 'mysql_fetch', 'syntax error',
            'unclosed quotation', 'ODBC Driver', 'ORA-'
        ]

    def check(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            return self._test_forms(url, soup)
        except:
            return []

    def _test_forms(self, url, soup):
        vulnerabilities = []
        test_payloads = ["' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--"]
        
        for form in soup.find_all('form'):
            for payload in test_payloads:
                if self._test_form(form, url, payload):
                    vulnerabilities.append({
                        'form': str(form),
                        'payload': payload,
                        'severity': 'High'
                    })
        return vulnerabilities

    def _test_form(self, form, base_url, payload):
        try:
            form_data = {inp.get('name'): payload for inp in form.find_all('input')}
            action = form.get('action', base_url)
            method = form.get('method', 'get').upper()
            
            response = requests.request(
                method,
                action,
                data=form_data,
                timeout=5
            )
            
            return any(error in response.text for error in self.sql_errors)
        except:
            return False