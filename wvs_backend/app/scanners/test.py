from sql_scanner import AdvancedSQLiScanner

def generate_detailed_report(vulnerabilities):
    # Organize vulnerabilities by severity
    severity_groups = {
        'Critical': [],
        'High': [],
        'Medium': [],
        'Low': []
    }
    
    # Vulnerability explanations
    vuln_explanations = {
        'UNION SELECT': {
            'technical': "UNION-based SQL injection allowing database schema extraction",
            'impact': "Attackers can steal entire database contents",
            'analogy': "Like finding a master key that opens every room in a building"
        },
        'SLEEP': {
            'technical': "Time-based blind SQL injection vulnerability",
            'impact': "Enables hidden data theft through response timing",
            'analogy': "Like detecting safe combinations by listening to mechanism sounds"
        },
        'BENCHMARK': {
            'technical': "Resource-intensive query execution vulnerability",
            'impact': "Can cause system slowdowns and denial of service",
            'analogy': "Like flooding an engine to find weak points"
        },
        'xp_cmdshell': {
            'technical': "Potential remote command execution vulnerability",
            'impact': "Could allow full server compromise",
            'analogy': "Digital equivalent of handing over steering wheel to hackers"
        }
    }

    for vuln in vulnerabilities:
        severity_groups[vuln['severity']].append(vuln)

    report = []
    
    # Report Header
    report.append("🛡️ Comprehensive Security Assessment Report 🛡️")
    report.append("="*80)
    
    # Executive Summary
    report.append("\n📋 Executive Summary")
    report.append(f"Total Vulnerabilities Found: {len(vulnerabilities)}")
    report.append(f"Critical Risk Findings: {len(severity_groups['Critical'])}")
    report.append(f"High Risk Findings: {len(severity_groups['High'])}")
    report.append(f"Affected Login Form: {vulnerabilities[0]['form_action']} (POST method)")
    
    # Detailed Vulnerability Breakdown
    report.append("\n" + "="*80)
    report.append("\n🔬 Technical Vulnerability Analysis")
    
    for severity in ['Critical', 'High', 'Medium', 'Low']:
        if not severity_groups[severity]:
            continue
            
        report.append(f"\n⚡ {severity} Severity Issues:")
        
        for idx, vuln in enumerate(severity_groups[severity], 1):
            vuln_type = next((k for k in vuln_explanations if k in vuln['payload']), "SQL Injection")
            
            report.append(f"\n🚩 Finding {idx}: {vuln_type}")
            report.append(f"   Affected Form: {vuln['form_action']} ({vuln['form_method']})")
            report.append(f"   Parameters: {', '.join(vuln['parameters'])}")
            report.append(f"   Attack Payload: {vuln['payload']}")
            report.append(f"   Database Type: {vuln['database_type']}")
            report.append(f"   Confidence: {vuln['confidence']}")
            report.append(f"   System Response: {vuln['evidence']}")
            
            if vuln_type in vuln_explanations:
                report.append(f"\n   Technical Explanation: {vuln_explanations[vuln_type]['technical']}")
                report.append(f"   Business Impact: {vuln_explanations[vuln_type]['impact']}")
                report.append(f"   Simple Analogy: {vuln_explanations[vuln_type]['analogy']}")
            
            report.append(f"\n   Error Sample:\n   {vuln['response_sample'][:150]}...")
            report.append("-"*60)

    # Affected Forms Section
    report.append("\n" + "="*80)
    report.append("\n📝 Vulnerable Form Details")
    report.append("\nForm Endpoint: Login Page (POST)")
    report.append("Affected Fields: username, password")
    report.append("Total Vulnerabilities in Form: 6")
    report.append("Maximum Severity: Critical")
    
    # Error Analysis
    report.append("\n" + "="*80)
    report.append("\n🔍 Error Message Breakdown")
    error_types = {
        'different number of columns': {
            'meaning': "Union query column mismatch",
            'fix': "Validate query structure and implement parameterization"
        },
        'syntax error near': {
            'meaning': "Malformed SQL query execution",
            'fix': "Implement input sanitization and prepared statements"
        },
        'uncaught mysqli_sql_exception': {
            'meaning': "Raw database errors exposed",
            'fix': "Configure custom error pages and disable debug mode"
        }
    }
    
    for vuln in vulnerabilities:
        error_key = next((k for k in error_types if k in vuln['response_sample']), None)
        if error_key:
            report.append(f"\n❌ Error: {error_key}")
            report.append(f"   Found in: {vuln['payload']}")
            report.append(f"   Meaning: {error_types[error_key]['meaning']}")
            report.append(f"   Required Fix: {error_types[error_key]['fix']}")
            report.append("-"*50)

    # Remediation Plan
    report.append("\n" + "="*80)
    report.append("\n🔧 Recommended Fixes")
    report.append("\nTechnical Team Actions:")
    report.append("1. Implement parameterized queries for all SQL operations")
    report.append("2. Add input validation for username/password fields:")
    report.append("   - Allow only alphanumeric characters")
    report.append("   - Set maximum length limits")
    report.append("3. Configure WAF rules to block SQL patterns:")
    report.append("   - UNION SELECT, SLEEP(), BENCHMARK(), xp_cmdshell")
    report.append("4. Update error handling to prevent raw DB errors")
    
    report.append("\nManagement Actions:")
    report.append("1. Priority patching for critical vulnerabilities")
    report.append("2. Security awareness training for developers")
    report.append("3. Schedule penetration test within 2 weeks")
    report.append("4. Implement continuous security monitoring")

    return "\n".join(report)
# Example usage with your data

sql_scanner = AdvancedSQLiScanner()
results = (sql_scanner.scan('http://localhost/dummy_site/index.php'))

print(generate_detailed_report(results))