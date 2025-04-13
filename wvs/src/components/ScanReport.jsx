import React, { useState, useEffect } from 'react';
import { 
  FileText, Shield, ArrowLeft, Download, ExternalLink, 
  AlertTriangle, CheckCircle, AlertOctagon, Database, Lock, 
  Info, RefreshCw, ChevronDown, ChevronUp, Share2
} from 'lucide-react';

const ScanReport = ({ scanId, navigateTo }) => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedSections, setExpandedSections] = useState({
    sql: true,
    ssl: true,
    malicious: true
  });

  useEffect(() => {
    document.title = 'Scan Report - Web Vulnernability Scanner';
    fetchReport();
  }, [scanId]);

  const fetchReport = async () => {
    setLoading(true);
    try {
      const response = await fetch(`http://localhost:5000/report/${scanId}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        // Check if response is a PDF
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/pdf')) {
          // Handle PDF report - create a download link
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          
          // Create a simple report object with the PDF URL
          setReport({
            scan_id: scanId,
            url: url,
            isPdf: true,
            findings: null,
            timestamp: new Date().toISOString()
          });
        } else {
          // Handle JSON report
          const data = await response.json();
          setReport(data);
        }
      } else {
        const data = await response.json();
        setError(data.error || 'Failed to fetch report');
      }
    } catch (err) {
      setError('Failed to connect to server');
    } finally {
      setLoading(false);
    }
  };

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const handleBackClick = () => {
    navigateTo('dashboard');
  };

  const handleDownloadPdf = () => {
    if (report && report.isPdf) {
      const a = document.createElement('a');
      a.href = report.url;
      a.download = `scan_report_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } else {
      // In a real app, this would be an API call to get the PDF version
      console.log('PDF download not available for this report');
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 pt-6 pb-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white rounded-lg shadow-lg p-8 flex flex-col items-center justify-center">
            <div className="h-16 w-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
              <RefreshCw size={24} className="text-blue-800 animate-spin" />
            </div>
            <h2 className="text-2xl font-bold text-gray-900 mb-2">Loading report...</h2>
            <p className="text-gray-600">Retrieving scan results for ID: {scanId}</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 pt-6 pb-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white rounded-lg shadow-lg p-8">
            <div className="flex flex-col items-center">
              <div className="h-16 w-16 bg-red-100 rounded-full flex items-center justify-center mb-4">
                <AlertTriangle size={24} className="text-red-600" />
              </div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">Error loading report</h2>
              <p className="text-red-600 mb-6">{error}</p>
              <button
                onClick={handleBackClick}
                className="flex items-center px-4 py-2 bg-blue-800 text-white rounded-md hover:bg-blue-700"
              >
                <ArrowLeft size={16} className="mr-2" />
                Back to Dashboard
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen bg-gray-50 pt-6 pb-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white rounded-lg shadow-lg p-8">
            <div className="flex flex-col items-center">
              <div className="h-16 w-16 bg-yellow-100 rounded-full flex items-center justify-center mb-4">
                <Info size={24} className="text-yellow-600" />
              </div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">Report not found</h2>
              <p className="text-gray-600 mb-6">The requested scan report (ID: {scanId}) could not be found.</p>
              <button
                onClick={handleBackClick}
                className="flex items-center px-4 py-2 bg-blue-800 text-white rounded-md hover:bg-blue-700"
              >
                <ArrowLeft size={16} className="mr-2" />
                Back to Dashboard
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // If the report is a PDF, show a simple viewer with download option
  if (report.isPdf) {
    return (
      <div className="min-h-screen bg-gray-50 pt-6 pb-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="bg-white rounded-lg shadow-lg overflow-hidden">
            <div className="bg-blue-800 px-6 py-4 text-white flex items-center justify-between">
              <div className="flex items-center">
                <FileText size={20} className="mr-2" />
                <h1 className="text-xl font-bold">Scan Report #{scanId}</h1>
              </div>
              <button
                onClick={handleBackClick}
                className="flex items-center text-sm text-white hover:text-blue-200"
              >
                <ArrowLeft size={16} className="mr-1" />
                Back
              </button>
            </div>
            
            <div className="p-6">
              <div className="flex justify-center mb-6">
                <button
                  onClick={handleDownloadPdf}
                  className="flex items-center px-4 py-2 bg-blue-800 text-white rounded-md hover:bg-blue-700 shadow-sm"
                >
                  <Download size={16} className="mr-2" />
                  Download PDF Report
                </button>
              </div>
              
              <div className="border rounded-lg overflow-hidden">
                <iframe 
                  src={report.url} 
                  className="w-full h-screen" 
                  title="Scan Report"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Display JSON report with interactive UI
  const findings = report.findings || {};
  const hasSqlIssues = findings.sqli && findings.sqli.length > 0;
  const hasSslIssues = findings.ssl && !findings.ssl.valid;
  const isMalicious = findings.malicious && findings.malicious.is_malicious;
  
  const totalIssues = (hasSqlIssues ? findings.sqli.length : 0) + 
                      (hasSslIssues ? 1 : 0) + 
                      (isMalicious ? 1 : 0);
  
  const securityScore = totalIssues === 0 ? 100 : Math.max(0, 100 - (totalIssues * 20));

  return (
    <div className="min-h-screen bg-gray-50 pt-6 pb-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-6 flex justify-between items-center">
          <button
            onClick={handleBackClick}
            className="flex items-center text-gray-700 hover:text-blue-800"
          >
            <ArrowLeft size={16} className="mr-1" />
            Back to Dashboard
          </button>
          
          <div className="flex space-x-3">
            <button
              onClick={handleDownloadPdf}
              className="flex items-center px-3 py-1.5 border border-gray-300 rounded-md text-sm text-gray-700 bg-white hover:bg-gray-50 shadow-sm"
            >
              <Download size={14} className="mr-1" />
              Download
            </button>
            <button className="flex items-center px-3 py-1.5 border border-gray-300 rounded-md text-sm text-gray-700 bg-white hover:bg-gray-50 shadow-sm">
              <Share2 size={14} className="mr-1" />
              Share
            </button>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow-lg overflow-hidden mb-6">
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-r from-blue-900 to-blue-700 opacity-90"></div>
            <div className="relative px-6 py-6 text-white">
              <div className="flex flex-col md:flex-row md:items-center md:justify-between">
                <div className="flex items-center mb-4 md:mb-0">
                  <div className="h-12 w-12 bg-white rounded-full flex items-center justify-center shadow-lg mr-4">
                    <Shield size={24} className="text-blue-800" />
                  </div>
                  <div>
                    <div className="text-sm text-blue-200">Scan Report</div>
                    <h1 className="text-2xl font-bold">Security Analysis Results</h1>
                  </div>
                </div>
                
                <div className="flex flex-col items-end">
                  <div className="mb-1 text-sm flex justify-between w-full">
                    <span>Security Score:</span>
                    <span className={`font-bold ${securityScore < 50 ? 'text-red-300' : securityScore < 80 ? 'text-yellow-300' : 'text-green-300'}`}>
                      {securityScore}/100
                    </span>
                  </div>
                  <div className="w-36 bg-blue-800 bg-opacity-50 rounded-full h-2.5">
                    <div 
                      className={`h-2.5 rounded-full ${
                        securityScore < 50 ? 'bg-red-400' : securityScore < 80 ? 'bg-yellow-400' : 'bg-green-400'
                      }`}
                      style={{ width: `${securityScore}%` }}
                    ></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-center">
                <ExternalLink size={16} className="text-gray-500 mr-2" />
                <div>
                  <div className="text-xs text-gray-500">Target URL</div>
                  <a 
                    href={report.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-sm font-medium text-blue-800 hover:underline"
                  >
                    {report.url}
                  </a>
                </div>
              </div>
              
              <div className="flex items-center">
                <FileText size={16} className="text-gray-500 mr-2" />
                <div>
                  <div className="text-xs text-gray-500">Scan ID</div>
                  <div className="text-sm font-medium">{report.scan_id}</div>
                </div>
              </div>
              
              <div className="flex items-center">
                <Info size={16} className="text-gray-500 mr-2" />
                <div>
                  <div className="text-xs text-gray-500">Date & Time</div>
                  <div className="text-sm font-medium">{formatDate(report.timestamp)}</div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="p-6">
            <div className="mb-6">
              <h2 className="text-lg font-bold text-gray-900 mb-2">Executive Summary</h2>
              <p className="text-gray-700">
                {totalIssues > 0 
                  ? `The scan detected ${totalIssues} security ${totalIssues === 1 ? 'issue' : 'issues'} that should be addressed.` 
                  : 'No security issues were detected in this scan.'}
              </p>
              
              {totalIssues > 0 && (
                <ul className="mt-3 space-y-1">
                  {hasSqlIssues && (
                    <li className="flex items-center text-red-700">
                      <AlertTriangle size={14} className="mr-1 flex-shrink-0" />
                      <span>Found {findings.sqli.length} SQL injection {findings.sqli.length === 1 ? 'vulnerability' : 'vulnerabilities'}</span>
                    </li>
                  )}
                  {hasSslIssues && (
                    <li className="flex items-center text-orange-700">
                      <AlertTriangle size={14} className="mr-1 flex-shrink-0" />
                      <span>SSL certificate issue detected</span>
                    </li>
                  )}
                  {isMalicious && (
                    <li className="flex items-center text-purple-700">
                      <AlertTriangle size={14} className="mr-1 flex-shrink-0" />
                      <span>Site identified as potentially malicious</span>
                    </li>
                  )}
                </ul>
              )}
            </div>
            
            {/* SQL Injection Section */}
            <div className="border rounded-lg overflow-hidden mb-6">
              <div 
                className={`px-4 py-3 bg-gray-50 border-b flex items-center justify-between cursor-pointer ${hasSqlIssues ? 'border-red-200' : ''}`}
                onClick={() => toggleSection('sql')}
              >
                <div className="flex items-center">
                  <div className={`mr-3 h-9 w-9 rounded-full flex items-center justify-center ${
                    hasSqlIssues ? 'bg-red-100 text-red-600' : 'bg-green-100 text-green-600'
                  }`}>
                    {hasSqlIssues ? <AlertTriangle size={18} /> : <CheckCircle size={18} />}
                  </div>
                  <div>
                    <h3 className="text-base font-medium text-gray-900">SQL Injection Analysis</h3>
                    <p className="text-xs text-gray-500">
                      {hasSqlIssues 
                        ? `${findings.sqli.length} vulnerabilities detected` 
                        : 'No vulnerabilities detected'}
                    </p>
                  </div>
                </div>
                {expandedSections.sql ? (
                  <ChevronUp size={18} className="text-gray-500" />
                ) : (
                  <ChevronDown size={18} className="text-gray-500" />
                )}
              </div>
              
              {expandedSections.sql && (
                <div className="px-4 py-3">
                  {hasSqlIssues ? (
                    <div>
                      <p className="text-gray-700 mb-4">
                        SQL injection vulnerabilities allow attackers to execute malicious SQL statements to gain unauthorized access to your database.
                      </p>
                      
                      <div className="space-y-4">
                        {findings.sqli.map((vuln, index) => (
                          <div key={index} className="bg-red-50 border border-red-200 rounded-md p-4">
                            <div className="flex items-start">
                              <Database size={18} className="text-red-600 mr-3 mt-0.5 flex-shrink-0" />
                              <div>
                                <h4 className="font-medium text-red-800">Vulnerability {index + 1}: {vuln.type || 'SQL Injection'}</h4>
                                {vuln.parameter && (
                                  <p className="mt-1 text-sm text-red-700">Affected parameter: <code className="bg-red-100 px-1 py-0.5 rounded text-red-800">{vuln.parameter}</code></p>
                                )}
                                {vuln.severity && (
                                  <p className="mt-1 text-sm text-red-700">Severity: <span className="font-medium">{vuln.severity}</span></p>
                                )}
                                {vuln.payload && (
                                  <p className="mt-1 text-sm text-red-700">Test payload: <code className="bg-red-100 px-1 py-0.5 rounded text-red-800">{vuln.payload}</code></p>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                      
                      <div className="mt-4 bg-blue-50 border border-blue-200 rounded-md p-4">
                        <h4 className="font-medium text-blue-800 mb-2">Recommendations</h4>
                        <ul className="list-disc pl-5 space-y-1 text-sm text-blue-700">
                          <li>Use parameterized queries or prepared statements</li>
                          <li>Implement proper input validation and sanitization</li>
                          <li>Apply the principle of least privilege for database users</li>
                          <li>Consider implementing a Web Application Firewall (WAF)</li>
                        </ul>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-6">
                      <div className="inline-flex h-12 w-12 rounded-full bg-green-100 items-center justify-center mb-3">
                        <CheckCircle size={24} className="text-green-600" />
                      </div>
                      <h4 className="text-lg font-medium text-gray-900 mb-1">No SQL Injection Vulnerabilities</h4>
                      <p className="text-gray-600">This website appears to be protected against SQL injection attacks.</p>
                    </div>
                  )}
                </div>
              )}
            </div>
            
            {/* SSL Certificate Section */}
            <div className="border rounded-lg overflow-hidden mb-6">
              <div 
                className={`px-4 py-3 bg-gray-50 border-b flex items-center justify-between cursor-pointer ${hasSslIssues ? 'border-orange-200' : ''}`}
                onClick={() => toggleSection('ssl')}
              >
                <div className="flex items-center">
                  <div className={`mr-3 h-9 w-9 rounded-full flex items-center justify-center ${
                    hasSslIssues ? 'bg-orange-100 text-orange-600' : 'bg-green-100 text-green-600'
                  }`}>
                    {hasSslIssues ? <AlertTriangle size={18} /> : <Lock size={18} />}
                  </div>
                  <div>
                    <h3 className="text-base font-medium text-gray-900">SSL/TLS Certificate Analysis</h3>
                    <p className="text-xs text-gray-500">
                      {hasSslIssues 
                        ? 'SSL certificate issues detected' 
                        : 'Valid SSL certificate'}
                    </p>
                  </div>
                </div>
                {expandedSections.ssl ? (
                  <ChevronUp size={18} className="text-gray-500" />
                ) : (
                  <ChevronDown size={18} className="text-gray-500" />
                )}
              </div>
              
              {expandedSections.ssl && (
                <div className="px-4 py-3">
                  {hasSslIssues ? (
                    <div>
                      <p className="text-gray-700 mb-4">
                        SSL/TLS certificates are essential for secure website connections. Issues with certificates can leave your site vulnerable to attacks and damage user trust.
                      </p>
                      
                      <div className="bg-orange-50 border border-orange-200 rounded-md p-4 mb-4">
                        <div className="flex items-start">
                          <Lock size={18} className="text-orange-600 mr-3 mt-0.5 flex-shrink-0" />
                          <div>
                            <h4 className="font-medium text-orange-800">Certificate Issue</h4>
                            {findings.ssl.error && (
                              <p className="mt-1 text-sm text-orange-700">Error: {findings.ssl.error}</p>
                            )}
                            {findings.ssl.self_signed && (
                              <p className="mt-1 text-sm text-orange-700">Self-signed certificate detected (not trusted by browsers)</p>
                            )}
                            {findings.ssl.expires && (
                              <p className="mt-1 text-sm text-orange-700">Expiration date: {findings.ssl.expires}</p>
                            )}
                          </div>
                        </div>
                      </div>
                      
                      <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                        <h4 className="font-medium text-blue-800 mb-2">Recommendations</h4>
                        <ul className="list-disc pl-5 space-y-1 text-sm text-blue-700">
                          <li>Obtain a valid SSL/TLS certificate from a trusted certificate authority</li>
                          <li>Ensure proper SSL/TLS configuration on your server</li>
                          <li>Use strong cipher suites and modern protocols (TLS 1.2 or higher)</li>
                          <li>Implement HTTP Strict Transport Security (HSTS)</li>
                          <li>Regularly monitor certificate expiration and renew before it expires</li>
                        </ul>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-6">
                      <div className="inline-flex h-12 w-12 rounded-full bg-green-100 items-center justify-center mb-3">
                        <Lock size={24} className="text-green-600" />
                      </div>
                      <h4 className="text-lg font-medium text-gray-900 mb-1">Valid SSL Certificate</h4>
                      <p className="text-gray-600">This website has a properly configured SSL/TLS certificate.</p>
                      
                      {findings.ssl && (
                        <div className="mt-4 text-left max-w-2xl mx-auto">
                          <h5 className="font-medium text-gray-800 mb-2">Certificate Details</h5>
                          <div className="bg-gray-50 rounded-md p-4 text-sm">
                            {findings.ssl.issuer && (
                              <div className="flex mb-2">
                                <span className="font-medium w-28 text-gray-600">Issuer:</span>
                                <span className="text-gray-800">{findings.ssl.issuer.organizationName || findings.ssl.issuer.commonName}</span>
                              </div>
                            )}
                            {findings.ssl.subject && (
                              <div className="flex mb-2">
                                <span className="font-medium w-28 text-gray-600">Subject:</span>
                                <span className="text-gray-800">{findings.ssl.subject.commonName}</span>
                              </div>
                            )}
                            {findings.ssl.expires && (
                              <div className="flex mb-2">
                                <span className="font-medium w-28 text-gray-600">Expires:</span>
                                <span className="text-gray-800">{findings.ssl.expires}</span>
                              </div>
                            )}
                            {findings.ssl.protocol && (
                              <div className="flex">
                                <span className="font-medium w-28 text-gray-600">Protocol:</span>
                                <span className="text-gray-800">{findings.ssl.protocol}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
            
            {/* Malicious Content Section */}
            <div className="border rounded-lg overflow-hidden mb-6">
              <div 
                className={`px-4 py-3 bg-gray-50 border-b flex items-center justify-between cursor-pointer ${isMalicious ? 'border-purple-200' : ''}`}
                onClick={() => toggleSection('malicious')}
              >
                <div className="flex items-center">
                  <div className={`mr-3 h-9 w-9 rounded-full flex items-center justify-center ${
                    isMalicious ? 'bg-purple-100 text-purple-600' : 'bg-green-100 text-green-600'
                  }`}>
                    {isMalicious ? <AlertOctagon size={18} /> : <CheckCircle size={18} />}
                  </div>
                  <div>
                    <h3 className="text-base font-medium text-gray-900">Malicious Content Analysis</h3>
                    <p className="text-xs text-gray-500">
                      {isMalicious 
                        ? 'Site potentially malicious' 
                        : 'No malicious content detected'}
                    </p>
                  </div>
                </div>
                {expandedSections.malicious ? (
                  <ChevronUp size={18} className="text-gray-500" />
                ) : (
                  <ChevronDown size={18} className="text-gray-500" />
                )}
              </div>
              
              {expandedSections.malicious && (
                <div className="px-4 py-3">
                  {isMalicious ? (
                    <div>
                      <p className="text-gray-700 mb-4">
                        This website has been identified as potentially malicious. It may contain phishing attempts, malware, or other harmful content.
                      </p>
                      
                      <div className="bg-purple-50 border border-purple-200 rounded-md p-4 mb-4">
                        <div className="flex items-start">
                          <AlertOctagon size={18} className="text-purple-600 mr-3 mt-0.5 flex-shrink-0" />
                          <div>
                            <h4 className="font-medium text-purple-800">Malicious Indicators</h4>
                            <p className="mt-1 text-sm text-purple-700">Threat Score: {findings.malicious.score}/10</p>
                            
                            {findings.malicious.phishing_match && (
                              <p className="mt-1 text-sm text-purple-700">✗ Domain matches known phishing patterns</p>
                            )}
                            
                            {findings.malicious.dnsbl && findings.malicious.dnsbl.blacklisted && (
                              <p className="mt-1 text-sm text-purple-700">
                                ✗ Listed in {findings.malicious.dnsbl.total_detected} DNS blacklists
                              </p>
                            )}
                            
                            {findings.malicious.score_reasons && findings.malicious.score_reasons.length > 0 && (
                              <div className="mt-2">
                                <p className="text-sm font-medium text-purple-700">Additional flags:</p>
                                <ul className="list-disc pl-5 space-y-0.5 text-sm text-purple-700 mt-1">
                                  {findings.malicious.score_reasons.map((reason, index) => (
                                    <li key={index}>{reason}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                      
                      <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                        <h4 className="font-medium text-blue-800 mb-2">Recommendations</h4>
                        <ul className="list-disc pl-5 space-y-1 text-sm text-blue-700">
                          <li>Avoid sharing sensitive information on this website</li>
                          <li>Block access to this domain in your organization</li>
                          <li>If this is your website, investigate potential compromise</li>
                          <li>Run a comprehensive malware scan on your server</li>
                        </ul>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-6">
                      <div className="inline-flex h-12 w-12 rounded-full bg-green-100 items-center justify-center mb-3">
                        <CheckCircle size={24} className="text-green-600" />
                      </div>
                      <h4 className="text-lg font-medium text-gray-900 mb-1">No Malicious Content Detected</h4>
                      <p className="text-gray-600">This website does not appear to contain malicious content.</p>
                      
                      {findings.malicious && findings.malicious.score !== undefined && (
                        <div className="mt-4 flex items-center justify-center">
                          <span className="text-sm text-gray-600 mr-2">Threat Score:</span>
                          <div className="w-48 bg-gray-200 rounded-full h-1.5 mr-2">
                            <div 
                              className="bg-green-500 h-1.5 rounded-full" 
                              style={{ width: `${findings.malicious.score * 10}%` }}
                            ></div>
                          </div>
                          <span className="text-xs text-gray-500">{findings.malicious.score}/10</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
            
            {/* Conclusion */}
            <div className="bg-gray-50 border rounded-lg p-6">
              <h2 className="text-lg font-bold text-gray-900 mb-3">Conclusion & Next Steps</h2>
              
              {totalIssues > 0 ? (
                <div>
                  <p className="text-gray-700 mb-3">
                    This scan identified {totalIssues} security {totalIssues === 1 ? 'issue' : 'issues'} that should be addressed to improve your website's security posture.
                  </p>
                  
                  <h3 className="font-medium text-gray-800 mb-2">Recommended Actions:</h3>
                  <ol className="list-decimal pl-5 space-y-2 text-gray-700">
                    {hasSqlIssues && (
                      <li>
                        <span className="font-medium">Fix SQL Injection Vulnerabilities:</span> Implement parameterized queries and input validation to prevent SQL injection attacks.
                      </li>
                    )}
                    {hasSslIssues && (
                      <li>
                        <span className="font-medium">Resolve SSL Certificate Issues:</span> Obtain a valid SSL certificate from a trusted certificate authority and configure it properly.
                      </li>
                    )}
                    {isMalicious && (
                      <li>
                        <span className="font-medium">Investigate Malicious Content:</span> Check for unauthorized changes, malware, or phishing content on your website.
                      </li>
                    )}
                    <li>
                      <span className="font-medium">Regular Scanning:</span> Schedule regular security scans to monitor for new vulnerabilities.
                    </li>
                  </ol>
                </div>
              ) : (
                <div>
                  <p className="text-gray-700 mb-3">
                    No security issues were detected in this scan. Your website appears to be well-protected against common vulnerabilities.
                  </p>
                  
                  <h3 className="font-medium text-gray-800 mb-2">Recommended Actions:</h3>
                  <ol className="list-decimal pl-5 space-y-2 text-gray-700">
                    <li>
                      <span className="font-medium">Regular Scanning:</span> Continue to scan your website regularly to maintain security.
                    </li>
                    <li>
                      <span className="font-medium">Stay Updated:</span> Keep your web server, frameworks, and plugins up to date.
                    </li>
                    <li>
                      <span className="font-medium">Security Monitoring:</span> Implement logging and monitoring to detect potential security incidents.
                    </li>
                  </ol>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanReport;