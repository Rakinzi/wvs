import React, { useState } from 'react';

const Dashboard = ({ navigateTo }) => {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async () => {
    if (!url) {
      setError('Please enter a URL to scan');
      return;
    }

    try {
      setIsScanning(true);
      setError(null);
      
      // This would be an actual API call in production
      // const response = await fetch('/api/scan', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ url })
      // });
      
      // Mock API response for demonstration
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Simulate random scan result
      const mockResult = {
        scan_id: Math.floor(Math.random() * 1000),
        url: url,
        findings: {
          sqli: Math.random() > 0.7 ? [{ type: 'SQL Injection', severity: 'High' }] : [],
          ssl: { valid: Math.random() > 0.3 },
          malicious: { is_malicious: Math.random() > 0.8, score: Math.floor(Math.random() * 10) }
        }
      };
      
      setScanResult(mockResult);
      setIsScanning(false);
    } catch (err) {
      setError('Failed to perform scan. Please try again.');
      setIsScanning(false);
    }
  };

  const handleViewReport = () => {
    if (scanResult && scanResult.scan_id) {
      navigateTo('report', scanResult.scan_id);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
      <div className="bg-white shadow-lg rounded-lg overflow-hidden">
        <div className="bg-blue-800 px-6 py-8 text-white">
          <h1 className="text-3xl font-bold">Web Vulnerability Scanner</h1>
          <p className="mt-2 text-blue-100">Scan websites for SQL injection vulnerabilities, invalid SSL certificates, and malicious content</p>
        </div>
        
        <div className="p-6">
          <div className="mb-8">
            <label htmlFor="url" className="block text-sm font-medium text-gray-700 mb-2">
              Enter URL to scan
            </label>
            <div className="flex gap-4">
              <input
                type="text"
                id="url"
                className="flex-1 rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
              <button
                onClick={handleScan}
                disabled={isScanning}
                className={`px-4 py-2 rounded-md text-white font-medium ${
                  isScanning 
                    ? 'bg-blue-400 cursor-not-allowed' 
                    : 'bg-blue-800 hover:bg-blue-700'
                }`}
              >
                {isScanning ? 'Scanning...' : 'Scan Now'}
              </button>
            </div>
            {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
          </div>
          
          {isScanning && (
            <div className="flex justify-center items-center p-8">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
              <p className="ml-4 text-gray-700">Scanning in progress...</p>
            </div>
          )}
          
          {scanResult && !isScanning && (
            <div className="mt-6 border rounded-lg overflow-hidden">
              <div className="bg-gray-50 px-4 py-3 border-b">
                <h3 className="text-lg font-medium">Scan Results</h3>
              </div>
              <div className="p-4">
                <p className="text-gray-700">
                  <span className="font-medium">URL:</span> {scanResult.url}
                </p>
                
                <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-white p-4 rounded-lg border shadow-sm">
                    <div className="flex items-center">
                      <div className={`h-8 w-8 rounded-full flex items-center justify-center ${
                        scanResult.findings.sqli.length > 0 ? 'bg-red-100 text-red-500' : 'bg-green-100 text-green-500'
                      }`}>
                        {scanResult.findings.sqli.length > 0 ? (
                          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        ) : (
                          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </div>
                      <h4 className="ml-2 text-lg font-medium">SQL Injection</h4>
                    </div>
                    <p className="mt-2 text-sm text-gray-600">
                      {scanResult.findings.sqli.length > 0 
                        ? `Found ${scanResult.findings.sqli.length} SQL injection vulnerabilities` 
                        : 'No SQL injection vulnerabilities detected'}
                    </p>
                  </div>
                  
                  <div className="bg-white p-4 rounded-lg border shadow-sm">
                    <div className="flex items-center">
                      <div className={`h-8 w-8 rounded-full flex items-center justify-center ${
                        scanResult.findings.ssl.valid ? 'bg-green-100 text-green-500' : 'bg-red-100 text-red-500'
                      }`}>
                        {scanResult.findings.ssl.valid ? (
                          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                        ) : (
                          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        )}
                      </div>
                      <h4 className="ml-2 text-lg font-medium">SSL Certificate</h4>
                    </div>
                    <p className="mt-2 text-sm text-gray-600">
                      {scanResult.findings.ssl.valid 
                        ? 'Valid SSL certificate detected' 
                        : 'Invalid or missing SSL certificate'}
                    </p>
                  </div>
                  
                  <div className="bg-white p-4 rounded-lg border shadow-sm">
                    <div className="flex items-center">
                      <div className={`h-8 w-8 rounded-full flex items-center justify-center ${
                        scanResult.findings.malicious.is_malicious ? 'bg-red-100 text-red-500' : 'bg-green-100 text-green-500'
                      }`}>
                        {scanResult.findings.malicious.is_malicious ? (
                          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                          </svg>
                        ) : (
                          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </div>
                      <h4 className="ml-2 text-lg font-medium">Malicious Content</h4>
                    </div>
                    <p className="mt-2 text-sm text-gray-600">
                      {scanResult.findings.malicious.is_malicious 
                        ? 'Site potentially malicious' 
                        : 'No malicious content detected'}
                    </p>
                    <p className="text-xs text-gray-500 mt-1">
                      Threat score: {scanResult.findings.malicious.score}/10
                    </p>
                  </div>
                </div>
                
                <div className="mt-6 flex justify-end">
                  <button
                    onClick={handleViewReport}
                    className="px-4 py-2 bg-blue-800 text-white rounded-md hover:bg-blue-700"
                  >
                    View Detailed Report
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
        
        <div className="bg-gray-50 px-6 py-4 border-t">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-white rounded-lg border shadow-sm">
              <div className="flex items-center text-blue-800">
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <h3 className="ml-2 text-lg font-medium">SQL Injection Protection</h3>
              </div>
              <p className="mt-2 text-sm text-gray-600">
                Detect SQL injection vulnerabilities in web forms and URL parameters
              </p>
            </div>
            
            <div className="p-4 bg-white rounded-lg border shadow-sm">
              <div className="flex items-center text-blue-800">
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <h3 className="ml-2 text-lg font-medium">SSL/TLS Verification</h3>
              </div>
              <p className="mt-2 text-sm text-gray-600">
                Check for valid SSL certificates and secure HTTPS implementation
              </p>
            </div>
            
            <div className="p-4 bg-white rounded-lg border shadow-sm">
              <div className="flex items-center text-blue-800">
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <h3 className="ml-2 text-lg font-medium">Malicious Site Detection</h3>
              </div>
              <p className="mt-2 text-sm text-gray-600">
                Identify known malicious domains and phishing attempts
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;