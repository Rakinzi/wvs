import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, Lock, Database, 
  RefreshCw, ExternalLink, CheckCircle, Search, 
  Info, Award, Clock, Activity, PieChart,
  BarChart as BarChartIcon, Calendar, Globe, Filter,
  ArrowRight, User
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, Legend, ResponsiveContainer,
  PieChart as RechartsPieChart, Pie, Cell,
  LineChart, Line, AreaChart, Area
} from 'recharts';

const Dashboard = ({ navigateTo }) => {
  // URLs for scanning
  const [sqlScanUrl, setSqlScanUrl] = useState('');
  const [sslScanUrl, setSslScanUrl] = useState('');
  
  // Scanning states
  const [isSqlScanning, setIsSqlScanning] = useState(false);
  const [isSslScanning, setIsSslScanning] = useState(false);
  
  // Scan results
  const [sqlScanResult, setSqlScanResult] = useState(null);
  const [sslScanResult, setSslScanResult] = useState(null);
  
  // Errors
  const [sqlError, setSqlError] = useState(null);
  const [sslError, setSslError] = useState(null);
  
  // Stats and dashboard data
  const [dashboardStats, setDashboardStats] = useState(null);
  const [isLoadingStats, setIsLoadingStats] = useState(true);
  const [statsError, setStatsError] = useState(null);
  
  // Fetch dashboard stats from the backend
  const fetchDashboardStats = async () => {
    setIsLoadingStats(true);
    setStatsError(null);
    
    try {
      // Fetch dashboard statistics from API
      const response = await fetch('http://localhost:5000/api/dashboard/stats', {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      
      if (!response.ok) {
        throw new Error(`Error ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success') {
        setDashboardStats(data.stats);
      } else {
        throw new Error(data.message || 'Failed to load dashboard statistics');
      }
    } catch (err) {
      setStatsError(err.message || 'Failed to load dashboard statistics');
      console.error(err);
    } finally {
      setIsLoadingStats(false);
    }
  };

  // Load dashboard stats and recent blocked access on component mount
  useEffect(() => {
    document.title = 'Dashboard - Web Vulnerability Scanner';
    const fetchData = async () => {
      await fetchDashboardStats();
      
      // Fetch recent blocked access attempts
      try {
        const response = await fetch('http://localhost:5000/dashboard/recent-blocked', {
          headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.status === 'success') {
            setDashboardStats(prev => prev ? {
              ...prev,
              recentBlockedAttempts: data.recent_blocked
            } : null);
          }
        }
      } catch (error) {
        console.error('Error fetching recent blocked access:', error);
      }
    };
    
    fetchData();
    
    // Set up auto-refresh interval
    const refreshInterval = setInterval(fetchData, 60000); // Refresh every minute
    
    // Clean up on component unmount
    return () => {
      clearInterval(refreshInterval);
    };
  }, []);
  
  // Format date for display
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };
  
  // Format relative time for recent scans
  const getRelativeTime = (dateString) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMin = Math.floor(diffMs / 60000);
    
    if (diffMin < 1) return 'Just now';
    if (diffMin < 60) return `${diffMin} min ago`;
    
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `${diffHours} hours ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays} days ago`;
  };
  
  // Handle SQL Injection scan
  const handleSqlScan = async () => {
    if (!sqlScanUrl) {
      setSqlError('Please enter a URL to scan');
      return;
    }

    // Add protocol if missing
    let formattedUrl = sqlScanUrl;
    if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
      formattedUrl = 'https://' + formattedUrl;
    }

    try {
      setIsSqlScanning(true);
      setSqlError(null);
      
      // Make API call to the backend SQL scanner
      const response = await fetch('http://localhost:5000/scan/sqli', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ url: formattedUrl })
      });
      
      if (!response.ok) {
        throw new Error(`Error ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success') {
        setSqlScanResult({
          url: data.url,
          scan_id: data.scan_id || Math.floor(Math.random() * 1000),
          timestamp: new Date().toISOString(),
          vulnerable: data.vulnerable,
          findings: data.findings || [],
          recommendations: data.recommendations || []
        });
        
        // Refresh stats after scan
        fetchDashboardStats();
      } else {
        throw new Error(data.message || 'Failed to perform SQL injection scan');
      }
    } catch (err) {
      setSqlError(err.message || 'Failed to perform scan. Please try again.');
      console.error(err);
    } finally {
      setIsSqlScanning(false);
    }
  };
  
  // Handle SSL/TLS scan
  const handleSslScan = async () => {
    if (!sslScanUrl) {
      setSslError('Please enter a URL to scan');
      return;
    }

    // Add protocol if missing
    let formattedUrl = sslScanUrl;
    if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
      formattedUrl = 'https://' + formattedUrl;
    }

    try {
      setIsSslScanning(true);
      setSslError(null);
      
      // Make API call to the backend SSL scanner
      const response = await fetch('http://localhost:5000/scan/ssl', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ url: formattedUrl })
      });
      
      if (!response.ok) {
        throw new Error(`Error ${response.status}: ${response.statusText}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success') {
        setSslScanResult({
          url: data.url,
          scan_id: data.scan_id || Math.floor(Math.random() * 1000),
          timestamp: new Date().toISOString(),
          findings: data.findings || {
            valid: false,
            error: 'No findings returned from scan'
          },
          recommendations: data.recommendations || []
        });
        
        // Refresh stats after scan
        fetchDashboardStats();
      } else {
        throw new Error(data.message || 'Failed to perform SSL/TLS scan');
      }
    } catch (err) {
      setSslError(err.message || 'Failed to perform scan. Please try again.');
      console.error(err);
    } finally {
      setIsSslScanning(false);
    }
  };
  
  // Handle viewing detailed reports
  const handleViewSqlReport = () => {
    if (sqlScanResult && sqlScanResult.scan_id) {
      navigateTo('report', sqlScanResult.scan_id);
    }
  };
  
  const handleViewSslReport = () => {
    if (sslScanResult && sslScanResult.scan_id) {
      navigateTo('report', sslScanResult.scan_id);
    }
  };

  // Custom colors for charts
  const COLORS = ['#1e40af', '#3b82f6', '#93c5fd', '#60a5fa', '#2563eb'];
  const VULNERABILITY_COLORS = {
    'SQL Injection': '#ef4444',
    'SSL Issues': '#f59e0b',
    'Malicious Content': '#8b5cf6'
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Dashboard header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Web Vulnerability Scanner Dashboard</h1>
          <p className="mt-2 text-gray-600">Monitor security scans, detect vulnerabilities, and protect your web applications</p>
        </div>
        
        {/* Stats overview cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          {isLoadingStats ? (
            <div className="col-span-3 bg-white shadow-lg rounded-lg p-6 flex items-center justify-center">
              <RefreshCw size={24} className="text-blue-800 animate-spin mr-3" />
              <p className="text-gray-600">Loading dashboard statistics...</p>
            </div>
          ) : statsError ? (
            <div className="col-span-3 bg-white shadow-lg rounded-lg p-6">
              <div className="flex flex-col items-center">
                <div className="h-12 w-12 bg-red-100 rounded-full flex items-center justify-center mb-4">
                  <AlertTriangle size={20} className="text-red-600" />
                </div>
                <h3 className="text-lg font-medium text-gray-900 mb-2">Error loading statistics</h3>
                <p className="text-red-600 mb-4">{statsError}</p>
                <button
                  onClick={fetchDashboardStats}
                  className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-800 hover:bg-blue-700"
                >
                  <RefreshCw size={16} className="mr-2" />
                  Try Again
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="bg-white shadow-lg rounded-lg p-6">
                <div className="flex items-center">
                  <div className="h-12 w-12 bg-blue-100 rounded-lg flex items-center justify-center">
                    <Search size={20} className="text-blue-800" />
                  </div>
                  <div className="ml-4">
                    <h2 className="text-sm font-medium text-gray-600">Total Scans</h2>
                    <p className="text-3xl font-bold text-gray-900">{dashboardStats.totalScans}</p>
                  </div>
                </div>
                <div className="mt-4">
                  <div className="flex items-center text-sm">
                    <Award size={14} className="text-blue-800 mr-1" />
                    <span className="text-gray-600">Today: {dashboardStats.today.scans} scans performed</span>
                  </div>
                </div>
              </div>
              
              <div className="bg-white shadow-lg rounded-lg p-6">
                <div className="flex items-center">
                  <div className="h-12 w-12 bg-red-100 rounded-lg flex items-center justify-center">
                    <AlertTriangle size={20} className="text-red-600" />
                  </div>
                  <div className="ml-4">
                    <h2 className="text-sm font-medium text-gray-600">Vulnerable Sites</h2>
                    <p className="text-3xl font-bold text-gray-900">{dashboardStats.vulnerableScans}</p>
                  </div>
                </div>
                <div className="mt-4">
                  <div className="flex items-center text-sm">
                    <Activity size={14} className="text-red-600 mr-1" />
                    <span className="text-gray-600">Today: {dashboardStats.today.vulnerabilities} issues detected</span>
                  </div>
                </div>
              </div>
              
              <div className="bg-white shadow-lg rounded-lg p-6">
                <div className="flex items-center">
                  <div className="h-12 w-12 bg-purple-100 rounded-lg flex items-center justify-center">
                    <Shield size={20} className="text-purple-800" />
                  </div>
                  <div className="ml-4">
                    <h2 className="text-sm font-medium text-gray-600">Blocked Sites</h2>
                    <p className="text-3xl font-bold text-gray-900">{dashboardStats.blockedSites}</p>
                  </div>
                </div>
                <div className="mt-4">
                  <div className="flex items-center text-sm">
                    <Filter size={14} className="text-purple-800 mr-1" />
                    <span className="text-gray-600">Today: {dashboardStats.today.blockedAttempts} access attempts blocked</span>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
        
        {/* Main content grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* SQL Injection Scanner */}
          <div className="bg-white shadow-lg rounded-lg overflow-hidden">
            <div className="bg-blue-800 px-6 py-4 text-white">
              <div className="flex items-center">
                <div className="h-10 w-10 bg-white rounded-full flex items-center justify-center shadow-lg mr-3">
                  <Database size={18} className="text-blue-800" />
                </div>
                <h2 className="text-xl font-bold">SQL Injection Scanner</h2>
              </div>
            </div>
            
            <div className="p-6">
              <div className="mb-6">
                <label htmlFor="sqlUrl" className="block text-sm font-medium text-gray-700 mb-2">
                  Enter URL to scan for SQL injection vulnerabilities
                </label>
                <div className="flex gap-4">
                  <input
                    type="text"
                    id="sqlUrl"
                    className="flex-1 rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                    placeholder="https://example.com"
                    value={sqlScanUrl}
                    onChange={(e) => setSqlScanUrl(e.target.value)}
                  />
                  <button
                    onClick={handleSqlScan}
                    disabled={isSqlScanning}
                    className={`px-4 py-2 rounded-md text-white font-medium ${
                      isSqlScanning 
                        ? 'bg-blue-400 cursor-not-allowed' 
                        : 'bg-blue-800 hover:bg-blue-700'
                    }`}
                  >
                    {isSqlScanning ? (
                      <div className="flex items-center">
                        <RefreshCw size={16} className="animate-spin mr-2" />
                        <span>Scanning</span>
                      </div>
                    ) : 'Scan Now'}
                  </button>
                </div>
                {sqlError && <p className="mt-2 text-sm text-red-600">{sqlError}</p>}
              </div>
              
              {isSqlScanning && (
                <div className="flex justify-center items-center p-6">
                  <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
                  <p className="ml-4 text-gray-700">Scanning for SQL injection vulnerabilities...</p>
                </div>
              )}
              
              {sqlScanResult && !isSqlScanning && (
                <div className="border rounded-lg overflow-hidden">
                  <div className="bg-gray-50 px-4 py-3 border-b">
                    <div className="flex justify-between items-center">
                      <h3 className="text-lg font-medium text-gray-900">Scan Results</h3>
                      <div className="text-xs text-gray-500">
                        Scan ID: {sqlScanResult.scan_id} | {formatDate(sqlScanResult.timestamp)}
                      </div>
                    </div>
                  </div>
                  
                  <div className="p-4">
                    <div className="flex justify-between items-start mb-4">
                      <p className="text-gray-700">
                        <span className="font-medium">URL:</span> {sqlScanResult.url}
                      </p>
                      
                      <div className="flex items-center">
                        {sqlScanResult.vulnerable ? (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                            <AlertTriangle size={12} className="mr-1" />
                            Vulnerable
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            <CheckCircle size={12} className="mr-1" />
                            Secure
                          </span>
                        )}
                      </div>
                    </div>
                    
                    {sqlScanResult.vulnerable ? (
                      <div>
                        <p className="text-red-700 mb-3">
                          Found {sqlScanResult.findings.length} SQL injection {sqlScanResult.findings.length === 1 ? 'vulnerability' : 'vulnerabilities'}
                        </p>
                        
                        <div className="space-y-3 mb-4">
                          {sqlScanResult.findings.map((finding, idx) => (
                            <div key={idx} className="bg-red-50 border border-red-200 rounded p-3">
                              <div className="flex items-start">
                                <AlertTriangle size={16} className="text-red-600 mt-0.5 mr-2 flex-shrink-0" />
                                <div>
                                  <p className="font-medium text-red-800">{finding.type}</p>
                                  <p className="text-xs text-red-700 mt-1">
                                    Parameter: <code className="bg-red-100 px-1 py-0.5 rounded">{finding.parameter}</code> | 
                                    Severity: <span className="font-medium">{finding.severity}</span>
                                  </p>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                        
                        <div className="bg-blue-50 border border-blue-200 rounded p-3">
                          <h4 className="text-sm font-medium text-blue-800 mb-2">Recommendations</h4>
                          <ul className="list-disc pl-5 space-y-1 text-xs text-blue-700">
                            {sqlScanResult.recommendations.map((rec, idx) => (
                              <li key={idx}>{rec}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-6">
                        <div className="inline-flex h-12 w-12 rounded-full bg-green-100 items-center justify-center mb-3">
                          <CheckCircle size={24} className="text-green-600" />
                        </div>
                        <h4 className="text-lg font-medium text-gray-900 mb-1">No SQL Injection Vulnerabilities</h4>
                        <p className="text-gray-600 mb-4">This website appears to be protected against SQL injection attacks.</p>
                      </div>
                    )}
                    
                    <div className="flex justify-end mt-4">
                      <button
                        onClick={handleViewSqlReport}
                        className="px-4 py-2 bg-blue-800 text-white rounded-md hover:bg-blue-700"
                      >
                        View Detailed Report
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
          
          {/* SSL/TLS Scanner */}
          <div className="bg-white shadow-lg rounded-lg overflow-hidden">
            <div className="bg-blue-800 px-6 py-4 text-white">
              <div className="flex items-center">
                <div className="h-10 w-10 bg-white rounded-full flex items-center justify-center shadow-lg mr-3">
                  <Lock size={18} className="text-blue-800" />
                </div>
                <h2 className="text-xl font-bold">SSL/TLS Certificate Scanner</h2>
              </div>
            </div>
            
            <div className="p-6">
              <div className="mb-6">
                <label htmlFor="sslUrl" className="block text-sm font-medium text-gray-700 mb-2">
                  Enter URL to check SSL/TLS certificate
                </label>
                <div className="flex gap-4">
                  <input
                    type="text"
                    id="sslUrl"
                    className="flex-1 rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                    placeholder="https://example.com"
                    value={sslScanUrl}
                    onChange={(e) => setSslScanUrl(e.target.value)}
                  />
                  <button
                    onClick={handleSslScan}
                    disabled={isSslScanning}
                    className={`px-4 py-2 rounded-md text-white font-medium ${
                      isSslScanning 
                        ? 'bg-blue-400 cursor-not-allowed' 
                        : 'bg-blue-800 hover:bg-blue-700'
                    }`}
                  >
                    {isSslScanning ? (
                      <div className="flex items-center">
                        <RefreshCw size={16} className="animate-spin mr-2" />
                        <span>Scanning</span>
                      </div>
                    ) : 'Scan Now'}
                  </button>
                </div>
                {sslError && <p className="mt-2 text-sm text-red-600">{sslError}</p>}
              </div>
              
              {isSslScanning && (
                <div className="flex justify-center items-center p-6">
                  <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
                  <p className="ml-4 text-gray-700">Verifying SSL/TLS certificate...</p>
                </div>
              )}
              
              {sslScanResult && !isSslScanning && (
                <div className="border rounded-lg overflow-hidden">
                  <div className="bg-gray-50 px-4 py-3 border-b">
                    <div className="flex justify-between items-center">
                      <h3 className="text-lg font-medium text-gray-900">Certificate Results</h3>
                      <div className="text-xs text-gray-500">
                        Scan ID: {sslScanResult.scan_id} | {formatDate(sslScanResult.timestamp)}
                      </div>
                    </div>
                  </div>
                  
                  <div className="p-4">
                    <div className="flex justify-between items-start mb-4">
                      <p className="text-gray-700">
                        <span className="font-medium">URL:</span> {sslScanResult.url}
                      </p>
                      
                      <div className="flex items-center">
                        {sslScanResult.findings.valid ? (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            <CheckCircle size={12} className="mr-1" />
                            Valid Certificate
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                            <AlertTriangle size={12} className="mr-1" />
                            Invalid Certificate
                          </span>
                        )}
                      </div>
                    </div>
                    
                    {sslScanResult.findings.valid ? (
                      <div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                          {sslScanResult.findings.issuer && (
                            <div className="bg-gray-50 rounded p-3">
                              <h4 className="text-sm font-medium text-gray-700 mb-2">Certificate Expiration</h4>
                              <p className="text-sm text-gray-600">{formatDate(sslScanResult.findings.expires)}</p>
                              <p className="text-xs text-gray-500">
                                {new Date(sslScanResult.findings.expires) > new Date() ? 'Valid' : 'Expired'}
                              </p>
                            </div>
                          )}
                        </div>
                        
                        <div className="bg-green-50 border border-green-200 rounded p-3 mb-4">
                          <div className="flex items-start">
                            <CheckCircle size={16} className="text-green-600 mt-0.5 mr-2 flex-shrink-0" />
                            <div>
                              <p className="font-medium text-green-800">Secure Connection</p>
                              <p className="text-xs text-green-700 mt-1">
                                Protocol: <span className="font-medium">{sslScanResult.findings.protocol}</span> | 
                                Self-Signed: <span className="font-medium">{sslScanResult.findings.self_signed ? 'Yes' : 'No'}</span>
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div>
                        <div className="bg-orange-50 border border-orange-200 rounded p-3 mb-4">
                          <div className="flex items-start">
                            <AlertTriangle size={16} className="text-orange-600 mt-0.5 mr-2 flex-shrink-0" />
                            <div>
                              <p className="font-medium text-orange-800">Certificate Issue Detected</p>
                              <p className="text-xs text-orange-700 mt-1">
                                Error: {sslScanResult.findings.error}
                                {sslScanResult.findings.self_signed && <span> | Self-signed certificate detected</span>}
                              </p>
                            </div>
                          </div>
                        </div>
                        
                        <div className="bg-blue-50 border border-blue-200 rounded p-3">
                          <h4 className="text-sm font-medium text-blue-800 mb-2">Recommendations</h4>
                          <ul className="list-disc pl-5 space-y-1 text-xs text-blue-700">
                            {sslScanResult.recommendations.map((rec, idx) => (
                              <li key={idx}>{rec}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}
                    
                    <div className="flex justify-end mt-4">
                      <button
                        onClick={handleViewSslReport}
                        className="px-4 py-2 bg-blue-800 text-white rounded-md hover:bg-blue-700"
                      >
                        View Detailed Report
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
        
        {/* Dashboard charts and stats */}
        {isLoadingStats ? null : statsError ? null : (
          <div className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Vulnerability distribution chart */}
            <div className="bg-white shadow-lg rounded-lg overflow-hidden lg:col-span-1">
              <div className="px-6 py-4 border-b border-gray-200">
                <div className="flex items-center">
                  <PieChart size={18} className="text-blue-800 mr-2" />
                  <h3 className="text-lg font-medium text-gray-900">Vulnerability Types</h3>
                </div>
              </div>
              
              <div className="p-6">
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <RechartsPieChart>
                      <Pie
                        data={dashboardStats.vulnerabilityTypes}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                        label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                      >
                        {dashboardStats.vulnerabilityTypes.map((entry, index) => (
                          <Cell 
                            key={`cell-${index}`} 
                            fill={VULNERABILITY_COLORS[entry.name] || COLORS[index % COLORS.length]} 
                          />
                        ))}
                      </Pie>
                      <Tooltip 
                        formatter={(value, name) => [value, name]} 
                        contentStyle={{ borderRadius: '0.375rem' }}
                      />
                    </RechartsPieChart>
                  </ResponsiveContainer>
                </div>
                
                <div className="mt-4">
                  <div className="grid grid-cols-1 gap-2">
                    {dashboardStats.vulnerabilityTypes.map((type, index) => (
                      <div key={index} className="flex items-center">
                        <div 
                          className="w-3 h-3 rounded-full mr-2" 
                          style={{ backgroundColor: VULNERABILITY_COLORS[type.name] || COLORS[index % COLORS.length] }}
                        ></div>
                        <span className="text-xs text-gray-600">{type.name}: <span className="font-medium">{type.value}</span></span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
            
            {/* Weekly scan activity chart */}
            <div className="bg-white shadow-lg rounded-lg overflow-hidden lg:col-span-2">
              <div className="px-6 py-4 border-b border-gray-200">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <BarChartIcon size={18} className="text-blue-800 mr-2" />
                    <h3 className="text-lg font-medium text-gray-900">Scan Activity (Last 7 Days)</h3>
                  </div>
                </div>
              </div>
              
              <div className="p-6">
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={dashboardStats.scansByDay}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} />
                      <XAxis 
                        dataKey="date" 
                        tickFormatter={(value) => new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                      />
                      <YAxis />
                      <Tooltip 
                        formatter={(value, name) => [value, name === 'scans' ? 'Total Scans' : 'Vulnerabilities']} 
                        labelFormatter={(value) => new Date(value).toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' })}
                        contentStyle={{ borderRadius: '0.375rem' }}
                      />
                      <Legend />
                      <Bar dataKey="scans" name="Total Scans" fill="#1e40af" />
                      <Bar dataKey="vulnerabilities" name="Vulnerabilities" fill="#ef4444" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
            
            {/* Blocked attempts chart */}
            <div className="bg-white shadow-lg rounded-lg overflow-hidden lg:col-span-2">
              <div className="px-6 py-4 border-b border-gray-200">
                <div className="flex items-center">
                  <Shield size={18} className="text-blue-800 mr-2" />
                  <h3 className="text-lg font-medium text-gray-900">Blocked Access Attempts</h3>
                </div>
              </div>
              
              <div className="p-6">
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={dashboardStats.blockedAttemptsByDay}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} />
                      <XAxis 
                        dataKey="date" 
                        tickFormatter={(value) => new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                      />
                      <YAxis />
                      <Tooltip 
                        formatter={(value) => [value, 'Blocked Attempts']} 
                        labelFormatter={(value) => new Date(value).toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' })}
                        contentStyle={{ borderRadius: '0.375rem' }}
                      />
                      <Area type="monotone" dataKey="count" name="Blocked Attempts" stroke="#8b5cf6" fill="#c4b5fd" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
            
            {/* Recent scans list */}
            <div className="bg-white shadow-lg rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-200">
                <div className="flex items-center">
                  <Clock size={18} className="text-blue-800 mr-2" />
                  <h3 className="text-lg font-medium text-gray-900">Recent Scans</h3>
                </div>
              </div>
              
              <div className="p-4">
                <ul className="divide-y divide-gray-200">
                  {dashboardStats.recentScans.map((scan) => (
                    <li key={scan.id} className="py-3">
                      <div className="flex items-start">
                        <div className={`flex-shrink-0 h-8 w-8 rounded-full flex items-center justify-center ${
                          scan.hasVulnerabilities ? 'bg-red-100 text-red-600' : 'bg-green-100 text-green-600'
                        }`}>
                          {scan.hasVulnerabilities ? <AlertTriangle size={14} /> : <CheckCircle size={14} />}
                        </div>
                        <div className="ml-3 flex-1">
                          <div className="flex items-center justify-between">
                            <p className="text-sm font-medium text-gray-900">{scan.url}</p>
                            <p className="text-xs text-gray-500">{getRelativeTime(scan.timestamp)}</p>
                          </div>
                          <div className="mt-1 flex items-center">
                            {scan.hasVulnerabilities ? (
                              <span className="inline-flex items-center text-xs text-red-700">
                                <AlertTriangle size={10} className="mr-1" />
                                Vulnerabilities detected
                              </span>
                            ) : (
                              <span className="inline-flex items-center text-xs text-green-700">
                                <CheckCircle size={10} className="mr-1" />
                                Secure
                              </span>
                            )}
                            <button
                              onClick={() => navigateTo('report', scan.id)}
                              className="ml-4 text-xs text-blue-800 hover:text-blue-600"
                            >
                              View Report
                            </button>
                          </div>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
                
                <div className="mt-4 text-center">
                  <button
                    onClick={() => navigateTo('history')}
                    className="text-sm text-blue-800 hover:text-blue-600 font-medium"
                  >
                    View All Scans
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
        
        {/* Recent Blocked Access Attempts Section */}
        {!isLoadingStats && !statsError && dashboardStats && dashboardStats.recentBlockedAttempts && dashboardStats.recentBlockedAttempts.length > 0 && (
          <div className="mt-8 bg-white shadow-lg rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200">
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <Globe size={18} className="text-blue-800 mr-2" />
                  <h3 className="text-lg font-medium text-gray-900">Recent Blocked Access Attempts</h3>
                </div>
                <button
                  onClick={() => navigateTo('blockedAccess')}
                  className="text-sm text-blue-800 hover:text-blue-600"
                >
                  View all
                </button>
              </div>
            </div>
            
            <div className="divide-y divide-gray-200">
              {dashboardStats.recentBlockedAttempts.map((attempt) => (
                <div key={attempt.id} className="p-4 hover:bg-gray-50">
                  <div className="flex items-start">
                    <div className="flex-shrink-0 h-8 w-8 bg-red-100 rounded-md flex items-center justify-center text-red-600">
                      <AlertTriangle size={14} />
                    </div>
                    <div className="ml-3 flex-1">
                      <div className="flex justify-between">
                        <p className="text-sm font-medium text-gray-900 truncate max-w-sm">{attempt.url}</p>
                        <p className="text-xs text-gray-500">{formatDate(attempt.timestamp)}</p>
                      </div>
                      <div className="mt-1 flex items-center justify-between">
                        <div className="flex items-center">
                          <User size={12} className="text-gray-500 mr-1" />
                          <span className="text-xs text-gray-600">{attempt.ip_address}</span>
                        </div>
                        <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-red-100 text-red-800">
                          {attempt.reason || 'Malicious site'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            
            <div className="px-6 py-4 border-t border-gray-200 bg-gray-50">
              <button
                onClick={() => navigateTo('blockedAccess')}
                className="text-sm text-blue-800 hover:text-blue-600 flex items-center justify-center w-full"
              >
                View all blocked access attempts
                <ArrowRight size={14} className="ml-1" />
              </button>
            </div>
          </div>
        )}
        
        {/* Feature cards */}
        <div className="mt-8 bg-white shadow-lg rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Security Features</h3>
          </div>
          
          <div className="p-6 grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="p-4 bg-gray-50 rounded-lg border">
              <div className="flex items-center text-blue-800 mb-3">
                <Database size={20} className="mr-2" />
                <h4 className="text-lg font-medium">SQL Injection Protection</h4>
              </div>
              <p className="text-sm text-gray-600">
                Detect and prevent SQL injection vulnerabilities in web forms and URL parameters
              </p>
            </div>
            
            <div className="p-4 bg-gray-50 rounded-lg border">
              <div className="flex items-center text-blue-800 mb-3">
                <Lock size={20} className="mr-2" />
                <h4 className="text-lg font-medium">SSL/TLS Verification</h4>
              </div>
              <p className="text-sm text-gray-600">
                Check for valid SSL certificates and secure HTTPS implementation
              </p>
            </div>
            
            <div className="p-4 bg-gray-50 rounded-lg border">
              <div className="flex items-center text-blue-800 mb-3">
                <Shield size={20} className="mr-2" />
                <h4 className="text-lg font-medium">Malicious Site Detection</h4>
              </div>
              <p className="text-sm text-gray-600">
                Identify and block known malicious domains and phishing attempts
              </p>
            </div>
            
            <div className="p-4 bg-gray-50 rounded-lg border">
              <div className="flex items-center text-blue-800 mb-3">
                <Globe size={20} className="mr-2" />
                <h4 className="text-lg font-medium">Access Monitoring</h4>
              </div>
              <p className="text-sm text-gray-600">
                Track and monitor all attempts to access malicious websites through the proxy
              </p>
              <div className="mt-4">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-gray-500">Blocked today</span>
                  <span className="text-xs font-medium text-gray-700">
                    {dashboardStats?.today?.blockedAttempts || 0}
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-1.5">
                  <div 
                    className="h-1.5 rounded-full bg-red-500" 
                    style={{ width: `${Math.min(100, ((dashboardStats?.today?.blockedAttempts || 0) / 10) * 100)}%` }}
                  ></div>
                </div>
              </div>
              <div className="mt-3">
                <button
                  onClick={() => navigateTo('blockedAccess')}
                  className="text-sm text-blue-800 hover:text-blue-600 font-medium flex items-center"
                >
                  View access attempts
                  <ArrowRight size={14} className="ml-1" />
                </button>
              </div>
            </div>
          </div>
          
          <div className="px-6 py-4 border-t border-gray-200 bg-gray-50">
            <div className="flex items-center">
              <Info size={16} className="text-blue-800 mr-2" />
              <p className="text-sm text-gray-600">
                Regular scanning helps protect your web applications from security vulnerabilities.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;