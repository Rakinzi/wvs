import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, Search, ArrowLeft, RefreshCw, 
  ChevronDown, User, Globe, Calendar, Clock, 
  Filter, Monitor, Info, AlertOctagon
} from 'lucide-react';

const BlockedAccess = ({ navigateTo }) => {
  const [blockedRequests, setBlockedRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  
  const requestsPerPage = 10;

  useEffect(() => {
    document.title = 'Blocked Access Attempts - Web Vulnerability Scanner';
    fetchBlockedRequests();
  }, [currentPage]);

  const fetchBlockedRequests = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const offset = (currentPage - 1) * requestsPerPage;
      const response = await fetch(`http://localhost:5000/blocked-access/list?limit=${requestsPerPage}&offset=${offset}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      // Handle different HTTP response status codes
      if (response.status === 401) {
        // Unauthorized - token expired or invalid
        setError('Your session has expired. Please login again.');
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        // In a real app, you would redirect to login page here
        return;
      }
      
      if (response.status === 403) {
        // Forbidden - user doesn't have permission
        setError('You do not have permission to view this data.');
        return;
      }
      
      const data = await response.json();
      
      if (response.ok && data.status === 'success') {
        setBlockedRequests(data.blocked_requests || []);
        setTotalCount(data.total || 0);
      } else {
        setError(data.message || 'Failed to fetch blocked access attempts');
        setBlockedRequests([]);
        setTotalCount(0);
      }
    } catch (err) {
      setError('Failed to connect to server. Please check your connection and try again.');
      setBlockedRequests([]);
      setTotalCount(0);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
    setCurrentPage(1); // Reset to first page on search
  };

  const toggleFilterDropdown = () => {
    setShowFilterDropdown(!showFilterDropdown);
  };

  const handleFilterChange = (type) => {
    setFilterType(type);
    setShowFilterDropdown(false);
    setCurrentPage(1); // Reset to first page on filter change
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };
  
  // Get user browser from user agent string
  const getBrowserInfo = (userAgent) => {
    if (!userAgent) return 'Unknown';
    
    if (userAgent.includes('Firefox')) return 'Firefox';
    if (userAgent.includes('Chrome') && !userAgent.includes('Chromium')) return 'Chrome';
    if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) return 'Safari';
    if (userAgent.includes('Edge')) return 'Edge';
    if (userAgent.includes('MSIE') || userAgent.includes('Trident/')) return 'Internet Explorer';
    if (userAgent.includes('Opera') || userAgent.includes('OPR')) return 'Opera';
    
    return 'Other';
  };
  
  // Get device type from user agent
  const getDeviceType = (userAgent) => {
    if (!userAgent) return 'Unknown';
    
    if (userAgent.includes('Mobile')) return 'Mobile';
    if (userAgent.includes('Tablet')) return 'Tablet';
    if (userAgent.includes('Windows') || userAgent.includes('Macintosh') || userAgent.includes('Linux')) return 'Desktop';
    
    return 'Other';
  };

  // Filter blocked requests based on search and filter
  const filteredRequests = blockedRequests
    .filter(request => {
      // Apply text search filter
      const matchesSearch = searchQuery === '' || 
        request.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (request.ip_address && request.ip_address.includes(searchQuery)) ||
        (request.reason && request.reason.toLowerCase().includes(searchQuery.toLowerCase()));
      
      // Apply type filter
      const browser = getBrowserInfo(request.user_agent);
      const matchesFilter = filterType === 'all' || 
        (filterType === 'chrome' && browser === 'Chrome') ||
        (filterType === 'firefox' && browser === 'Firefox') ||
        (filterType === 'safari' && browser === 'Safari') ||
        (filterType === 'mobile' && getDeviceType(request.user_agent) === 'Mobile');
      
      return matchesSearch && matchesFilter;
    });

  // Calculate total pages
  const totalPages = Math.ceil(totalCount / requestsPerPage);

  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-6 flex flex-col sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center mb-4 sm:mb-0">
            <button
              onClick={() => navigateTo('dashboard')}
              className="mr-4 flex items-center text-gray-700 hover:text-blue-800"
            >
              <ArrowLeft size={16} className="mr-1" />
              Back
            </button>
            <h1 className="text-2xl font-bold text-gray-900 flex items-center">
              <AlertOctagon size={24} className="mr-2 text-blue-800" />
              Blocked Access Attempts
            </h1>
          </div>
          
          <button
            onClick={fetchBlockedRequests}
            className="flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
          >
            <RefreshCw size={16} className="mr-2" />
            Refresh
          </button>
        </div>
        
        <div className="bg-white shadow-lg rounded-lg overflow-hidden mb-6">
          <div className="px-6 py-5 bg-blue-800 text-white">
            <div className="flex items-center mb-2">
              <AlertTriangle size={20} className="mr-2" />
              <h2 className="text-xl font-bold">Access Attempts to Blocked Sites</h2>
            </div>
            <p className="text-blue-100 text-sm">
              This page shows all attempts to access websites that have been flagged as malicious and blocked by the scanner.
            </p>
          </div>
        </div>
        
        <div className="bg-white shadow-lg rounded-lg overflow-hidden">
          <div className="px-4 py-5 sm:px-6 border-b border-gray-200 bg-gray-50">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
              <div className="relative flex-grow max-w-md">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Search size={16} className="text-gray-400" />
                </div>
                <input
                  type="text"
                  className="pl-10 block w-full border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="Search by URL, IP address or reason..."
                  value={searchQuery}
                  onChange={handleSearchChange}
                />
              </div>
              
              <div className="relative">
                <button
                  onClick={toggleFilterDropdown}
                  className="flex items-center px-3 py-1.5 border border-gray-300 rounded-md text-sm text-gray-700 bg-white hover:bg-gray-50"
                >
                  <Filter size={14} className="mr-1" />
                  Filter: {filterType === 'all' ? 'All Browsers' : 
                           filterType === 'chrome' ? 'Chrome' : 
                           filterType === 'firefox' ? 'Firefox' : 
                           filterType === 'safari' ? 'Safari' : 
                           filterType === 'mobile' ? 'Mobile Devices' : 'Unknown'}
                  <ChevronDown size={14} className="ml-1" />
                </button>
                
                {showFilterDropdown && (
                  <div className="origin-top-right absolute right-0 mt-2 w-56 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 focus:outline-none z-10">
                    <div className="py-1">
                      <button
                        onClick={() => handleFilterChange('all')}
                        className={`flex items-center px-4 py-2 text-sm w-full text-left ${
                          filterType === 'all' ? 'bg-blue-50 text-blue-800 font-medium' : 'text-gray-700 hover:bg-gray-100'
                        }`}
                      >
                        All Browsers
                      </button>
                      <button
                        onClick={() => handleFilterChange('chrome')}
                        className={`flex items-center px-4 py-2 text-sm w-full text-left ${
                          filterType === 'chrome' ? 'bg-blue-50 text-blue-800 font-medium' : 'text-gray-700 hover:bg-gray-100'
                        }`}
                      >
                        Chrome
                      </button>
                      <button
                        onClick={() => handleFilterChange('firefox')}
                        className={`flex items-center px-4 py-2 text-sm w-full text-left ${
                          filterType === 'firefox' ? 'bg-blue-50 text-blue-800 font-medium' : 'text-gray-700 hover:bg-gray-100'
                        }`}
                      >
                        Firefox
                      </button>
                      <button
                        onClick={() => handleFilterChange('safari')}
                        className={`flex items-center px-4 py-2 text-sm w-full text-left ${
                          filterType === 'safari' ? 'bg-blue-50 text-blue-800 font-medium' : 'text-gray-700 hover:bg-gray-100'
                        }`}
                      >
                        Safari
                      </button>
                      <button
                        onClick={() => handleFilterChange('mobile')}
                        className={`flex items-center px-4 py-2 text-sm w-full text-left ${
                          filterType === 'mobile' ? 'bg-blue-50 text-blue-800 font-medium' : 'text-gray-700 hover:bg-gray-100'
                        }`}
                      >
                        Mobile Devices
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
          
          {loading ? (
            <div className="flex justify-center items-center p-12">
              <RefreshCw size={24} className="text-blue-800 animate-spin mr-3" />
              <p className="text-gray-600">Loading blocked access attempts...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center p-12">
              <div className="h-12 w-12 bg-red-100 rounded-full flex items-center justify-center mb-4">
                <AlertTriangle size={20} className="text-red-600" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">Error loading blocked access attempts</h3>
              <p className="text-red-600 mb-4">{error}</p>
              <button
                onClick={fetchBlockedRequests}
                className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-800 hover:bg-blue-700"
              >
                <RefreshCw size={16} className="mr-2" />
                Try Again
              </button>
            </div>
          ) : blockedRequests.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-12">
              <div className="h-16 w-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                <Info size={24} className="text-blue-800" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">No blocked access attempts found</h3>
              <p className="text-gray-500 mb-4">
                No users have attempted to access blocked malicious sites yet.
              </p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Browser</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date & Time</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reason</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {filteredRequests.map((request) => (
                      <tr key={request.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="flex-shrink-0 h-8 w-8 bg-red-100 rounded-md flex items-center justify-center text-red-600">
                              <Globe size={14} />
                            </div>
                            <div className="ml-4">
                              <div className="text-sm font-medium text-gray-900 max-w-xs truncate">{request.url}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <User size={14} className="text-gray-500 mr-2" />
                            <div className="text-sm text-gray-900">{request.ip_address || 'Unknown'}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <Monitor size={14} className="text-gray-500 mr-2" />
                            <div className="text-sm text-gray-900">
                              {getBrowserInfo(request.user_agent)}
                              {getDeviceType(request.user_agent) === 'Mobile' && 
                                <span className="ml-1 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                                  Mobile
                                </span>
                              }
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center text-sm text-gray-900">
                            <Clock size={14} className="mr-1 text-gray-500" />
                            {formatDate(request.timestamp)}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                            {request.reason || 'Malicious site'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              
              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-6 py-3 bg-gray-50 border-t border-gray-200 sm:px-6">
                  <div className="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
                    <div>
                      <p className="text-sm text-gray-700">
                        Showing <span className="font-medium">{((currentPage - 1) * requestsPerPage) + 1}</span> to{' '}
                        <span className="font-medium">
                          {Math.min(currentPage * requestsPerPage, totalCount)}
                        </span>{' '}
                        of <span className="font-medium">{totalCount}</span> results
                      </p>
                    </div>
                    <div>
                      <nav className="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
                        <button
                          onClick={() => paginate(Math.max(1, currentPage - 1))}
                          disabled={currentPage === 1}
                          className={`relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium ${
                            currentPage === 1 
                              ? 'text-gray-300 cursor-not-allowed' 
                              : 'text-gray-500 hover:bg-gray-50'
                          }`}
                        >
                          <span className="sr-only">Previous</span>
                          <ChevronDown className="h-5 w-5 transform -rotate-90" />
                        </button>
                        
                        {/* Show pagination numbers */}
                        {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                          // Calculate which page numbers to show
                          let pageNum;
                          if (totalPages <= 5) {
                            // If we have 5 or fewer pages, just show all pages in order
                            pageNum = i + 1;
                          } else if (currentPage <= 3) {
                            // If we're on pages 1-3, show pages 1-5
                            pageNum = i + 1;
                          } else if (currentPage >= totalPages - 2) {
                            // If we're on the last 3 pages, show the last 5 pages
                            pageNum = totalPages - 4 + i;
                          } else {
                            // Otherwise show current page and 2 pages on either side
                            pageNum = currentPage - 2 + i;
                          }
                          
                          return (
                            <button
                              key={pageNum}
                              onClick={() => paginate(pageNum)}
                              className={`relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium ${
                                currentPage === pageNum
                                  ? 'z-10 bg-blue-50 border-blue-500 text-blue-800'
                                  : 'bg-white text-gray-500 hover:bg-gray-50'
                              }`}
                            >
                              {pageNum}
                            </button>
                          );
                        })}
                        
                        <button
                          onClick={() => paginate(Math.min(totalPages, currentPage + 1))}
                          disabled={currentPage === totalPages}
                          className={`relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium ${
                            currentPage === totalPages 
                              ? 'text-gray-300 cursor-not-allowed' 
                              : 'text-gray-500 hover:bg-gray-50'
                          }`}
                        >
                          <span className="sr-only">Next</span>
                          <ChevronDown className="h-5 w-5 transform rotate-90" />
                        </button>
                      </nav>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
        
        {/* Analytics cards */}
        {!loading && !error && blockedRequests.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
            <div className="bg-white shadow-lg rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
                <Globe className="mr-2 text-blue-800" size={20} />
                Most Blocked Domains
              </h3>
              <div className="space-y-3">
                {Array.from(
                  blockedRequests.reduce((acc, request) => {
                    try {
                      const url = new URL(request.url);
                      const domain = url.hostname;
                      acc.set(domain, (acc.get(domain) || 0) + 1);
                    } catch (e) {
                      // Skip invalid URLs
                    }
                    return acc;
                  }, new Map())
                )
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 5)
                  .map(([domain, count], index) => (
                    <div key={domain} className="flex items-center justify-between">
                      <div className="flex items-center">
                        <div className="w-6 h-6 rounded-full bg-red-100 text-red-800 flex items-center justify-center text-xs font-medium mr-2">
                          {index + 1}
                        </div>
                        <span className="text-sm font-medium text-gray-800">{domain}</span>
                      </div>
                      <span className="text-sm text-gray-500">{count} attempts</span>
                    </div>
                  ))}
              </div>
            </div>
            
            <div className="bg-white shadow-lg rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
                <Monitor className="mr-2 text-blue-800" size={20} />
                Browser Distribution
              </h3>
              <div className="space-y-4">
                {Array.from(
                  blockedRequests.reduce((acc, request) => {
                    const browser = getBrowserInfo(request.user_agent);
                    acc.set(browser, (acc.get(browser) || 0) + 1);
                    return acc;
                  }, new Map())
                )
                  .sort((a, b) => b[1] - a[1])
                  .map(([browser, count]) => {
                    const percentage = Math.round((count / blockedRequests.length) * 100);
                    let color;
                    switch(browser) {
                      case 'Chrome': color = 'bg-green-500'; break;
                      case 'Firefox': color = 'bg-orange-500'; break;
                      case 'Safari': color = 'bg-blue-500'; break;
                      case 'Edge': color = 'bg-blue-600'; break;
                      default: color = 'bg-gray-500';
                    }
                    
                    return (
                      <div key={browser}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium text-gray-800">{browser}</span>
                          <span className="text-sm text-gray-500">{percentage}%</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div 
                            className={`h-2 rounded-full ${color}`} 
                            style={{ width: `${percentage}%` }}
                          ></div>
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
            
            <div className="bg-white shadow-lg rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
                <User className="mr-2 text-blue-800" size={20} />
                Access by Device Type
              </h3>
              <div className="space-y-4">
                {Array.from(
                  blockedRequests.reduce((acc, request) => {
                    const deviceType = getDeviceType(request.user_agent);
                    acc.set(deviceType, (acc.get(deviceType) || 0) + 1);
                    return acc;
                  }, new Map())
                )
                  .sort((a, b) => b[1] - a[1])
                  .map(([deviceType, count]) => {
                    const percentage = Math.round((count / blockedRequests.length) * 100);
                    let color;
                    switch(deviceType) {
                      case 'Desktop': color = 'bg-blue-500'; break;
                      case 'Mobile': color = 'bg-green-500'; break;
                      case 'Tablet': color = 'bg-purple-500'; break;
                      default: color = 'bg-gray-500';
                    }
                    
                    return (
                      <div key={deviceType}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium text-gray-800">{deviceType}</span>
                          <span className="text-sm text-gray-500">{percentage}%</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div 
                            className={`h-2 rounded-full ${color}`} 
                            style={{ width: `${percentage}%` }}
                          ></div>
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default BlockedAccess;