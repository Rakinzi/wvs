import React, { useState, useEffect } from 'react';
import { 
  Clock, Search, FileText, Filter, 
  ChevronDown, ChevronUp, RefreshCw, 
  AlertTriangle, CheckCircle, ExternalLink,
  ArrowLeft, Calendar, Download
} from 'lucide-react';

const ScanHistory = ({ navigateTo }) => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [sortOrder, setSortOrder] = useState('desc');
  const [filterStatus, setFilterStatus] = useState('all');
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const [showExportDropdown, setShowExportDropdown] = useState(false);
  const [selectedScans, setSelectedScans] = useState([]);
  const [selectAll, setSelectAll] = useState(false);
  
  const scansPerPage = 10;

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/scans/history?limit=100', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.status === 'success' && data.scans) {
          setScans(data.scans);
        } else {
          setScans([]);
        }
      } else {
        const data = await response.json();
        setError(data.error || 'Failed to fetch scan history');
      }
    } catch (err) {
      setError('Failed to connect to server');
    } finally {
      setLoading(false);
    }
  };

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value);
    setCurrentPage(1); // Reset to first page on search
  };

  const toggleSortOrder = () => {
    setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc');
  };

  const toggleFilterDropdown = () => {
    setShowFilterDropdown(!showFilterDropdown);
  };

  const toggleExportDropdown = () => {
    setShowExportDropdown(!showExportDropdown);
  };

  const handleFilterChange = (status) => {
    setFilterStatus(status);
    setShowFilterDropdown(false);
    setCurrentPage(1); // Reset to first page on filter change
  };

  const handleCheckboxChange = (scanId) => {
    setSelectedScans(prev => {
      if (prev.includes(scanId)) {
        return prev.filter(id => id !== scanId);
      } else {
        return [...prev, scanId];
      }
    });
  };

  const handleSelectAllChange = () => {
    if (selectAll) {
      setSelectedScans([]);
    } else {
      setSelectedScans(filteredScans.map(scan => scan.id));
    }
    setSelectAll(!selectAll);
  };

  const handleExport = (format) => {
    // In a real app, this would call an API to generate the export
    console.log(`Exporting ${selectedScans.length} scans as ${format}`);
    setShowExportDropdown(false);
  };

  const handleViewReport = (scanId) => {
    navigateTo('report', scanId);
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // Filter and sort scans
  const filteredScans = scans
    .filter(scan => {
      // Apply text search filter
      const matchesSearch = searchQuery === '' || 
        scan.url.toLowerCase().includes(searchQuery.toLowerCase());
      
      // Apply status filter
      const matchesStatus = filterStatus === 'all' || 
        (filterStatus === 'vulnerable' && scan.has_vulnerabilities) || 
        (filterStatus === 'secure' && !scan.has_vulnerabilities);
      
      return matchesSearch && matchesStatus;
    })
    .sort((a, b) => {
      // Apply sorting
      const dateA = new Date(a.timestamp);
      const dateB = new Date(b.timestamp);
      return sortOrder === 'desc' ? dateB - dateA : dateA - dateB;
    });

  // Pagination
  const totalPages = Math.ceil(filteredScans.length / scansPerPage);
  const indexOfLastScan = currentPage * scansPerPage;
  const indexOfFirstScan = indexOfLastScan - scansPerPage;
  const currentScans = filteredScans.slice(indexOfFirstScan, indexOfLastScan);

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
              <Clock size={24} className="mr-2 text-blue-800" />
              Scan History
            </h1>
          </div>
          
          <button
            onClick={fetchScans}
            className="flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
          >
            <RefreshCw size={16} className="mr-2" />
            Refresh
          </button>
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
                  placeholder="Search by URL..."
                  value={searchQuery}
                  onChange={handleSearchChange}
                />
              </div>
              
              <div className="flex space-x-3">
                <div className="relative">
                  <button
                    onClick={toggleFilterDropdown}
                    className="flex items-center px-3 py-1.5 border border-gray-300 rounded-md text-sm text-gray-700 bg-white hover:bg-gray-50"
                  >
                    <Filter size={14} className="mr-1" />
                    Filter
                    {filterStatus !== 'all' && (
                      <span className="ml-1 bg-blue-100 text-blue-800 text-xs px-1.5 py-0.5 rounded-full">
                        1
                      </span>
                    )}
                    <ChevronDown size={14} className="ml-1" />
                  </button>
                  
                  {showFilterDropdown && (
                    <div className="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 focus:outline-none z-10">
                      <div className="py-1">
                        <button
                          onClick={() => handleFilterChange('all')}
                          className={`flex items-center px-4 py-2 text-sm w-full text-left ${
                            filterStatus === 'all' ? 'bg-blue-50 text-blue-800 font-medium' : 'text-gray-700 hover:bg-gray-100'
                          }`}
                        >
                          All Scans
                        </button>
                        <button
                          onClick={() => handleFilterChange('vulnerable')}
                          className={`flex items-center px-4 py-2 text-sm w-full text-left ${
                            filterStatus === 'vulnerable' ? 'bg-blue-50 text-blue-800 font-medium' : 'text-gray-700 hover:bg-gray-100'
                          }`}
                        >
                          <AlertTriangle size={14} className="mr-2 text-red-500" />
                          Vulnerable
                        </button>
                        <button
                          onClick={() => handleFilterChange('secure')}
                          className={`flex items-center px-4 py-2 text-sm w-full text-left ${
                            filterStatus === 'secure' ? 'bg-blue-50 text-blue-800 font-medium' : 'text-gray-700 hover:bg-gray-100'
                          }`}
                        >
                          <CheckCircle size={14} className="mr-2 text-green-500" />
                          Secure
                        </button>
                      </div>
                    </div>
                  )}
                </div>
                
                {selectedScans.length > 0 && (
                  <div className="relative">
                    <button
                      onClick={toggleExportDropdown}
                      className="flex items-center px-3 py-1.5 border border-gray-300 rounded-md text-sm text-gray-700 bg-white hover:bg-gray-50"
                    >
                      <Download size={14} className="mr-1" />
                      Export ({selectedScans.length})
                      <ChevronDown size={14} className="ml-1" />
                    </button>
                    
                    {showExportDropdown && (
                      <div className="origin-top-right absolute right-0 mt-2 w-48 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 focus:outline-none z-10">
                        <div className="py-1">
                          <button
                            onClick={() => handleExport('pdf')}
                            className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 w-full text-left"
                          >
                            Export as PDF
                          </button>
                          <button
                            onClick={() => handleExport('csv')}
                            className="flex items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 w-full text-left"
                          >
                            Export as CSV
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
          
          {loading ? (
            <div className="flex justify-center items-center p-12">
              <RefreshCw size={24} className="text-blue-800 animate-spin mr-3" />
              <p className="text-gray-600">Loading scan history...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center p-12">
              <div className="h-12 w-12 bg-red-100 rounded-full flex items-center justify-center mb-4">
                <AlertTriangle size={20} className="text-red-600" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">Error loading scan history</h3>
              <p className="text-red-600 mb-4">{error}</p>
              <button
                onClick={fetchScans}
                className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-800 hover:bg-blue-700"
              >
                <RefreshCw size={16} className="mr-2" />
                Try Again
              </button>
            </div>
          ) : filteredScans.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-12">
              <div className="h-16 w-16 bg-gray-100 rounded-full flex items-center justify-center mb-4">
                <Search size={24} className="text-gray-400" />
              </div>
              {searchQuery || filterStatus !== 'all' ? (
                <>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No matching scans found</h3>
                  <p className="text-gray-500 mb-4">Try adjusting your search or filters</p>
                  <button
                    onClick={() => {
                      setSearchQuery('');
                      setFilterStatus('all');
                    }}
                    className="text-blue-800 font-medium hover:text-blue-700"
                  >
                    Clear filters
                  </button>
                </>
              ) : (
                <>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No scan history yet</h3>
                  <p className="text-gray-500 mb-4">Start scanning websites to build your history</p>
                  <button
                    onClick={() => navigateTo('dashboard')}
                    className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-800 hover:bg-blue-700"
                  >
                    Scan a Website
                  </button>
                </>
              )}
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-10">
                        <input
                          type="checkbox"
                          className="h-4 w-4 text-blue-800 border-gray-300 rounded focus:ring-blue-500"
                          checked={selectAll}
                          onChange={handleSelectAllChange}
                        />
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                      <th 
                        scope="col" 
                        className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer"
                        onClick={toggleSortOrder}
                      >
                        <div className="flex items-center">
                          <span>Date</span>
                          {sortOrder === 'desc' ? (
                            <ChevronDown size={14} className="ml-1" />
                          ) : (
                            <ChevronUp size={14} className="ml-1" />
                          )}
                        </div>
                      </th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                      <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {currentScans.map((scan) => (
                      <tr key={scan.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <input
                            type="checkbox"
                            className="h-4 w-4 text-blue-800 border-gray-300 rounded focus:ring-blue-500"
                            checked={selectedScans.includes(scan.id)}
                            onChange={() => handleCheckboxChange(scan.id)}
                          />
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="ml-4">
                              <div className="text-sm font-medium text-gray-900 max-w-xs truncate">{scan.url}</div>
                              <div className="text-xs text-gray-500">ID: {scan.id}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center text-sm text-gray-900">
                            <Calendar size={14} className="mr-1 text-gray-500" />
                            {formatDate(scan.timestamp)}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          {scan.has_vulnerabilities ? (
                            <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                              Vulnerable
                            </span>
                          ) : (
                            <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                              Secure
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                          <div className="flex justify-end space-x-3">
                            <a 
                              href={scan.url} 
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="text-gray-500 hover:text-gray-800"
                              title="Visit Website"
                            >
                              <ExternalLink size={16} />
                            </a>
                            <button
                              onClick={() => handleViewReport(scan.id)}
                              className="text-blue-800 hover:text-blue-600"
                              title="View Report"
                            >
                              <FileText size={16} />
                            </button>
                          </div>
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
                        Showing <span className="font-medium">{indexOfFirstScan + 1}</span> to{' '}
                        <span className="font-medium">
                          {Math.min(indexOfLastScan, filteredScans.length)}
                        </span>{' '}
                        of <span className="font-medium">{filteredScans.length}</span> results
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
                          <ChevronUp className="h-5 w-5 transform rotate-90" />
                        </button>
                        
                        {[...Array(totalPages)].map((_, i) => (
                          <button
                            key={i}
                            onClick={() => paginate(i + 1)}
                            className={`relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium ${
                              currentPage === i + 1
                                ? 'z-10 bg-blue-50 border-blue-500 text-blue-800'
                                : 'bg-white text-gray-500 hover:bg-gray-50'
                            }`}
                          >
                            {i + 1}
                          </button>
                        ))}
                        
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
      </div>
    </div>
  );
};

export default ScanHistory;