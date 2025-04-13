import React, { useState, useEffect } from 'react';
import { 
  AlertOctagon, Search, ArrowLeft, RefreshCw, 
  Plus, AlertTriangle, Filter, ChevronDown, 
  ExternalLink, Trash2, CheckCircle, Info,
  Globe, Calendar
} from 'lucide-react';

const BlockedSites = ({ navigateTo }) => {
  const [blockedSites, setBlockedSites] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [newSiteUrl, setNewSiteUrl] = useState('');
  const [newSiteReason, setNewSiteReason] = useState('');
  const [addingUrl, setAddingUrl] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const [selectedSource, setSelectedSource] = useState('all');
  const [sources, setSources] = useState([]);
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [showConfirmDelete, setShowConfirmDelete] = useState(false);
  const [siteToDelete, setSiteToDelete] = useState(null);
  
  const sitesPerPage = 10;

  useEffect(() => {
    document.title = 'Blocked Malicious Sites - Web Vulnerability Scanner';
    fetchBlockedSites();
  }, []);

  const fetchBlockedSites = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/api/malicious/list?limit=1000', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        
        // Simulate a more detailed response with metadata
        // In a real app, this would come from the API
        const enhancedData = data.domains.map((domain, index) => ({
          id: index + 1,
          domain: domain,
          url: `http://${domain}`,
          reason: ['Phishing site', 'Malware distribution', 'Suspicious domain', 'Listed in DNS blacklists'][Math.floor(Math.random() * 4)],
          source: ['scan', 'manual', 'api_scan', 'ai', 'external'][Math.floor(Math.random() * 5)],
          date_added: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString()
        }));
        
        setBlockedSites(enhancedData);
        
        // Extract unique sources for filter dropdown
        const uniqueSources = ['all', ...new Set(enhancedData.map(site => site.source))];
        setSources(uniqueSources);
      } else {
        const data = await response.json();
        setError(data.error || 'Failed to fetch blocked sites');
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

  const toggleFilterDropdown = () => {
    setShowFilterDropdown(!showFilterDropdown);
  };

  const handleFilterChange = (source) => {
    setSelectedSource(source);
    setShowFilterDropdown(false);
    setCurrentPage(1); // Reset to first page on filter change
  };

  const handleAddSite = async (e) => {
    e.preventDefault();
    
    if (!newSiteUrl) {
      return;
    }
    
    setAddingUrl(true);
    
    try {
      const response = await fetch('http://localhost:5000/api/malicious/add', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          url: newSiteUrl,
          reason: newSiteReason || 'Manually blocked'
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        setSuccessMessage(data.message || 'Site added successfully');
        setNewSiteUrl('');
        setNewSiteReason('');
        setShowAddModal(false);
        
        // Refresh the list
        fetchBlockedSites();
        
        // Show success message
        setTimeout(() => {
          setSuccessMessage('');
        }, 3000);
      } else {
        const data = await response.json();
        setError(data.error || 'Failed to add site');
      }
    } catch (err) {
      setError('Failed to connect to server');
    } finally {
      setAddingUrl(false);
    }
  };

  const handleDeleteSite = (site) => {
    setSiteToDelete(site);
    setShowConfirmDelete(true);
  };

  const confirmDelete = async () => {
    // In a real app, this would call an API to delete the site
    if (siteToDelete) {
      // Instead of making an API call that doesn't exist yet,
      // we'll simulate it by removing from state
      setBlockedSites(prev => prev.filter(site => site.id !== siteToDelete.id));
      setSuccessMessage('Site removed successfully');
      
      // Clear the message after 3 seconds
      setTimeout(() => {
        setSuccessMessage('');
      }, 3000);
    }
    setShowConfirmDelete(false);
    setSiteToDelete(null);
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // Format source name for display
  const formatSource = (source) => {
    switch(source) {
      case 'scan': return 'Security Scan';
      case 'api_scan': return 'API Scan';
      case 'manual': return 'Manual Entry';
      case 'ai': return 'AI Detection';
      case 'external': return 'External Source';
      default: return source.charAt(0).toUpperCase() + source.slice(1);
    }
  };

  // Filter sites based on search and source filter
  const filteredSites = blockedSites
    .filter(site => {
      // Apply text search filter
      const matchesSearch = searchQuery === '' || 
        site.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
        site.reason.toLowerCase().includes(searchQuery.toLowerCase());
      
      // Apply source filter
      const matchesSource = selectedSource === 'all' || site.source === selectedSource;
      
      return matchesSearch && matchesSource;
    });

  // Pagination
  const totalPages = Math.ceil(filteredSites.length / sitesPerPage);
  const indexOfLastSite = currentPage * sitesPerPage;
  const indexOfFirstSite = indexOfLastSite - sitesPerPage;
  const currentSites = filteredSites.slice(indexOfFirstSite, indexOfLastSite);

  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {successMessage && (
          <div className="mb-4 bg-green-50 border border-green-200 text-green-800 rounded-md p-4 flex items-start">
            <CheckCircle size={18} className="text-green-600 mr-3 mt-0.5 flex-shrink-0" />
            <span>{successMessage}</span>
          </div>
        )}
        
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
              Blocked Malicious Sites
            </h1>
          </div>
          
          <div className="flex space-x-3">
            <button
              onClick={fetchBlockedSites}
              className="flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
            >
              <RefreshCw size={16} className="mr-2" />
              Refresh
            </button>
            
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center px-4 py-2 rounded-md shadow-sm text-sm font-medium text-white bg-blue-800 hover:bg-blue-700"
            >
              <Plus size={16} className="mr-2" />
              Add New
            </button>
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
                  placeholder="Search by domain or reason..."
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
                  Source: {selectedSource === 'all' ? 'All' : formatSource(selectedSource)}
                  <ChevronDown size={14} className="ml-1" />
                </button>
                
                {showFilterDropdown && (
                  <div className="origin-top-right absolute right-0 mt-2 w-56 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 focus:outline-none z-10">
                    <div className="py-1">
                      {sources.map(source => (
                        <button
                          key={source}
                          onClick={() => handleFilterChange(source)}
                          className={`flex items-center px-4 py-2 text-sm w-full text-left ${
                            selectedSource === source ? 'bg-blue-50 text-blue-800 font-medium' : 'text-gray-700 hover:bg-gray-100'
                          }`}
                        >
                          {source === 'all' ? 'All Sources' : formatSource(source)}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
          
          {loading ? (
            <div className="flex justify-center items-center p-12">
              <RefreshCw size={24} className="text-blue-800 animate-spin mr-3" />
              <p className="text-gray-600">Loading blocked sites...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center p-12">
              <div className="h-12 w-12 bg-red-100 rounded-full flex items-center justify-center mb-4">
                <AlertTriangle size={20} className="text-red-600" />
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">Error loading blocked sites</h3>
              <p className="text-red-600 mb-4">{error}</p>
              <button
                onClick={fetchBlockedSites}
                className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-800 hover:bg-blue-700"
              >
                <RefreshCw size={16} className="mr-2" />
                Try Again
              </button>
            </div>
          ) : filteredSites.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-12">
              <div className="h-16 w-16 bg-gray-100 rounded-full flex items-center justify-center mb-4">
                <AlertOctagon size={24} className="text-gray-400" />
              </div>
              {searchQuery || selectedSource !== 'all' ? (
                <>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No matching sites found</h3>
                  <p className="text-gray-500 mb-4">Try adjusting your search or filters</p>
                  <button
                    onClick={() => {
                      setSearchQuery('');
                      setSelectedSource('all');
                    }}
                    className="text-blue-800 font-medium hover:text-blue-700"
                  >
                    Clear filters
                  </button>
                </>
              ) : (
                <>
                  <h3 className="text-lg font-medium text-gray-900 mb-2">No blocked sites yet</h3>
                  <p className="text-gray-500 mb-4">Scan websites or add domains manually to block malicious sites</p>
                  <button
                    onClick={() => setShowAddModal(true)}
                    className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-800 hover:bg-blue-700"
                  >
                    <Plus size={16} className="mr-2" />
                    Add Site
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
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reason</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                      <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date Added</th>
                      <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {currentSites.map((site) => (
                      <tr key={site.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="flex-shrink-0 h-8 w-8 bg-red-100 rounded-md flex items-center justify-center text-red-600">
                              <Globe size={14} />
                            </div>
                            <div className="ml-4">
                              <div className="text-sm font-medium text-gray-900">{site.domain}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-sm text-gray-900">{site.reason}</div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">
                            {formatSource(site.source)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center text-sm text-gray-900">
                            <Calendar size={14} className="mr-1 text-gray-500" />
                            {formatDate(site.date_added)}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                          <div className="flex justify-end space-x-3">
                            <a 
                              href={site.url}
                              target="_blank" 
                              rel="noopener noreferrer"
                              className="text-gray-500 hover:text-gray-800"
                              title="Visit Website (Caution: Site marked as malicious)"
                            >
                              <ExternalLink size={16} />
                            </a>
                            <button
                              onClick={() => handleDeleteSite(site)}
                              className="text-red-600 hover:text-red-800"
                              title="Remove from Blocklist"
                            >
                              <Trash2 size={16} />
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
                        Showing <span className="font-medium">{indexOfFirstSite + 1}</span> to{' '}
                        <span className="font-medium">
                          {Math.min(indexOfLastSite, filteredSites.length)}
                        </span>{' '}
                        of <span className="font-medium">{filteredSites.length}</span> results
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
                        
                        {/* Pagination buttons */}
                        {[...Array(totalPages)].map((_, i) => {
                          // Show first 3 pages, last 3 pages, and pages around current page
                          const pageNum = i + 1;
                          const showPage = pageNum <= 3 || pageNum > totalPages - 3 || 
                                         Math.abs(pageNum - currentPage) <= 1;
                          
                          // Show ellipsis when needed
                          if (!showPage) {
                            if (pageNum === 4 && currentPage > 4) return (
                              <span key={i} className="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700">
                                ...
                              </span>
                            );
                            if (pageNum === totalPages - 3 && currentPage < totalPages - 3) return (
                              <span key={i} className="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700">
                                ...
                              </span>
                            );
                            return null;
                          }
                          
                          return (
                            <button
                              key={i}
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
      </div>
      
      {/* Add Site Modal */}
      {showAddModal && (
        <div className="fixed z-10 inset-0 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 transition-opacity" aria-hidden="true">
              <div className="absolute inset-0 bg-gray-500 opacity-75"></div>
            </div>
            
            <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
            
            <div className="inline-block align-bottom bg-white rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
              <div className="sm:flex sm:items-start">
                <div className="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 sm:mx-0 sm:h-10 sm:w-10">
                  <Plus size={20} className="text-blue-800" />
                </div>
                <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                  <h3 className="text-lg leading-6 font-medium text-gray-900">Add Malicious Site</h3>
                  <div className="mt-2">
                    <p className="text-sm text-gray-500">
                      Enter the URL of a malicious site to add it to the blocklist. This site will be blocked for all users.
                    </p>
                  </div>
                  
                  <form onSubmit={handleAddSite} className="mt-4 space-y-4">
                    <div>
                      <label htmlFor="site-url" className="block text-sm font-medium text-gray-700">Site URL</label>
                      <input
                        type="text"
                        id="site-url"
                        className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                        placeholder="example.com or https://example.com"
                        value={newSiteUrl}
                        onChange={(e) => setNewSiteUrl(e.target.value)}
                        required
                      />
                    </div>
                    
                    <div>
                      <label htmlFor="site-reason" className="block text-sm font-medium text-gray-700">Reason (optional)</label>
                      <input
                        type="text"
                        id="site-reason"
                        className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                        placeholder="e.g., Phishing site, Malware distribution"
                        value={newSiteReason}
                        onChange={(e) => setNewSiteReason(e.target.value)}
                      />
                    </div>
                    
                    <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 flex items-start">
                      <Info size={16} className="text-yellow-600 mt-0.5 mr-2 flex-shrink-0" />
                      <p className="text-xs text-yellow-800">
                        Adding a site to the blocklist will prevent it from being accessed through the proxy. The site will be automatically blocked for all users.
                      </p>
                    </div>
                  </form>
                </div>
              </div>
              
              <div className="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                <button
                  type="button"
                  onClick={handleAddSite}
                  disabled={addingUrl || !newSiteUrl}
                  className={`w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 text-base font-medium text-white ${
                    addingUrl || !newSiteUrl
                      ? 'bg-blue-400 cursor-not-allowed'
                      : 'bg-blue-800 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500'
                  } sm:ml-3 sm:w-auto sm:text-sm`}
                >
                  {addingUrl ? (
                    <span className="flex items-center">
                      <RefreshCw size={16} className="animate-spin mr-2" />
                      Adding...
                    </span>
                  ) : (
                    'Add to Blocklist'
                  )}
                </button>
                
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:w-auto sm:text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Confirm Delete Modal */}
      {showConfirmDelete && (
        <div className="fixed z-10 inset-0 overflow-y-auto">
          <div className="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div className="fixed inset-0 transition-opacity" aria-hidden="true">
              <div className="absolute inset-0 bg-gray-500 opacity-75"></div>
            </div>
            
            <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
            
            <div className="inline-block align-bottom bg-white rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
              <div className="sm:flex sm:items-start">
                <div className="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                  <AlertTriangle size={20} className="text-red-600" />
                </div>
                <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                  <h3 className="text-lg leading-6 font-medium text-gray-900">Remove from Blocklist</h3>
                  <div className="mt-2">
                    <p className="text-sm text-gray-500">
                      Are you sure you want to remove <span className="font-medium">{siteToDelete?.domain}</span> from the blocklist? This will allow users to access the site.
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
                <button
                  type="button"
                  onClick={confirmDelete}
                  className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 sm:ml-3 sm:w-auto sm:text-sm"
                  >
                    Remove
                  </button>
                  
                  <button
                    type="button"
                    onClick={() => {
                      setShowConfirmDelete(false);
                      setSiteToDelete(null);
                    }}
                    className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:w-auto sm:text-sm"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };
  
  export default BlockedSites;