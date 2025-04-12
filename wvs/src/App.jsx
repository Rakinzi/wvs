import React, { useState, useEffect } from 'react';
import Dashboard from './components/Dashboard';
import ScanReport from './components/ScanReport';
import ScanHistory from './components/ScanHistory';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import Login from './components/Login';
import Settings from './components/Settings';
import BlockedSites from './components/BlockedSites';

const App = () => {
  // Authentication state
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [activeScanId, setActiveScanId] = useState(null);
  const [userData, setUserData] = useState(null);
  
  // Check if user is logged in on initial load
  useEffect(() => {
    const token = localStorage.getItem('token');
    const username = localStorage.getItem('username');
    
    if (token && username) {
      setIsAuthenticated(true);
      setUserData({ username });
    } else {
      setCurrentPage('login');
    }
  }, []);
  
  // Authentication handlers
  const handleLogin = (userData) => {
    setIsAuthenticated(true);
    setUserData(userData);
    setCurrentPage('dashboard');
  };
  
  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setIsAuthenticated(false);
    setUserData(null);
    setCurrentPage('login');
  };
  
  // Navigation handler
  const navigateTo = (page, scanId = null) => {
    setCurrentPage(page);
    if (scanId) {
      setActiveScanId(scanId);
    }
  };
  
  // Page renderer
  const renderPage = () => {
    if (!isAuthenticated) {
      return <Login onLogin={handleLogin} />;
    }
    
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard navigateTo={navigateTo} userData={userData} />;
      case 'report':
        return <ScanReport scanId={activeScanId} navigateTo={navigateTo} />;
      case 'history':
        return <ScanHistory navigateTo={navigateTo} />;
      case 'settings':
        return <Settings userData={userData} />;
      case 'blockedSites':
        return <BlockedSites />;
      default:
        return <Dashboard navigateTo={navigateTo} userData={userData} />;
    }
  };
  
  return (
    <div className="flex flex-col min-h-screen bg-gray-50">
      <Navbar 
        isAuthenticated={isAuthenticated} 
        onLogout={handleLogout} 
        navigateTo={navigateTo}
        currentPage={currentPage}
      />
      <main className="flex-grow">
        {renderPage()}
      </main>
      <Footer />
    </div>
  );
};

export default App;