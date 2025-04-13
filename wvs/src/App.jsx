import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, useLocation, useParams } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import ScanReport from './components/ScanReport';
import ScanHistory from './components/ScanHistory';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import Login from './components/Login';
import Register from './components/Register';
import Settings from './components/Settings';
import BlockedSites from './components/BlockedSites';

// A wrapper component for authenticated routes
const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem('token');
  const username = localStorage.getItem('username');
  
  if (!token || !username) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

// Layout component that includes the Navbar and Footer
const Layout = ({ children }) => {
  const location = useLocation();
  const isAuthenticated = localStorage.getItem('token') && localStorage.getItem('username');
  const navigate = useNavigate();
  
  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    navigate('/login');
  };
  
  // Determine current page for the Navbar
  const getCurrentPage = () => {
    const path = location.pathname;
    if (path === '/') return 'dashboard';
    if (path.startsWith('/report')) return 'report';
    return path.replace('/', '');
  };
  
  return (
    <div className="flex flex-col min-h-screen bg-gray-50">
      <Navbar 
        isAuthenticated={isAuthenticated} 
        onLogout={handleLogout} 
        currentPage={getCurrentPage()}
        navigateTo={(page) => navigate(page === 'dashboard' ? '/' : `/${page}`)}
      />
      <main className="flex-grow">
        {children}
      </main>
      <Footer />
    </div>
  );
};

// Wrapper components with hooks for each route
const DashboardWrapper = () => {
  const navigate = useNavigate();
  
  const navigateTo = (page, scanId) => {
    if (page === 'report' && scanId) {
      navigate(`/report/${scanId}`);
    } else {
      navigate(page === 'dashboard' ? '/' : `/${page}`);
    }
  };
  
  return <Dashboard navigateTo={navigateTo} />;
};

const ScanReportWrapper = () => {
  const navigate = useNavigate();
  const params = useParams();
  
  const navigateTo = (page) => {
    navigate(page === 'dashboard' ? '/' : `/${page}`);
  };
  
  return <ScanReport scanId={params.scanId} navigateTo={navigateTo} />;
};

const ScanHistoryWrapper = () => {
  const navigate = useNavigate();
  
  const navigateTo = (page, scanId) => {
    if (page === 'report' && scanId) {
      navigate(`/report/${scanId}`);
    } else {
      navigate(page === 'dashboard' ? '/' : `/${page}`);
    }
  };
  
  return <ScanHistory navigateTo={navigateTo} />;
};

const SettingsWrapper = () => {
  const navigate = useNavigate();
  const [userData, setUserData] = useState(null);
  
  useEffect(() => {
    const username = localStorage.getItem('username');
    if (username) {
      setUserData({ username });
    }
  }, []);
  
  const navigateTo = (page) => {
    navigate(page === 'dashboard' ? '/' : `/${page}`);
  };
  
  return <Settings userData={userData} navigateTo={navigateTo} />;
};

const BlockedSitesWrapper = () => {
  const navigate = useNavigate();
  
  const navigateTo = (page) => {
    navigate(page === 'dashboard' ? '/' : `/${page}`);
  };
  
  return <BlockedSites navigateTo={navigateTo} />;
};

const App = () => {
  const [user, setUser] = useState(null);
  
  useEffect(() => {
    // Check if user is already logged in
    const username = localStorage.getItem('username');
    if (username) {
      setUser({ username });
    }
  }, []);
  
  const handleLogin = (userData) => {
    setUser(userData);
  };
  
  return (
    <Router>
      <Routes>
        <Route path="/login" element={
          <Layout>
            <Login onLogin={handleLogin} />
          </Layout>
        } />
        
        <Route path="/register" element={
          <Layout>
            <Register />
          </Layout>
        } />
        
        <Route path="/" element={
          <Layout>
            <ProtectedRoute>
              <DashboardWrapper />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/report/:scanId" element={
          <Layout>
            <ProtectedRoute>
              <ScanReportWrapper />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/history" element={
          <Layout>
            <ProtectedRoute>
              <ScanHistoryWrapper />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/settings" element={
          <Layout>
            <ProtectedRoute>
              <SettingsWrapper />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/blockedSites" element={
          <Layout>
            <ProtectedRoute>
              <BlockedSitesWrapper />
            </ProtectedRoute>
          </Layout>
        } />
        
        {/* Catch-all route to redirect to dashboard */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
};

export default App;