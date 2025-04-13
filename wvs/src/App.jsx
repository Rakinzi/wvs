import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
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

const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={
          <Layout>
            <Login navigateTo={(page) => window.location.href = page === 'dashboard' ? '/' : `/${page}`} />
          </Layout>
        } />
        
        <Route path="/register" element={
          <Layout>
            <Register navigateTo={(page) => window.location.href = page === 'dashboard' ? '/' : `/${page}`} />
          </Layout>
        } />
        
        <Route path="/" element={
          <Layout>
            <ProtectedRoute>
              <Dashboard navigateTo={(page, scanId) => {
                if (page === 'report' && scanId) {
                  window.location.href = `/report/${scanId}`;
                } else {
                  window.location.href = page === 'dashboard' ? '/' : `/${page}`;
                }
              }} />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/report/:scanId" element={
          <Layout>
            <ProtectedRoute>
              <ScanReport navigateTo={(page) => window.location.href = page === 'dashboard' ? '/' : `/${page}`} />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/history" element={
          <Layout>
            <ProtectedRoute>
              <ScanHistory navigateTo={(page, scanId) => {
                if (page === 'report' && scanId) {
                  window.location.href = `/report/${scanId}`;
                } else {
                  window.location.href = page === 'dashboard' ? '/' : `/${page}`;
                }
              }} />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/settings" element={
          <Layout>
            <ProtectedRoute>
              <Settings navigateTo={(page) => window.location.href = page === 'dashboard' ? '/' : `/${page}`} />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/blockedSites" element={
          <Layout>
            <ProtectedRoute>
              <BlockedSites navigateTo={(page) => window.location.href = page === 'dashboard' ? '/' : `/${page}`} />
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