import React from 'react';
import { ThemeContext, useThemeProvider } from './hooks/useTheme';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, useLocation, useParams } from 'react-router-dom';
import { clearSession, getSessionUsername, isAuthenticated } from './lib/auth';
import { apiJson } from './lib/api';
import Dashboard from './components/Dashboard';
import Scanners from './components/Scanners';
import ScanReport from './components/ScanReport';
import ScanHistory from './components/ScanHistory';
import Sidebar from './components/Sidebar';
import Login from './components/Login';
import Register from './components/Register';
import ResetPassword from './components/ResetPassword';
import VerifyEmail from './components/VerifyEmail';
import Settings from './components/Settings';
import BlockedSites from './components/BlockedSites';
import BlockedAccess from './components/BlockedAccess';

// A wrapper component for authenticated routes
const ProtectedRoute = ({ children }) => {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

const AUTH_ROUTES = ['/login', '/register', '/reset-password', '/verify-email'];

// Layout component that includes the Sidebar and Footer
const Layout = ({ children }) => {
  const location = useLocation();
  const authenticated = isAuthenticated();
  const navigate = useNavigate();
  const isAuthRoute = AUTH_ROUTES.includes(location.pathname);

  const handleLogout = async () => {
    try {
      await apiJson('/logout', { method: 'POST', auth: true });
    } catch {
      // Clear client session even if the server cookie is already missing or expired.
    } finally {
      clearSession();
      navigate('/login');
    }
  };

  const getCurrentPage = () => {
    const path = location.pathname;
    if (path === '/') return 'dashboard';
    if (path.startsWith('/report')) return 'report';
    return path.replace('/', '');
  };

  if (isAuthRoute) {
    return <>{children}</>;
  }

  return (
    <div className="flex min-h-screen" style={{ background: 'var(--color-bg)' }}>
      <Sidebar
        isAuthenticated={authenticated}
        onLogout={handleLogout}
        currentPage={getCurrentPage()}
        navigateTo={(page) => navigate(page === 'dashboard' ? '/' : `/${page}`)}
      />
      <main className="flex-1 min-w-0">
        {children}
      </main>
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

const ScannersWrapper = () => {
  const navigate = useNavigate();

  const navigateTo = (page, scanId) => {
    if (page === 'report' && scanId) {
      navigate(`/report/${scanId}`);
    } else {
      navigate(page === 'dashboard' ? '/' : `/${page}`);
    }
  };

  return <Scanners navigateTo={navigateTo} />;
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
  const [userData, setUserData] = React.useState({ username: getSessionUsername() });

  React.useEffect(() => {
    apiJson('/profile', { auth: true })
      .then(({ data }) => setUserData(data))
      .catch(() => {});
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

const BlockedAccessWrapper = () => {
  const navigate = useNavigate();
  
  const navigateTo = (page) => {
    navigate(page === 'dashboard' ? '/' : `/${page}`);
  };
  
  return <BlockedAccess navigateTo={navigateTo} />;
};

const App = () => {
  const themeValue = useThemeProvider();
  return (
    <ThemeContext.Provider value={themeValue}>
    <Router>
      <Routes>
        <Route path="/login" element={
          <Layout>
            <Login />
          </Layout>
        } />
        
        <Route path="/register" element={
          <Layout>
            <Register />
          </Layout>
        } />

        <Route path="/reset-password" element={
          <Layout>
            <ResetPassword />
          </Layout>
        } />

        <Route path="/verify-email" element={
          <Layout>
            <VerifyEmail />
          </Layout>
        } />
        
        <Route path="/" element={
          <Layout>
            <ProtectedRoute>
              <DashboardWrapper />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/scanners" element={
          <Layout>
            <ProtectedRoute>
              <ScannersWrapper />
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
        
        <Route path="/blockedAccess" element={
          <Layout>
            <ProtectedRoute>
              <BlockedAccessWrapper />
            </ProtectedRoute>
          </Layout>
        } />
        
        {/* Catch-all route to redirect to dashboard */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
    </ThemeContext.Provider>
  );
};

export default App;
