import React, { Suspense } from 'react';
import { ThemeContext, useThemeProvider } from './hooks/useTheme';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, useLocation, useParams } from 'react-router-dom';
import { clearSession, getSessionIsAdmin, getSessionRole, getSessionUsername, isAuthenticated, updateSession } from './lib/auth';
import { apiJson } from './lib/api';
import Sidebar from './components/Sidebar';
const Dashboard = React.lazy(() => import('./components/Dashboard'));
const Scanners = React.lazy(() => import('./components/Scanners'));
const ScanReport = React.lazy(() => import('./components/ScanReport'));
const ScanHistory = React.lazy(() => import('./components/ScanHistory'));
const Login = React.lazy(() => import('./components/Login'));
const Register = React.lazy(() => import('./components/Register'));
const ResetPassword = React.lazy(() => import('./components/ResetPassword'));
const VerifyEmail = React.lazy(() => import('./components/VerifyEmail'));
const Settings = React.lazy(() => import('./components/Settings'));
const BlockedSites = React.lazy(() => import('./components/BlockedSites'));
const BlockedAccess = React.lazy(() => import('./components/BlockedAccess'));
const VerifiedTargets = React.lazy(() => import('./components/VerifiedTargets'));
const UptimeMonitors = React.lazy(() => import('./components/UptimeMonitors'));
const LandingPage = React.lazy(() => import('./components/LandingPage'));
const NewsPage = React.lazy(() => import('./components/NewsPage'));
const NewsAdmin = React.lazy(() => import('./components/NewsAdmin'));
const AdminUsers = React.lazy(() => import('./components/AdminUsers'));
const TermsOfService = React.lazy(() => import('./components/TermsOfService'));
const PrivacyPolicy = React.lazy(() => import('./components/PrivacyPolicy'));

const RouteFallback = () => (
    <div
      className="min-h-screen flex items-center justify-center"
      style={{ background: 'var(--color-bg)' }}
    >
      <div style={{ position: 'relative', width: 120, height: 120 }}>
        {/* Track */}
        <svg width="120" height="120" viewBox="0 0 120 120" fill="none" style={{ position: 'absolute', inset: 0 }}>
          <circle cx="60" cy="60" r="56" stroke="var(--color-border)" strokeWidth="2.5" />
        </svg>
        {/* Spinning arc */}
        <svg width="120" height="120" viewBox="0 0 120 120" fill="none"
          style={{ position: 'absolute', inset: 0, animation: 'spin 900ms linear infinite' }}>
          <circle cx="60" cy="60" r="56" stroke="var(--color-primary)" strokeWidth="2.5"
            strokeLinecap="round" strokeDasharray="70 282" />
        </svg>
        {/* Logo centered inside ring */}
        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <img src="/launchguard-icon.svg" alt="LaunchGuard" style={{ width: 72, height: 72 }} />
        </div>
      </div>
    </div>
);

// A wrapper component for authenticated routes
const ProtectedRoute = ({ children }) => {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />;
  }
  
  return children;
};

const GuestRoute = ({ children }) => {
  if (isAuthenticated()) {
    return <Navigate to="/" replace />;
  }

  return children;
};

const AdminRoute = ({ children }) => {
  const [isAdmin, setIsAdmin] = React.useState(getSessionIsAdmin());

  React.useEffect(() => {
    if (isAdmin !== null) {
      return;
    }
    apiJson('/profile', { auth: true })
      .then(({ data }) => {
        const next = Boolean(data?.is_admin);
        updateSession({ isAdmin: next, role: data?.role || 'free' });
        setIsAdmin(next);
      })
      .catch(() => setIsAdmin(false));
  }, [isAdmin]);

  if (isAdmin === null) {
    return null;
  }

  if (!isAdmin) {
    return <Navigate to="/" replace />;
  }

  return children;
};

const AUTH_ROUTES = ['/login', '/register', '/reset-password', '/verify-email'];
const PUBLIC_ROUTES = ['/', '/news', '/landing', '/terms', '/privacy'];

// Layout component that includes the Sidebar and Footer
const Layout = ({ children }) => {
  const location = useLocation();
  const authenticated = isAuthenticated();
  const navigate = useNavigate();
  const isAuthRoute = AUTH_ROUTES.includes(location.pathname);
  const isPublicNewsRoute = location.pathname === '/news';
  const isPublicRoute =
    (!authenticated && location.pathname === '/') ||
    ['/landing', '/terms', '/privacy'].includes(location.pathname) ||
    isPublicNewsRoute;
  const [isAdmin, setIsAdmin] = React.useState(getSessionIsAdmin());

  React.useEffect(() => {
    if (!authenticated) {
      setIsAdmin(null);
      return;
    }
    apiJson('/profile', { auth: true })
      .then(({ data }) => {
        const next = Boolean(data?.is_admin);
        updateSession({ isAdmin: next, role: data?.role || 'free' });
        setIsAdmin(next);
      })
      .catch(() => {});
  }, [authenticated]);

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
    if (path.startsWith('/admin/users')) return 'admin/users';
    if (path.startsWith('/news/admin')) return 'news/admin';
    if (path.startsWith('/news')) return 'news';
    return path.replace('/', '');
  };

  if (isAuthRoute || isPublicRoute) {
    return <Suspense fallback={<RouteFallback />}>{children}</Suspense>;
  }

  return (
    <div className="flex min-h-screen" style={{ background: 'var(--color-bg)' }}>
      <Sidebar
        isAuthenticated={authenticated}
        isAdmin={Boolean(isAdmin)}
        onLogout={handleLogout}
        currentPage={getCurrentPage()}
        navigateTo={(page) => navigate(page === 'dashboard' ? '/' : `/${page}`)}
      />
      <main className="flex-1 min-w-0">
        <Suspense fallback={<RouteFallback />}>{children}</Suspense>
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

const VerifiedTargetsWrapper = () => {
  const navigate = useNavigate();

  const navigateTo = (page) => {
    navigate(page === 'dashboard' ? '/' : `/${page}`);
  };

  return <VerifiedTargets navigateTo={navigateTo} />;
};

const UptimeMonitorsWrapper = () => {
  const navigate = useNavigate();

  const navigateTo = (page) => {
    navigate(page === 'dashboard' ? '/' : `/${page}`);
  };

  return <UptimeMonitors navigateTo={navigateTo} />;
};

const LandingPageWrapper = () => {
  const navigate = useNavigate();
  if (isAuthenticated()) {
    return <Navigate to="/" replace />;
  }

  const navigateTo = (page) => {
    if (page === 'login') navigate('/login');
    else if (page === 'news') navigate('/news');
    else if (page === 'terms') navigate('/terms');
    else if (page === 'privacy') navigate('/privacy');
    else if (page === 'dashboard') navigate('/');
    else navigate('/');
  };
  return <LandingPage navigateTo={navigateTo} />;
};

const NewsPageWrapper = () => {
  const navigate = useNavigate();
  const navigateTo = (page) => {
    if (page === 'dashboard') navigate('/');
    else if (page === 'login') navigate('/login');
    else if (page === 'landing') navigate('/landing');
    else navigate(`/${page}`);
  };
  return <NewsPage navigateTo={navigateTo} isAuthenticated={isAuthenticated()} />;
};

const NewsAdminWrapper = () => {
  const navigate = useNavigate();
  const navigateTo = (page) => {
    if (page === 'news') navigate('/news');
    else navigate(page === 'dashboard' ? '/' : `/${page}`);
  };
  return <NewsAdmin navigateTo={navigateTo} />;
};

const TermsWrapper = () => {
  const navigate = useNavigate();
  return <TermsOfService navigateTo={(page) => navigate(page === 'landing' ? '/landing' : `/${page}`)} />;
};

const PrivacyWrapper = () => {
  const navigate = useNavigate();
  return <PrivacyPolicy navigateTo={(page) => navigate(page === 'landing' ? '/landing' : `/${page}`)} />;
};

const HomeRoute = () => {
  if (!isAuthenticated()) {
    return <LandingPageWrapper />;
  }

  return (
    <ProtectedRoute>
      <DashboardWrapper />
    </ProtectedRoute>
  );
};

const App = () => {
  const themeValue = useThemeProvider();
  return (
    <ThemeContext.Provider value={themeValue}>
    <Router>
      <Routes>
        <Route path="/login" element={
          <Layout>
            <GuestRoute>
              <Login />
            </GuestRoute>
          </Layout>
        } />
        
        <Route path="/register" element={
          <Layout>
            <GuestRoute>
              <Register />
            </GuestRoute>
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
        
        <Route path="/landing" element={
          <Layout>
            <GuestRoute>
              <LandingPageWrapper />
            </GuestRoute>
          </Layout>
        } />

        <Route path="/news" element={
          <Layout>
            <NewsPageWrapper />
          </Layout>
        } />

        <Route path="/news/admin" element={
          <Layout>
            <ProtectedRoute>
              <AdminRoute>
                <NewsAdminWrapper />
              </AdminRoute>
            </ProtectedRoute>
          </Layout>
        } />

        <Route path="/admin/users" element={
          <Layout>
            <ProtectedRoute>
              <AdminRoute>
                <AdminUsers />
              </AdminRoute>
            </ProtectedRoute>
          </Layout>
        } />

        <Route path="/" element={
          <Layout>
            <HomeRoute />
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
              <AdminRoute>
                <BlockedSitesWrapper />
              </AdminRoute>
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/blockedAccess" element={
          <Layout>
            <ProtectedRoute>
              <AdminRoute>
                <BlockedAccessWrapper />
              </AdminRoute>
            </ProtectedRoute>
          </Layout>
        } />

        <Route path="/targets" element={
          <Layout>
            <ProtectedRoute>
              <VerifiedTargetsWrapper />
            </ProtectedRoute>
          </Layout>
        } />

        <Route path="/uptime" element={
          <Layout>
            <ProtectedRoute>
              <UptimeMonitorsWrapper />
            </ProtectedRoute>
          </Layout>
        } />
        
        <Route path="/terms" element={
          <Layout>
            <TermsWrapper />
          </Layout>
        } />

        <Route path="/privacy" element={
          <Layout>
            <PrivacyWrapper />
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
