import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, Menu, X, User, BarChart2, Clock, Settings,
  LogOut, AlertTriangle, Bell, ChevronDown, Globe
} from 'lucide-react';

const NAV_ITEMS = [
  { key: 'dashboard', label: 'Dashboard', icon: BarChart2 },
  { key: 'history',   label: 'Scan History', icon: Clock },
  { key: 'blockedSites',   label: 'Blocked Sites', icon: AlertTriangle },
  { key: 'blockedAccess',  label: 'Access Attempts', icon: Globe },
];

const Navbar = ({ isAuthenticated, onLogout, navigateTo, currentPage }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [userOpen, setUserOpen]   = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const userRef  = useRef(null);
  const notifRef = useRef(null);

  const notifications = [
    { id: 1, type: 'alert', message: 'New vulnerability detected', time: '10 min ago' },
    { id: 2, type: 'info',  message: 'System updated successfully', time: '1 hour ago' },
  ];

  useEffect(() => {
    const close = (e) => {
      if (userRef.current  && !userRef.current.contains(e.target))  setUserOpen(false);
      if (notifRef.current && !notifRef.current.contains(e.target)) setNotifOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, []);

  const go = (page) => {
    navigateTo(page);
    setMobileOpen(false);
    setUserOpen(false);
  };

  return (
    <nav
      style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border-subtle)' }}
      className="sticky top-0 z-50"
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">

          {/* Logo */}
          <button
            onClick={() => isAuthenticated && go('dashboard')}
            className="flex items-center gap-2.5 focus-visible:outline-none"
            aria-label="Go to dashboard"
          >
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: 'var(--color-primary)' }}
            >
              <Shield size={16} className="text-white" />
            </div>
            <span className="text-white font-semibold tracking-tight text-base hidden sm:block">
              LaunchGuard
            </span>
          </button>

          {/* Desktop nav */}
          {isAuthenticated && (
            <div className="hidden md:flex items-center gap-1">
              {NAV_ITEMS.map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  onClick={() => go(key)}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-150 cursor-pointer"
                  style={{
                    color: currentPage === key ? 'var(--color-text)' : 'var(--color-text-muted)',
                    background: currentPage === key ? 'var(--color-elevated)' : 'transparent',
                  }}
                  aria-current={currentPage === key ? 'page' : undefined}
                >
                  <Icon size={15} />
                  {label}
                </button>
              ))}
            </div>
          )}

          {/* Right actions */}
          {isAuthenticated ? (
            <div className="flex items-center gap-2">

              {/* Notifications */}
              <div ref={notifRef} className="relative">
                <button
                  onClick={() => { setNotifOpen(o => !o); setUserOpen(false); }}
                  className="relative w-9 h-9 rounded-lg flex items-center justify-center transition-colors duration-150 cursor-pointer"
                  style={{ color: 'var(--color-text-muted)' }}
                  aria-label="Notifications"
                >
                  <Bell size={18} />
                  {notifications.length > 0 && (
                    <span
                      className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full"
                      style={{ background: 'var(--color-danger)' }}
                    />
                  )}
                </button>

                {notifOpen && (
                  <div
                    className="absolute right-0 mt-2 w-80 rounded-xl shadow-2xl overflow-hidden"
                    style={{ background: 'var(--color-elevated)', border: '1px solid var(--color-border)' }}
                  >
                    <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
                      <p className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Notifications</p>
                    </div>
                    {notifications.map(n => (
                      <div
                        key={n.id}
                        className="flex items-start gap-3 px-4 py-3 transition-colors duration-150"
                        style={{ borderBottom: '1px solid var(--color-border-subtle)' }}
                      >
                        <div
                          className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
                          style={{
                            background: n.type === 'alert' ? 'var(--color-danger-dim)' : 'var(--color-info-dim)',
                            color:      n.type === 'alert' ? 'var(--color-danger)'     : 'var(--color-info)',
                          }}
                        >
                          {n.type === 'alert' ? <AlertTriangle size={13} /> : <Bell size={13} />}
                        </div>
                        <div>
                          <p className="text-sm" style={{ color: 'var(--color-text)' }}>{n.message}</p>
                          <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>{n.time}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* User menu */}
              <div ref={userRef} className="relative">
                <button
                  onClick={() => { setUserOpen(o => !o); setNotifOpen(false); }}
                  className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg transition-colors duration-150 cursor-pointer"
                  style={{ color: 'var(--color-text-muted)' }}
                  aria-label="User menu"
                  aria-expanded={userOpen}
                >
                  <div
                    className="w-7 h-7 rounded-full flex items-center justify-center"
                    style={{ background: 'var(--color-primary-dim)', color: 'var(--color-primary)' }}
                  >
                    <User size={14} />
                  </div>
                  <ChevronDown
                    size={14}
                    className="transition-transform duration-200"
                    style={{ transform: userOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}
                  />
                </button>

                {userOpen && (
                  <div
                    className="absolute right-0 mt-2 w-44 rounded-xl shadow-2xl overflow-hidden"
                    style={{ background: 'var(--color-elevated)', border: '1px solid var(--color-border)' }}
                  >
                    <button
                      onClick={() => go('settings')}
                      className="flex items-center gap-2.5 w-full px-4 py-2.5 text-sm text-left transition-colors duration-150 cursor-pointer"
                      style={{ color: 'var(--color-text-muted)' }}
                    >
                      <Settings size={14} />
                      Settings
                    </button>
                    <div style={{ height: '1px', background: 'var(--color-border-subtle)' }} />
                    <button
                      onClick={() => { setUserOpen(false); onLogout(); }}
                      className="flex items-center gap-2.5 w-full px-4 py-2.5 text-sm text-left transition-colors duration-150 cursor-pointer"
                      style={{ color: 'var(--color-danger)' }}
                    >
                      <LogOut size={14} />
                      Logout
                    </button>
                  </div>
                )}
              </div>

              {/* Mobile hamburger */}
              <button
                onClick={() => setMobileOpen(o => !o)}
                className="md:hidden w-9 h-9 rounded-lg flex items-center justify-center cursor-pointer"
                style={{ color: 'var(--color-text-muted)' }}
                aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
              >
                {mobileOpen ? <X size={20} /> : <Menu size={20} />}
              </button>
            </div>
          ) : (
            <button
              onClick={() => go('login')}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-150 cursor-pointer"
              style={{ background: 'var(--color-primary)', color: '#fff' }}
            >
              <User size={15} />
              Login
            </button>
          )}
        </div>
      </div>

      {/* Mobile drawer */}
      {isAuthenticated && mobileOpen && (
        <div
          className="md:hidden px-4 pb-4 pt-2 flex flex-col gap-1"
          style={{ borderTop: '1px solid var(--color-border-subtle)' }}
        >
          {NAV_ITEMS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => go(key)}
              className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium text-left w-full transition-colors duration-150 cursor-pointer"
              style={{
                color:      currentPage === key ? 'var(--color-text)'      : 'var(--color-text-muted)',
                background: currentPage === key ? 'var(--color-elevated)'  : 'transparent',
              }}
            >
              <Icon size={16} />
              {label}
            </button>
          ))}
          <div style={{ height: '1px', background: 'var(--color-border-subtle)', margin: '4px 0' }} />
          <button
            onClick={() => go('settings')}
            className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium text-left w-full cursor-pointer"
            style={{ color: 'var(--color-text-muted)' }}
          >
            <Settings size={16} />
            Settings
          </button>
          <button
            onClick={() => { onLogout(); setMobileOpen(false); }}
            className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium text-left w-full cursor-pointer"
            style={{ color: 'var(--color-danger)' }}
          >
            <LogOut size={16} />
            Logout
          </button>
        </div>
      )}
    </nav>
  );
};

export default Navbar;
