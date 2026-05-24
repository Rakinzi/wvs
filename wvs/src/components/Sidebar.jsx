import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, BarChart2, Clock, Settings, LogOut,
  AlertTriangle, Globe, User, Bell, X, Menu, ChevronDown, Zap, Sun, Moon,
} from 'lucide-react';
import { useTheme } from '../hooks/useTheme';
import { getSessionUsername } from '../lib/auth';

const NAV_ITEMS = [
  { key: 'dashboard',     label: 'Dashboard',      icon: BarChart2 },
  { key: 'scanners',      label: 'Scanners',        icon: Zap },
  { key: 'history',       label: 'Scan History',   icon: Clock },
  { key: 'blockedSites',  label: 'Blocked Sites',  icon: AlertTriangle },
  { key: 'blockedAccess', label: 'Access Attempts',icon: Globe },
];

const NOTIFICATIONS = [
  { id: 1, type: 'alert', message: 'New vulnerability detected', time: '10 min ago' },
  { id: 2, type: 'info',  message: 'System updated successfully', time: '1 hour ago' },
];

const Sidebar = ({ isAuthenticated, onLogout, navigateTo, currentPage }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [notifOpen, setNotifOpen]   = useState(false);
  const [userOpen, setUserOpen]     = useState(false);
  const notifRef = useRef(null);
  const userRef  = useRef(null);
  const { theme, toggle: toggleTheme } = useTheme();

  useEffect(() => {
    const close = (e) => {
      if (notifRef.current && !notifRef.current.contains(e.target)) setNotifOpen(false);
      if (userRef.current  && !userRef.current.contains(e.target))  setUserOpen(false);
    };
    document.addEventListener('mousedown', close);
    return () => document.removeEventListener('mousedown', close);
  }, []);

  const go = (page) => {
    navigateTo(page);
    setMobileOpen(false);
    setUserOpen(false);
  };

  const SidebarContent = ({ mobile = false }) => (
    <div
      className="flex flex-col h-full"
      style={{
        background: 'var(--color-surface)',
        borderRight: '1px solid var(--color-border-subtle)',
        width: mobile ? '260px' : '220px',
      }}
    >
      {/* Logo */}
      <div
        className="flex items-center gap-3 h-16 px-5 flex-shrink-0"
        style={{ borderBottom: '1px solid var(--color-border-subtle)' }}
      >
        <button
          onClick={() => isAuthenticated && go('dashboard')}
          className="flex items-center gap-2.5 focus-visible:outline-none"
          aria-label="Go to dashboard"
        >
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: 'var(--color-primary)' }}
          >
            <Shield size={16} className="text-white" />
          </div>
          <span className="text-white font-semibold tracking-tight text-sm">
            WebVulnScanner
          </span>
        </button>

        {mobile && (
          <button
            onClick={() => setMobileOpen(false)}
            className="ml-auto w-7 h-7 rounded-md flex items-center justify-center cursor-pointer"
            style={{ color: 'var(--color-text-dim)' }}
            aria-label="Close menu"
          >
            <X size={15} />
          </button>
        )}
      </div>

      {/* Nav items */}
      {isAuthenticated && (
        <nav className="flex flex-col gap-0.5 p-3 flex-1 overflow-y-auto">
          {NAV_ITEMS.map(({ key, label, icon: Icon }) => {
            const active = currentPage === key;
            return (
              <button
                key={key}
                onClick={() => go(key)}
                className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 cursor-pointer w-full text-left"
                style={{
                  color:      active ? 'var(--color-text)'     : 'var(--color-text-muted)',
                  background: active ? 'var(--color-elevated)' : 'transparent',
                }}
                aria-current={active ? 'page' : undefined}
              >
                {React.createElement(Icon, { size: 16, className: 'flex-shrink-0' })}
                <span className="truncate">{label}</span>
              </button>
            );
          })}
        </nav>
      )}

      {/* Bottom: notifications + settings + user */}
      {isAuthenticated && (
        <div
          className="p-3 flex flex-col gap-0.5 flex-shrink-0"
          style={{ borderTop: '1px solid var(--color-border-subtle)' }}
        >
          {/* Notifications */}
          <div ref={notifRef} className="relative">
            <button
              onClick={() => { setNotifOpen(o => !o); setUserOpen(false); }}
              className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm w-full transition-colors duration-150 cursor-pointer"
              style={{ color: 'var(--color-text-muted)' }}
              aria-label="Notifications"
            >
              <Bell size={16} className="flex-shrink-0" />
              <span className="flex-1 text-left truncate">Notifications</span>
              {NOTIFICATIONS.length > 0 && (
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: 'var(--color-danger)' }} />
              )}
            </button>

            {notifOpen && (
              <div
                className="absolute bottom-full mb-2 left-0 w-72 rounded-xl shadow-2xl overflow-hidden z-50"
                style={{ background: 'var(--color-elevated)', border: '1px solid var(--color-border)' }}
              >
                <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Notifications</p>
                </div>
                {NOTIFICATIONS.map(n => (
                  <div key={n.id} className="flex items-start gap-3 px-4 py-3" style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
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

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm transition-colors duration-150 cursor-pointer w-full text-left"
            style={{ color: 'var(--color-text-muted)' }}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark'
              ? <Sun size={16} className="flex-shrink-0" />
              : <Moon size={16} className="flex-shrink-0" />}
            <span className="truncate">{theme === 'dark' ? 'Light Mode' : 'Dark Mode'}</span>
          </button>

          {/* Settings */}
          <button
            onClick={() => go('settings')}
            className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm transition-colors duration-150 cursor-pointer w-full text-left"
            style={{
              color:      currentPage === 'settings' ? 'var(--color-text)'     : 'var(--color-text-muted)',
              background: currentPage === 'settings' ? 'var(--color-elevated)' : 'transparent',
            }}
          >
            <Settings size={16} className="flex-shrink-0" />
            <span className="truncate">Settings</span>
          </button>

          {/* User + logout */}
          <div ref={userRef} className="relative">
            <button
              onClick={() => { setUserOpen(o => !o); setNotifOpen(false); }}
              className="flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm w-full transition-colors duration-150 cursor-pointer"
              style={{ color: 'var(--color-text-muted)' }}
              aria-label="User menu"
              aria-expanded={userOpen}
            >
              <div
                className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0"
                style={{ background: 'var(--color-primary-dim)', color: 'var(--color-primary)' }}
              >
                <User size={13} />
              </div>
              <span className="flex-1 text-left truncate text-sm">
                {getSessionUsername() || 'Account'}
              </span>
              <ChevronDown
                size={13}
                className="flex-shrink-0 transition-transform duration-200"
                style={{ transform: userOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}
              />
            </button>

            {userOpen && (
              <div
                className="absolute bottom-full mb-2 left-0 w-44 rounded-xl shadow-2xl overflow-hidden z-50"
                style={{ background: 'var(--color-elevated)', border: '1px solid var(--color-border)' }}
              >
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
        </div>
      )}
    </div>
  );

  return (
    <>
      {/* Desktop sidebar — always expanded */}
      <aside className="hidden md:flex flex-col h-screen sticky top-0 flex-shrink-0">
        <SidebarContent />
      </aside>

      {/* Mobile hamburger */}
      <button
        onClick={() => setMobileOpen(true)}
        className="md:hidden fixed top-4 left-4 z-40 w-9 h-9 rounded-lg flex items-center justify-center cursor-pointer shadow-lg"
        style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', color: 'var(--color-text-muted)' }}
        aria-label="Open menu"
      >
        <Menu size={18} />
      </button>

      {/* Mobile drawer */}
      {mobileOpen && (
        <>
          <div
            className="fixed inset-0 z-40 md:hidden"
            style={{ background: 'rgba(0,0,0,0.6)' }}
            onClick={() => setMobileOpen(false)}
          />
          <aside className="fixed inset-y-0 left-0 z-50 md:hidden flex flex-col h-full shadow-2xl">
            <SidebarContent mobile />
          </aside>
        </>
      )}
    </>
  );
};

export default Sidebar;
