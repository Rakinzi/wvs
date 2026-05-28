import React, { useState, useEffect, useRef } from 'react';
import {
  BarChart2, Clock, Settings, LogOut,
  AlertTriangle, Globe, User, Bell, X, Menu, ChevronDown,
  Zap, Sun, Moon, BadgeCheck, Activity, ChevronRight, Newspaper, BookOpen,
} from 'lucide-react';
import { useTheme } from '../hooks/useTheme';
import { getSessionUsername } from '../lib/auth';

const NAV_ITEMS = [
  { key: 'dashboard',     label: 'Dashboard',       icon: BarChart2 },
  { key: 'scanners',      label: 'Scanners',         icon: Zap },
  { key: 'uptime',        label: 'Uptime',           icon: Activity },
  { key: 'targets',       label: 'Verified Targets', icon: BadgeCheck },
  { key: 'history',       label: 'Scan History',     icon: Clock },
  { key: 'blockedSites',  label: 'Blocked Sites',    icon: AlertTriangle },
  { key: 'blockedAccess', label: 'Access Attempts',  icon: Globe, adminOnly: true },
  { key: 'news',          label: 'Security News',    icon: Newspaper },
  { key: 'news/admin',    label: 'News CMS',         icon: BookOpen, adminOnly: true },
];

const NOTIFICATIONS = [
  { id: 1, type: 'alert', message: 'New vulnerability detected', time: '10 min ago' },
  { id: 2, type: 'info',  message: 'System updated successfully', time: '1 hour ago' },
];

const Sidebar = ({ isAuthenticated, onLogout, navigateTo, currentPage, isAdmin = false }) => {
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
        borderRight: '1px solid var(--color-border)',
        width: mobile ? '256px' : '216px',
      }}
    >
      {/* ── Logo ── */}
      <div
        className="flex items-center gap-3 h-[60px] px-4 flex-shrink-0"
        style={{ borderBottom: '1px solid var(--color-border)' }}
      >
        <button
          onClick={() => isAuthenticated && go('dashboard')}
          className="flex items-center gap-2.5 focus-visible:outline-none group"
          aria-label="Go to dashboard"
        >
          <img
            src="/launchguard-icon.svg"
            alt=""
            className="w-8 h-8 rounded-lg flex-shrink-0 glow-pulse transition-all duration-200"
            style={{ boxShadow: '0 0 18px rgba(45,212,191,0.35)' }}
          />
          <span
            className="font-bold tracking-tight text-sm gradient-text"
            style={{ letterSpacing: '-0.02em' }}
          >
            LaunchGuard
          </span>
        </button>

        {mobile && (
          <button
            onClick={() => setMobileOpen(false)}
            className="ml-auto w-7 h-7 rounded-md flex items-center justify-center cursor-pointer transition-colors duration-150"
            style={{ color: 'var(--color-text-dim)' }}
            aria-label="Close menu"
          >
            <X size={14} />
          </button>
        )}
      </div>

      {/* ── Nav items ── */}
      {isAuthenticated && (
        <nav className="flex flex-col gap-0.5 p-2 flex-1 overflow-y-auto">
          {NAV_ITEMS.filter((item) => !item.adminOnly || isAdmin).map(({ key, label, icon: Icon }) => {
            const active = currentPage === key;
            return (
              <button
                key={key}
                onClick={() => go(key)}
                className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150 cursor-pointer w-full text-left group ${active ? 'nav-active-glow' : 'hover:bg-[var(--color-elevated)]'}`}
                style={active ? {} : { color: 'var(--color-text-muted)' }}
                aria-current={active ? 'page' : undefined}
              >
                <Icon
                  size={15}
                  className="flex-shrink-0 transition-colors duration-150"
                  style={{ color: active ? 'var(--color-primary)' : 'var(--color-text-dim)' }}
                />
                <span className="truncate">{label}</span>
                {active && (
                  <span
                    className="ml-auto w-1.5 h-1.5 rounded-full flex-shrink-0"
                    style={{ background: 'var(--color-primary)', boxShadow: '0 0 6px rgba(99,102,241,0.8)' }}
                  />
                )}
              </button>
            );
          })}
        </nav>
      )}

      {/* ── Bottom section ── */}
      {isAuthenticated && (
        <div
          className="p-2 flex flex-col gap-0.5 flex-shrink-0"
          style={{ borderTop: '1px solid var(--color-border)' }}
        >
          {/* Notifications */}
          <div ref={notifRef} className="relative">
            <button
              onClick={() => { setNotifOpen(o => !o); setUserOpen(false); }}
              className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm w-full transition-all duration-150 cursor-pointer hover:bg-[var(--color-elevated)]"
              style={{ color: 'var(--color-text-muted)' }}
              aria-label="Notifications"
            >
              <Bell size={15} className="flex-shrink-0" style={{ color: 'var(--color-text-dim)' }} />
              <span className="flex-1 text-left truncate">Notifications</span>
              {NOTIFICATIONS.length > 0 && (
                <span
                  className="w-4 h-4 rounded-full flex items-center justify-center text-white flex-shrink-0"
                  style={{ background: 'var(--color-danger)', fontSize: '9px', fontWeight: 700 }}
                >
                  {NOTIFICATIONS.length}
                </span>
              )}
            </button>

            {notifOpen && (
              <div
                className="absolute bottom-full mb-2 left-0 w-72 rounded-xl shadow-2xl overflow-hidden z-50 fade-up"
                style={{ background: 'var(--color-overlay)', border: '1px solid var(--color-border-bright)' }}
              >
                <div className="px-4 py-3 flex items-center justify-between" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Notifications</p>
                  <span className="section-label">recent</span>
                </div>
                {NOTIFICATIONS.map(n => (
                  <div key={n.id} className="flex items-start gap-3 px-4 py-3 hover:bg-[var(--color-elevated)] transition-colors duration-100" style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
                      style={{
                        background: n.type === 'alert' ? 'var(--color-danger-dim)' : 'var(--color-info-dim)',
                        color:      n.type === 'alert' ? 'var(--color-danger)'     : 'var(--color-info)',
                      }}
                    >
                      {n.type === 'alert' ? <AlertTriangle size={12} /> : <Bell size={12} />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm" style={{ color: 'var(--color-text)' }}>{n.message}</p>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)', fontFamily: 'IBM Plex Mono, monospace' }}>{n.time}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-all duration-150 cursor-pointer w-full text-left hover:bg-[var(--color-elevated)]"
            style={{ color: 'var(--color-text-muted)' }}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark'
              ? <Sun size={15} className="flex-shrink-0" style={{ color: 'var(--color-text-dim)' }} />
              : <Moon size={15} className="flex-shrink-0" style={{ color: 'var(--color-text-dim)' }} />}
            <span className="truncate">{theme === 'dark' ? 'Light mode' : 'Dark mode'}</span>
          </button>

          {/* Settings */}
          <button
            onClick={() => go('settings')}
            className={`flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-all duration-150 cursor-pointer w-full text-left ${currentPage === 'settings' ? 'nav-active-glow' : 'hover:bg-[var(--color-elevated)]'}`}
            style={currentPage === 'settings' ? {} : { color: 'var(--color-text-muted)' }}
          >
            <Settings size={15} className="flex-shrink-0" style={{ color: currentPage === 'settings' ? 'var(--color-primary)' : 'var(--color-text-dim)' }} />
            <span className="truncate">Settings</span>
          </button>

          {/* User menu */}
          <div ref={userRef} className="relative">
            <button
              onClick={() => { setUserOpen(o => !o); setNotifOpen(false); }}
              className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm w-full transition-all duration-150 cursor-pointer hover:bg-[var(--color-elevated)]"
              style={{ color: 'var(--color-text-muted)' }}
              aria-label="User menu"
              aria-expanded={userOpen}
            >
              <div
                className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 text-white font-bold"
                style={{
                  background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
                  fontSize: '10px',
                  letterSpacing: 0,
                }}
              >
                {(getSessionUsername() || 'U')[0].toUpperCase()}
              </div>
              <span className="flex-1 text-left truncate text-sm" style={{ color: 'var(--color-text)' }}>
                {getSessionUsername() || 'Account'}
              </span>
              <ChevronDown
                size={12}
                className="flex-shrink-0 transition-transform duration-200"
                style={{
                  color: 'var(--color-text-dim)',
                  transform: userOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                }}
              />
            </button>

            {userOpen && (
              <div
                className="absolute bottom-full mb-2 left-0 w-48 rounded-xl shadow-2xl overflow-hidden z-50 fade-up"
                style={{ background: 'var(--color-overlay)', border: '1px solid var(--color-border-bright)' }}
              >
                <div className="px-4 py-2.5" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="text-xs font-semibold" style={{ color: 'var(--color-text)' }}>{getSessionUsername() || 'Account'}</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>Free plan</p>
                </div>
                <button
                  onClick={() => { setUserOpen(false); onLogout(); }}
                  className="flex items-center gap-2.5 w-full px-4 py-2.5 text-sm text-left transition-colors duration-150 cursor-pointer hover:bg-[var(--color-elevated)]"
                  style={{ color: 'var(--color-danger)' }}
                >
                  <LogOut size={13} />
                  Sign out
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
      {/* Desktop sidebar */}
      <aside className="hidden md:flex flex-col h-screen sticky top-0 flex-shrink-0">
        <SidebarContent />
      </aside>

      {/* Mobile hamburger */}
      <button
        onClick={() => setMobileOpen(true)}
        className="md:hidden fixed top-4 left-4 z-40 w-9 h-9 rounded-xl flex items-center justify-center cursor-pointer shadow-lg transition-all duration-150 active:scale-95"
        style={{
          background: 'var(--color-card)',
          border: '1px solid var(--color-border)',
          color: 'var(--color-text-muted)',
        }}
        aria-label="Open menu"
      >
        <Menu size={16} />
      </button>

      {/* Mobile drawer */}
      {mobileOpen && (
        <>
          <div
            className="fixed inset-0 z-40 md:hidden"
            style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
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
