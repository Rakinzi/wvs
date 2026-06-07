import React, { useState, useEffect, useRef } from 'react';
import {
  BarChart2, Clock, Settings, LogOut,
  AlertTriangle, Globe, User, Bell, ChevronDown,
  Zap, Sun, Moon, BadgeCheck, Activity, Newspaper, BookOpen,
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
    setUserOpen(false);
  };

  const username = getSessionUsername() || 'Account';
  const initial  = username[0].toUpperCase();

  const SidebarContent = () => (
    <div style={{
      display: 'flex', flexDirection: 'column', height: '100%',
      background: 'var(--color-surface)',
      borderRight: '1px solid var(--color-border)',
      width: '200px',
    }}>

      {/* ── Logo ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 0,
        height: 52, padding: '0 12px',
        borderBottom: '1px solid var(--color-border)',
        flexShrink: 0,
      }}>
        <button onClick={() => isAuthenticated && go('dashboard')}
          style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'none', border: 'none', cursor: 'pointer', padding: '6px 8px', borderRadius: 6, flex: 1 }}
          aria-label="Go to dashboard">
          <img src="/launchguard-icon.svg" alt="" style={{ width: 24, height: 24, flexShrink: 0 }} />
          <span style={{
            fontFamily: "var(--font-display)",
            fontWeight: 700, fontSize: 14, letterSpacing: '-0.02em',
            color: 'var(--color-text)',
          }}>LaunchGuard</span>
        </button>
      </div>

      {/* ── Nav items ── */}
      {isAuthenticated && (
        <nav style={{ display: 'flex', flexDirection: 'column', gap: 1, padding: '8px', flex: 1, overflowY: 'auto' }}>

          {/* Group label */}
          <p style={{
            fontSize: 9, fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase',
            color: 'var(--color-text-dim)', fontFamily: "var(--font-mono)",
            padding: '8px 8px 4px', margin: 0,
          }}>Navigation</p>

          {NAV_ITEMS.filter(item => !item.adminOnly || isAdmin).map(({ key, label, icon: Icon }) => {
            const active = currentPage === key;
            return (
              <button key={key} onClick={() => go(key)}
                className={active ? 'nav-active-glow' : ''}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '7px 8px', borderRadius: 6,
                  fontSize: 13, fontWeight: active ? 600 : 400,
                  cursor: 'pointer', width: '100%', textAlign: 'left',
                  background: active ? undefined : 'none',
                  border: active ? undefined : '1px solid transparent',
                  color: active ? 'var(--color-text)' : 'var(--color-text-muted)',
                  transition: 'background 120ms, color 120ms',
                  letterSpacing: '-0.005em',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--color-elevated)'; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'none'; }}
                aria-current={active ? 'page' : undefined}>
                <Icon size={14} style={{ flexShrink: 0, color: active ? 'var(--color-primary)' : 'var(--color-text-dim)' }} />
                <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
              </button>
            );
          })}
        </nav>
      )}

      {/* ── Bottom section ── */}
      {isAuthenticated && (
        <div style={{ padding: '8px', borderTop: '1px solid var(--color-border)', display: 'flex', flexDirection: 'column', gap: 1, flexShrink: 0 }}>

          {/* Notifications */}
          <div ref={notifRef} style={{ position: 'relative' }}>
            <button onClick={() => { setNotifOpen(o => !o); setUserOpen(false); }}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '7px 8px', borderRadius: 6,
                fontSize: 13, fontWeight: 400, width: '100%', textAlign: 'left',
                background: 'none', border: '1px solid transparent', cursor: 'pointer',
                color: 'var(--color-text-muted)', transition: 'background 120ms',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--color-elevated)'}
              onMouseLeave={e => e.currentTarget.style.background = 'none'}
              aria-label="Notifications">
              <Bell size={14} style={{ flexShrink: 0, color: 'var(--color-text-dim)' }} />
              <span style={{ flex: 1 }}>Notifications</span>
              {NOTIFICATIONS.length > 0 && (
                <span style={{
                  width: 16, height: 16, borderRadius: 3,
                  background: 'var(--color-danger)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 9, fontWeight: 700, color: '#fff',
                  fontFamily: "var(--font-mono)", flexShrink: 0,
                }}>{NOTIFICATIONS.length}</span>
              )}
            </button>

            {notifOpen && (
              <div className="fade-up" style={{
                position: 'absolute', bottom: '100%', marginBottom: 6, left: 0,
                width: 264, borderRadius: 8, overflow: 'hidden', zIndex: 50,
                background: 'var(--color-overlay)', border: '1px solid var(--color-border-bright)',
                boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
              }}>
                <div style={{ padding: '10px 14px 8px', borderBottom: '1px solid var(--color-border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-text)', fontFamily: "var(--font-mono)", letterSpacing: '0.06em', textTransform: 'uppercase' }}>Notifications</span>
                  <span className="section-label">recent</span>
                </div>
                {NOTIFICATIONS.map(n => (
                  <div key={n.id} style={{
                    display: 'flex', alignItems: 'flex-start', gap: 10,
                    padding: '10px 14px',
                    borderBottom: '1px solid var(--color-border-subtle)',
                    transition: 'background 100ms',
                  }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--color-elevated)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'none'}>
                    <div style={{
                      width: 24, height: 24, borderRadius: 5, flexShrink: 0, marginTop: 1,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: n.type === 'alert' ? 'var(--color-danger-dim)' : 'var(--color-info-dim)',
                      color: n.type === 'alert' ? 'var(--color-danger)' : 'var(--color-info)',
                    }}>
                      {n.type === 'alert' ? <AlertTriangle size={11} /> : <Bell size={11} />}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p style={{ fontSize: 12, color: 'var(--color-text)', margin: 0, lineHeight: 1.4 }}>{n.message}</p>
                      <p style={{ fontSize: 10, color: 'var(--color-text-dim)', margin: '2px 0 0', fontFamily: "var(--font-mono)" }}>{n.time}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Theme toggle */}
          <button onClick={toggleTheme}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '7px 8px', borderRadius: 6,
              fontSize: 13, fontWeight: 400, width: '100%', textAlign: 'left',
              background: 'none', border: '1px solid transparent', cursor: 'pointer',
              color: 'var(--color-text-muted)', transition: 'background 120ms',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--color-elevated)'}
            onMouseLeave={e => e.currentTarget.style.background = 'none'}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
            {theme === 'dark'
              ? <Sun size={14} style={{ flexShrink: 0, color: 'var(--color-text-dim)' }} />
              : <Moon size={14} style={{ flexShrink: 0, color: 'var(--color-text-dim)' }} />}
            <span>{theme === 'dark' ? 'Light mode' : 'Dark mode'}</span>
          </button>

          {/* Settings */}
          <button onClick={() => go('settings')}
            className={currentPage === 'settings' ? 'nav-active-glow' : ''}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '7px 8px', borderRadius: 6,
              fontSize: 13, fontWeight: currentPage === 'settings' ? 600 : 400,
              width: '100%', textAlign: 'left', cursor: 'pointer',
              background: currentPage === 'settings' ? undefined : 'none',
              border: currentPage === 'settings' ? undefined : '1px solid transparent',
              color: currentPage === 'settings' ? 'var(--color-text)' : 'var(--color-text-muted)',
              transition: 'background 120ms',
            }}
            onMouseEnter={e => { if (currentPage !== 'settings') e.currentTarget.style.background = 'var(--color-elevated)'; }}
            onMouseLeave={e => { if (currentPage !== 'settings') e.currentTarget.style.background = 'none'; }}>
            <Settings size={14} style={{ flexShrink: 0, color: currentPage === 'settings' ? 'var(--color-primary)' : 'var(--color-text-dim)' }} />
            <span>Settings</span>
          </button>

          {/* User menu */}
          <div ref={userRef} style={{ position: 'relative' }}>
            <button onClick={() => { setUserOpen(o => !o); setNotifOpen(false); }}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '7px 8px', borderRadius: 6,
                fontSize: 13, fontWeight: 400, width: '100%', textAlign: 'left',
                background: 'none', border: '1px solid transparent', cursor: 'pointer',
                color: 'var(--color-text-muted)', transition: 'background 120ms',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--color-elevated)'}
              onMouseLeave={e => e.currentTarget.style.background = 'none'}
              aria-label="User menu" aria-expanded={userOpen}>
              <div style={{
                width: 22, height: 22, borderRadius: 4, flexShrink: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'var(--color-primary-dim)', color: 'var(--color-primary)',
                fontSize: 10, fontWeight: 700, fontFamily: "var(--font-mono)",
              }}>{initial}</div>
              <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--color-text)' }}>{username}</span>
              <ChevronDown size={11} style={{ flexShrink: 0, color: 'var(--color-text-dim)', transform: userOpen ? 'rotate(180deg)' : 'none', transition: 'transform 150ms' }} />
            </button>

            {userOpen && (
              <div className="fade-up" style={{
                position: 'absolute', bottom: '100%', marginBottom: 6, left: 0,
                width: 180, borderRadius: 8, overflow: 'hidden', zIndex: 50,
                background: 'var(--color-overlay)', border: '1px solid var(--color-border-bright)',
                boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
              }}>
                <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--color-border)' }}>
                  <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text)', margin: 0 }}>{username}</p>
                  <p style={{ fontSize: 10, color: 'var(--color-text-dim)', margin: '2px 0 0', fontFamily: "var(--font-mono)" }}>Free plan</p>
                </div>
                <button onClick={() => { setUserOpen(false); onLogout(); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    width: '100%', padding: '9px 14px', fontSize: 13, textAlign: 'left',
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--color-danger)', transition: 'background 100ms',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--color-elevated)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'none'}>
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
    <aside className="flex flex-col h-screen sticky top-0 flex-shrink-0">
      <SidebarContent />
    </aside>
  );
};

export default Sidebar;
