import React, { useState } from 'react';
import { Menu, X, ChevronRight } from 'lucide-react';

const C = {
  bg:      'var(--color-bg)',
  border:  'var(--color-border)',
  borderDefault: 'var(--color-border)',
  text:    'var(--color-text)',
  muted:   'var(--color-text-muted)',
  dim:     'var(--color-text-dim)',
  primary: 'var(--color-primary)',
};

const NAV_LINKS = [
  { label: 'Features',      href: '/landing#features' },
  { label: 'How it works',  href: '/landing#how-it-works' },
  { label: 'Pricing',       href: '/landing#pricing' },
  { label: 'Security News', href: '/news' },
];

/**
 * Shared navbar for public (unauthenticated) pages.
 * Props: scrolled, onLogoClick, onLogin, isAuthenticated, breadcrumb, landingLinks
 */
const PublicNav = ({
  scrolled = false,
  onLogoClick,
  onLogin,
  isAuthenticated = false,
  breadcrumb = null,
  landingLinks = false,
}) => {
  const [mobileOpen, setMobileOpen] = useState(false);

  const links = landingLinks ? NAV_LINKS : NAV_LINKS.filter(l => !l.href.startsWith('/landing'));

  return (
    <header style={{
      position: 'sticky', top: 0, zIndex: 40,
      background: scrolled ? 'var(--color-bg)' : 'transparent',
      backdropFilter: scrolled ? 'blur(20px) saturate(180%)' : 'none',
      borderBottom: scrolled ? `1px solid var(--color-border)` : '1px solid transparent',
      transition: 'all 250ms ease',
    }}>
      <div style={{ maxWidth: 1040, margin: '0 auto', padding: '0 24px', height: 60, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>

        {/* Logo + optional breadcrumb */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button onClick={onLogoClick} style={{ display: 'flex', alignItems: 'center', gap: 9, background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
            <img src="/launchguard-icon.svg" alt="LaunchGuard" style={{ width: 28, height: 28 }} />
            <span style={{
              fontFamily: "var(--font-display)",
              fontWeight: 700, fontSize: 15, letterSpacing: '-0.02em', color: C.text,
            }}>LaunchGuard</span>
          </button>
          {breadcrumb && (
            <>
              <ChevronRight size={12} color={C.dim} />
              <span style={{ fontSize: 12, fontWeight: 500, color: C.muted, fontFamily: "var(--font-mono)" }}>{breadcrumb}</span>
            </>
          )}
        </div>

        {/* Desktop nav links */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: 2 }} className="hidden-mobile">
          {links.map(({ label, href }) => (
            <a key={label} href={href}
              style={{ padding: '5px 12px', borderRadius: 5, fontSize: 13, color: C.muted, textDecoration: 'none', transition: 'color 150ms', fontWeight: 500 }}
              onMouseEnter={e => e.target.style.color = C.text}
              onMouseLeave={e => e.target.style.color = C.muted}>
              {label}
            </a>
          ))}
        </nav>

        {/* Right CTAs */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {isAuthenticated ? (
            <button onClick={onLogin} style={{
              padding: '6px 16px', borderRadius: 5, fontSize: 13, fontWeight: 700,
              background: C.primary, color: '#060608', border: 'none', cursor: 'pointer', fontFamily: 'inherit',
            }}>Dashboard</button>
          ) : (
            <>
              <button onClick={onLogin} className="show-desktop" style={{
                padding: '6px 14px', borderRadius: 5, fontSize: 13, fontWeight: 500,
                background: 'none', border: `1px solid ${C.borderDefault}`, color: C.muted,
                cursor: 'pointer', fontFamily: 'inherit', display: 'none', transition: 'border-color 150ms, color 150ms',
              }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = C.primary; e.currentTarget.style.color = C.primary; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = C.borderDefault; e.currentTarget.style.color = C.muted; }}>
                Sign in
              </button>
              <button onClick={onLogin} style={{
                padding: '6px 16px', borderRadius: 5, fontSize: 13, fontWeight: 700,
                background: C.primary, color: '#060608', border: 'none', cursor: 'pointer', fontFamily: 'inherit',
              }}>Get started</button>
            </>
          )}
          <button onClick={() => setMobileOpen(o => !o)} className="show-mobile"
            style={{ display: 'none', background: 'none', border: `1px solid ${C.borderDefault}`, borderRadius: 5, padding: 7, cursor: 'pointer', color: C.muted }}
            aria-label="Menu">
            {mobileOpen ? <X size={15} /> : <Menu size={15} />}
          </button>
        </div>
      </div>

      {/* Mobile drawer */}
      {mobileOpen && (
        <div style={{ borderTop: `1px solid var(--color-border)`, padding: '8px 16px 16px', display: 'flex', flexDirection: 'column', gap: 2, background: 'var(--color-bg)', backdropFilter: 'blur(20px)' }}>
          {links.map(({ label, href }) => (
            <a key={label} href={href} onClick={() => setMobileOpen(false)}
              style={{ padding: '9px 12px', borderRadius: 5, fontSize: 13, color: C.muted, textDecoration: 'none', display: 'block', fontWeight: 500 }}>
              {label}
            </a>
          ))}
          <button onClick={() => { setMobileOpen(false); onLogin(); }} style={{
            marginTop: 6, padding: '10px 12px', borderRadius: 5, fontSize: 13, fontWeight: 700,
            background: C.primary, border: 'none', color: '#060608', cursor: 'pointer', fontFamily: 'inherit', textAlign: 'left',
          }}>
            {isAuthenticated ? 'Dashboard' : 'Get started'}
          </button>
        </div>
      )}

      <style>{`
        @media (min-width: 768px) {
          .hidden-mobile { display: flex !important; }
          .show-desktop { display: block !important; }
        }
        @media (max-width: 767px) {
          .hidden-mobile { display: none !important; }
          .show-mobile { display: flex !important; }
        }
      `}</style>
    </header>
  );
};

export default PublicNav;
