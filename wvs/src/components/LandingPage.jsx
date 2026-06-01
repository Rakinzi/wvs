import React, { useState, useEffect } from 'react';
import { Shield, Zap, FileText, CheckCircle, BarChart2, ArrowRight, Activity, Eye } from 'lucide-react';
import PublicNav from './PublicNav';
import { isAuthenticated } from '../lib/auth';

const T = {
  bg:      'var(--color-bg)',
  surface: 'var(--color-surface)',
  card:    'var(--color-card)',
  elev:    'var(--color-elevated)',
  border:  'var(--color-border)',
  borderBright: 'var(--color-border-bright)',
  text:    'var(--color-text)',
  muted:   'var(--color-text-muted)',
  dim:     'var(--color-text-dim)',
  primary: 'var(--color-primary)',
  primaryDim: 'var(--color-primary-dim)',
  primaryGlow: 'var(--color-primary-glow)',
  amber:   'var(--color-secondary)',
  amberDim: 'var(--color-secondary-dim)',
  danger:  'var(--color-danger)',
  info:    'var(--color-info)',
};

const FEATURES = [
  {
    icon: Shield,
    title: 'OWASP Top 10 Coverage',
    desc: 'Full OWASP Web Top 10 (A01–A10) and OWASP LLM Top 10 2025 — from prompt injection to broken access control and SSRF.',
    accent: T.primary,
    dim: T.primaryDim,
  },
  {
    icon: Zap,
    title: 'Launch Verdict Engine',
    desc: 'Every scan produces a clear Blocked / Fix First / Monitor verdict so you know exactly what stands between you and shipping.',
    accent: T.amber,
    dim: T.amberDim,
  },
  {
    icon: Eye,
    title: 'Passive + Active Probing',
    desc: 'Passive analysis on every scan. Active SSRF probing and ZAP integration layer on top for deeper pre-launch audits.',
    accent: T.info,
    dim: 'rgba(91,159,255,0.1)',
  },
  {
    icon: BarChart2,
    title: 'Rescan Comparison',
    desc: 'Run a second scan after fixing issues and see exactly which vulnerabilities were resolved, which are new, which remain.',
    accent: T.primary,
    dim: T.primaryDim,
  },
  {
    icon: FileText,
    title: 'PDF & SBOM Reports',
    desc: 'Shareable PDF reports with OWASP compliance tables and per-finding remediation guidance. SBOM export for compliance teams.',
    accent: '#a855f7',
    dim: 'rgba(168,85,247,0.1)',
  },
  {
    icon: Activity,
    title: 'Uptime Monitoring',
    desc: 'Continuous uptime checks with configurable intervals alert you the moment your target goes down — no extra tooling required.',
    accent: T.danger,
    dim: 'rgba(255,79,79,0.1)',
  },
];

const SCANNERS = [
  'SQL Injection', 'XSS (Reflected)', 'SSL/TLS', 'HTTP Headers', 'OWASP ZAP',
  'WordPress Hardening', 'DNS / SPF / DMARC', 'Open Redirect', 'Subdomain Takeover',
  'Sensitive File Exposure', 'Hardcoded Secrets', 'Tech Fingerprinting',
  'SSRF (A10)', 'Auth Controls (A07)', 'Software Integrity (A08)', 'Logging & Monitoring (A09)',
  'Accessibility (WCAG)', 'Responsive UX', 'Performance UX', 'Form Usability',
  'SEO Readiness', 'Broken Links', 'Application Controls', 'Exposed Services',
  'Prompt Injection (LLM01)', 'Sensitive Info Disclosure (LLM02)', 'Excessive Agency (LLM06)',
];

const STATS = [
  { val: '83%',    label: 'of apps have security flaws on first scan',         src: 'Indusface, 2026' },
  { val: '$4.44M', label: 'average cost of a data breach globally',             src: 'IBM, 2025' },
  { val: '94%',    label: 'of apps have broken access control (OWASP A01)',     src: 'OWASP' },
  { val: '<5 days',label: 'median time to exploit a known vulnerability',       src: 'Edgescan, 2026' },
];

const HOW = [
  { n: '01', title: 'Enter your URL',        desc: 'Paste any web URL — no agent, no code changes.' },
  { n: '02', title: 'Choose a scan profile', desc: 'Security audit, product readiness, or full launch check.' },
  { n: '03', title: 'Get your verdict',      desc: 'Detailed report, OWASP coverage table, clear verdict.' },
  { n: '04', title: 'Fix, rescan, ship',     desc: 'Confirm every blocker resolved before you go live.' },
];

const PRICING = [
  {
    name: 'Starter', price: 'Free', period: '',
    desc: 'For indie hackers and early-stage projects.',
    features: ['5 scans / month', 'Full OWASP scanner suite', 'PDF + SBOM reports', 'Launch verdict engine', '1 verified target'],
    cta: 'Get started free', highlight: false,
  },
  {
    name: 'Pro', price: '$29', period: '/ month',
    desc: 'For teams shipping products to real users.',
    features: ['Unlimited scans', 'Active SSRF probing', 'Rescan comparisons', 'Uptime monitoring', '10 verified targets', 'Priority support'],
    cta: 'Start free trial', highlight: true,
  },
  {
    name: 'Enterprise', price: 'Custom', period: '',
    desc: 'For compliance-driven organisations.',
    features: ['Everything in Pro', 'SSO / SAML', 'Custom scan profiles', 'Dedicated SLA', 'Audit log export', 'Custom integrations'],
    cta: 'Contact us', highlight: false,
  },
];

const LandingPage = ({ navigateTo }) => {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    document.title = 'LaunchGuard — Security & UX Scanner for Launches';
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const authed = isAuthenticated();
  const goApp    = () => navigateTo(authed ? 'dashboard' : 'login');
  const goNews   = () => navigateTo('news');
  const goTerms  = () => navigateTo('terms');
  const goPrivacy = () => navigateTo('privacy');

  return (
    <div style={{ background: T.bg, color: T.text, fontFamily: "'Inter', system-ui, sans-serif", minHeight: '100vh' }}>

      <PublicNav scrolled={scrolled} onLogoClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })} onLogin={goApp} isAuthenticated={authed} landingLinks />

      {/* ── HERO ── */}
      <section style={{ position: 'relative', overflow: 'hidden' }}>
        {/* Background grid */}
        <div style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          backgroundImage: `linear-gradient(${T.border} 1px, transparent 1px), linear-gradient(90deg, ${T.border} 1px, transparent 1px)`,
          backgroundSize: '48px 48px', opacity: 0.5,
        }} />
        {/* Radial glow */}
        <div style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          background: `radial-gradient(ellipse 80% 50% at 50% 0%, rgba(0,212,170,0.07) 0%, transparent 70%)`,
        }} />

        <div style={{ position: 'relative', maxWidth: 1040, margin: '0 auto', padding: '100px 24px 88px', textAlign: 'center' }}>
          {/* Eyebrow */}
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '5px 14px', borderRadius: 3, border: `1px solid rgba(0,212,170,0.25)`, background: 'rgba(0,212,170,0.06)', marginBottom: 36 }}>
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: T.primary, display: 'block', boxShadow: `0 0 8px ${T.primary}` }} />
            <span style={{ fontSize: 11, fontWeight: 600, color: T.primary, letterSpacing: '0.1em', textTransform: 'uppercase', fontFamily: "'IBM Plex Mono', monospace" }}>
              OWASP Web Top 10 · OWASP LLM Top 10 2025
            </span>
          </div>

          <h1 style={{
            fontFamily: "'Syne', system-ui, sans-serif",
            fontSize: 'clamp(38px, 6vw, 72px)',
            fontWeight: 800,
            lineHeight: 1.0,
            letterSpacing: '-0.04em',
            margin: '0 0 28px',
            color: T.text,
          }}>
            Ship knowing<br />
            <span style={{ color: T.primary }}>your security</span><br />
            score.
          </h1>

          <p style={{ fontSize: 'clamp(15px, 1.8vw, 18px)', color: T.muted, lineHeight: 1.7, maxWidth: 560, margin: '0 auto 44px', fontWeight: 400 }}>
            83% of apps have exploitable flaws on day one. LaunchGuard runs 32 automated scanners
            and issues a single, actionable verdict — so you ship with eyes open.
          </p>

          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <button onClick={goApp} style={{
              display: 'inline-flex', alignItems: 'center', gap: 8,
              padding: '12px 26px', borderRadius: 6, fontSize: 14, fontWeight: 700,
              background: T.primary, color: '#060608', border: 'none', cursor: 'pointer',
              fontFamily: 'inherit', boxShadow: `0 0 28px ${T.primaryGlow}`,
              transition: 'box-shadow 150ms ease, transform 100ms ease',
            }}
              onMouseEnter={e => { e.currentTarget.style.boxShadow = `0 0 40px rgba(0,212,170,0.35)`; }}
              onMouseLeave={e => { e.currentTarget.style.boxShadow = `0 0 28px ${T.primaryGlow}`; }}>
              Start free scan <ArrowRight size={15} />
            </button>
            <button onClick={goNews} style={{
              display: 'inline-flex', alignItems: 'center', gap: 8,
              padding: '12px 26px', borderRadius: 6, fontSize: 14, fontWeight: 600,
              background: 'transparent', border: `1px solid ${T.borderBright}`,
              color: T.muted, cursor: 'pointer', fontFamily: 'inherit',
              transition: 'border-color 150ms, color 150ms',
            }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = T.primary; e.currentTarget.style.color = T.primary; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = T.borderBright; e.currentTarget.style.color = T.muted; }}>
              Security news
            </button>
          </div>

          <p style={{ marginTop: 28, fontSize: 12, color: T.dim, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.04em' }}>
            NO CREDIT CARD · RESULTS IN MINUTES · 48,174 CVEs TRACKED IN 2025
          </p>
        </div>
      </section>

      {/* ── STATS BAR ── */}
      <div style={{ borderTop: `1px solid ${T.border}`, borderBottom: `1px solid ${T.border}` }}>
        <div style={{ maxWidth: 1040, margin: '0 auto', padding: '0 24px', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)' }}>
          {STATS.map(({ val, label, src }, i) => (
            <div key={val} style={{
              padding: '32px 24px',
              borderRight: i < 3 ? `1px solid ${T.border}` : 'none',
            }}>
              <p style={{
                fontFamily: "'Syne', system-ui, sans-serif",
                fontSize: 'clamp(22px, 3vw, 34px)',
                fontWeight: 800, letterSpacing: '-0.04em',
                color: T.primary, margin: '0 0 6px',
              }}>{val}</p>
              <p style={{ fontSize: 13, color: T.muted, lineHeight: 1.5, marginBottom: 4 }}>{label}</p>
              <p style={{ fontSize: 10, color: T.dim, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.04em' }}>{src}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── TICKER ── */}
      <div style={{ borderBottom: `1px solid ${T.border}`, overflow: 'hidden', padding: '11px 0', background: T.surface }}>
        <div style={{ display: 'flex', gap: 40, animation: 'marquee 40s linear infinite', whiteSpace: 'nowrap' }}>
          {[...SCANNERS, ...SCANNERS].map((s, i) => (
            <span key={i} style={{
              display: 'inline-flex', alignItems: 'center', gap: 8,
              fontSize: 11, fontWeight: 600, color: T.dim,
              letterSpacing: '0.06em', fontFamily: "'IBM Plex Mono', monospace",
            }}>
              <span style={{ width: 3, height: 3, borderRadius: '50%', background: T.primary, flexShrink: 0, display: 'inline-block' }} />
              {s.toUpperCase()}
            </span>
          ))}
        </div>
      </div>

      {/* ── FEATURES ── */}
      <section id="features" style={{ maxWidth: 1040, margin: '0 auto', padding: '96px 24px' }}>
        <div style={{ marginBottom: 56 }}>
          <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.14em', color: T.primary, marginBottom: 14, fontFamily: "'IBM Plex Mono', monospace', textTransform: 'uppercase'" }}>CAPABILITIES</p>
          <h2 style={{ fontFamily: "'Syne', system-ui, sans-serif", fontSize: 'clamp(26px, 3.5vw, 42px)', fontWeight: 800, letterSpacing: '-0.035em', margin: '0 0 14px', maxWidth: 500 }}>
            Everything you need to ship safely.
          </h2>
          <p style={{ fontSize: 15, color: T.muted, maxWidth: 440 }}>
            One scan. One report. One verdict. No 15-tab security dashboard.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(290px, 1fr))', gap: 1, border: `1px solid ${T.border}`, borderRadius: 12, overflow: 'hidden' }}>
          {FEATURES.map(({ icon: Icon, title, desc, accent, dim }, idx) => (
            <div key={title} style={{
              background: T.card,
              borderRight: idx % 3 !== 2 ? `1px solid ${T.border}` : 'none',
              borderBottom: idx < 3 ? `1px solid ${T.border}` : 'none',
              padding: '28px 24px',
              transition: 'background 150ms',
              cursor: 'default',
            }}
              onMouseEnter={e => e.currentTarget.style.background = T.elev}
              onMouseLeave={e => e.currentTarget.style.background = T.card}>
              <div style={{ width: 36, height: 36, borderRadius: 6, background: dim, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 18 }}>
                <Icon size={17} color={accent} />
              </div>
              <p style={{ fontWeight: 700, fontSize: 14, marginBottom: 8, color: T.text, letterSpacing: '-0.01em' }}>{title}</p>
              <p style={{ fontSize: 13, color: T.muted, lineHeight: 1.65 }}>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── SCANNER LIST ── */}
      <section style={{ background: T.surface, borderTop: `1px solid ${T.border}`, borderBottom: `1px solid ${T.border}`, padding: '72px 24px' }}>
        <div style={{ maxWidth: 1040, margin: '0 auto' }}>
          <div style={{ marginBottom: 40 }}>
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.14em', color: T.primary, marginBottom: 14, fontFamily: "'IBM Plex Mono', monospace" }}>SCANNER SUITE</p>
            <h2 style={{ fontFamily: "'Syne', system-ui, sans-serif", fontSize: 'clamp(24px, 3vw, 36px)', fontWeight: 800, letterSpacing: '-0.035em', margin: '0 0 10px' }}>
              32 scanners. One report.
            </h2>
            <p style={{ fontSize: 14, color: T.muted, maxWidth: 560 }}>
              OWASP Web Top 10 · OWASP LLM Top 10 2025 · Accessibility · UX · SEO.
              Passive on every scan, active probing on launch audits.
            </p>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {SCANNERS.map((s) => (
              <span key={s} style={{
                padding: '5px 11px', borderRadius: 3,
                fontSize: 11, fontWeight: 600,
                background: T.elev, border: `1px solid ${T.borderBright}`,
                color: T.muted, fontFamily: "'IBM Plex Mono', monospace",
                letterSpacing: '0.03em',
              }}>{s}</span>
            ))}
          </div>
        </div>
      </section>

      {/* ── HOW IT WORKS ── */}
      <section id="how-it-works" style={{ maxWidth: 1040, margin: '0 auto', padding: '96px 24px' }}>
        <div style={{ marginBottom: 56 }}>
          <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.14em', color: T.primary, marginBottom: 14, fontFamily: "'IBM Plex Mono', monospace" }}>PROCESS</p>
          <h2 style={{ fontFamily: "'Syne', system-ui, sans-serif", fontSize: 'clamp(26px, 3.5vw, 42px)', fontWeight: 800, letterSpacing: '-0.035em', margin: 0 }}>
            From zero to launch-ready<br />in minutes.
          </h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 0, border: `1px solid ${T.border}`, borderRadius: 12, overflow: 'hidden' }}>
          {HOW.map(({ n, title, desc }, i) => (
            <div key={n} style={{
              background: T.card,
              borderRight: i < HOW.length - 1 ? `1px solid ${T.border}` : 'none',
              padding: '28px 24px',
            }}>
              <p style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, fontWeight: 700, color: T.primary, marginBottom: 18, letterSpacing: '0.08em' }}>{n}</p>
              <p style={{ fontWeight: 700, fontSize: 14, marginBottom: 8, color: T.text, letterSpacing: '-0.01em' }}>{title}</p>
              <p style={{ fontSize: 13, color: T.muted, lineHeight: 1.65 }}>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── PRICING ── */}
      <section id="pricing" style={{ background: T.surface, borderTop: `1px solid ${T.border}`, padding: '96px 24px' }}>
        <div style={{ maxWidth: 1040, margin: '0 auto' }}>
          <div style={{ marginBottom: 56 }}>
            <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.14em', color: T.primary, marginBottom: 14, fontFamily: "'IBM Plex Mono', monospace" }}>PRICING</p>
            <h2 style={{ fontFamily: "'Syne', system-ui, sans-serif", fontSize: 'clamp(26px, 3.5vw, 42px)', fontWeight: 800, letterSpacing: '-0.035em', margin: '0 0 12px' }}>
              Simple, honest pricing.
            </h2>
            <p style={{ fontSize: 15, color: T.muted }}>Start free. Upgrade when you need more.</p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(270px, 1fr))', gap: 16, maxWidth: 900, margin: '0 auto' }}>
            {PRICING.map(({ name, price, period, desc, features, cta, highlight }) => (
              <div key={name} style={{
                background: highlight ? 'rgba(0,212,170,0.04)' : T.card,
                border: highlight ? `1px solid rgba(0,212,170,0.3)` : `1px solid ${T.border}`,
                borderRadius: 12, padding: '32px 26px',
                position: 'relative',
                boxShadow: highlight ? `0 0 40px rgba(0,212,170,0.08)` : 'none',
              }}>
                {highlight && (
                  <span style={{
                    position: 'absolute', top: -11, left: '50%', transform: 'translateX(-50%)',
                    padding: '3px 12px', borderRadius: 3,
                    background: T.primary, fontSize: 10, fontWeight: 700,
                    color: '#060608', whiteSpace: 'nowrap',
                    fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.06em',
                  }}>MOST POPULAR</span>
                )}
                <p style={{ fontSize: 10, fontWeight: 700, color: highlight ? T.primary : T.muted, marginBottom: 10, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.1em' }}>{name.toUpperCase()}</p>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 8 }}>
                  <span style={{ fontFamily: "'Syne', system-ui, sans-serif", fontSize: 38, fontWeight: 800, letterSpacing: '-0.04em', color: T.text }}>{price}</span>
                  {period && <span style={{ fontSize: 13, color: T.muted }}>{period}</span>}
                </div>
                <p style={{ fontSize: 13, color: T.muted, marginBottom: 28, lineHeight: 1.6 }}>{desc}</p>
                <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 28px', display: 'flex', flexDirection: 'column', gap: 9 }}>
                  {features.map((f) => (
                    <li key={f} style={{ display: 'flex', alignItems: 'center', gap: 9, fontSize: 13, color: T.muted }}>
                      <CheckCircle size={13} color={T.primary} style={{ flexShrink: 0 }} />
                      {f}
                    </li>
                  ))}
                </ul>
                <button onClick={goApp} style={{
                  width: '100%', padding: '10px 20px', borderRadius: 6, fontSize: 13, fontWeight: 700,
                  background: highlight ? T.primary : 'transparent',
                  border: highlight ? 'none' : `1px solid ${T.borderBright}`,
                  color: highlight ? '#060608' : T.muted,
                  cursor: 'pointer', fontFamily: 'inherit',
                  transition: 'opacity 150ms',
                }}>
                  {cta}
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA BANNER ── */}
      <section style={{ maxWidth: 1040, margin: '0 auto', padding: '96px 24px' }}>
        <div style={{
          position: 'relative', overflow: 'hidden',
          background: T.card,
          border: `1px solid rgba(0,212,170,0.2)`,
          borderRadius: 12, padding: '60px 48px', textAlign: 'center',
        }}>
          <div style={{
            position: 'absolute', inset: 0, pointerEvents: 'none',
            background: `radial-gradient(ellipse 60% 60% at 50% 50%, rgba(0,212,170,0.06) 0%, transparent 70%)`,
          }} />
          <div style={{ position: 'relative' }}>
            <img src="/launchguard-icon.svg" alt="LaunchGuard" style={{ width: 44, height: 44, marginBottom: 24 }} />
            <h2 style={{ fontFamily: "'Syne', system-ui, sans-serif", fontSize: 'clamp(26px, 3.5vw, 42px)', fontWeight: 800, letterSpacing: '-0.04em', margin: '0 0 16px' }}>
              Ready to launch securely?
            </h2>
            <p style={{ fontSize: 15, color: T.muted, marginBottom: 36, maxWidth: 440, margin: '0 auto 36px', lineHeight: 1.65 }}>
              48,174 new CVEs were published in 2025. Run your first scan free and know your exposure before attackers do.
            </p>
            <button onClick={goApp} style={{
              display: 'inline-flex', alignItems: 'center', gap: 10,
              padding: '12px 28px', borderRadius: 6, fontSize: 14, fontWeight: 700,
              background: T.primary, color: '#060608', border: 'none', cursor: 'pointer',
              fontFamily: 'inherit', boxShadow: `0 0 36px rgba(0,212,170,0.3)`,
            }}>
              Scan your site now <ArrowRight size={15} />
            </button>
          </div>
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer style={{ borderTop: `1px solid ${T.border}`, padding: '32px 24px' }}>
        <div style={{ maxWidth: 1040, margin: '0 auto', display: 'flex', flexWrap: 'wrap', gap: 20, alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <img src="/launchguard-icon.svg" alt="LaunchGuard" style={{ width: 22, height: 22 }} />
            <span style={{ fontFamily: "'Syne', system-ui, sans-serif", fontWeight: 700, fontSize: 13, color: T.muted, letterSpacing: '-0.01em' }}>LaunchGuard</span>
          </div>
          <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
            {[
              { label: 'Security News', fn: goNews },
              { label: authed ? 'Dashboard' : 'Sign in', fn: goApp },
              ...(authed ? [] : [{ label: 'Get started', fn: goApp }]),
              { label: 'Terms', fn: goTerms },
              { label: 'Privacy', fn: goPrivacy },
            ].map(({ label, fn }) => (
              <button key={label} onClick={fn}
                style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 12, color: T.dim, fontFamily: 'inherit', padding: 0, transition: 'color 150ms', letterSpacing: '0.01em' }}
                onMouseEnter={e => e.target.style.color = T.muted}
                onMouseLeave={e => e.target.style.color = T.dim}>
                {label}
              </button>
            ))}
          </div>
          <p style={{ fontSize: 11, color: T.dim, margin: 0, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.02em' }}>
            © {new Date().getFullYear()} LAUNCHGUARD
          </p>
        </div>
      </footer>

      <style>{`
        @media (max-width: 767px) {
          .hidden-mobile { display: none !important; }
          .show-mobile { display: flex !important; }
        }
        @media (min-width: 768px) {
          .hidden-mobile { display: flex !important; }
          .show-desktop { display: flex !important; }
        }
        @media (max-width: 640px) {
          .stats-grid { grid-template-columns: repeat(2, 1fr) !important; }
          .feature-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </div>
  );
};

export default LandingPage;
