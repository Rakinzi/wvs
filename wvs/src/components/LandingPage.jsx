import React, { useState, useEffect } from 'react';
import {
  Shield, Zap, FileText, ChevronRight, CheckCircle,
  Lock, Globe, AlertTriangle, BarChart2, ArrowRight,
  ExternalLink, Menu, X, Activity, Eye, Search,
} from 'lucide-react';

const NAV_LINKS = [
  { label: 'Features', href: '#features' },
  { label: 'How it works', href: '#how-it-works' },
  { label: 'Pricing', href: '#pricing' },
  { label: 'Security News', href: '/news' },
];

const FEATURES = [
  {
    icon: Shield,
    title: 'OWASP Top 10 Coverage',
    desc: 'Full A01–A10 2021 coverage including SSRF, software integrity, logging gaps, and authentication failures — not just SQL injection.',
    color: '#6366f1',
    dim: 'rgba(99,102,241,0.12)',
  },
  {
    icon: Zap,
    title: 'Launch Verdict Engine',
    desc: 'Every scan produces a clear Blocked / Fix First / Monitor verdict so you know exactly what stands between you and shipping.',
    color: '#f59e0b',
    dim: 'rgba(245,158,11,0.12)',
  },
  {
    icon: Eye,
    title: 'Passive + Active Probing',
    desc: 'Passive analysis runs on every scan. Active SSRF probing and ZAP integration layer on top for deeper pre-launch audits.',
    color: '#38bdf8',
    dim: 'rgba(56,189,248,0.12)',
  },
  {
    icon: BarChart2,
    title: 'Rescan Comparison',
    desc: 'Run a second scan after fixing issues and see exactly which vulnerabilities were resolved, which are new, and which remain.',
    color: '#22c55e',
    dim: 'rgba(34,197,94,0.12)',
  },
  {
    icon: FileText,
    title: 'PDF & SBOM Reports',
    desc: 'Shareable PDF reports with OWASP compliance tables and per-finding remediation prompts. SBOM export for compliance teams.',
    color: '#a78bfa',
    dim: 'rgba(167,139,250,0.12)',
  },
  {
    icon: Activity,
    title: 'Uptime Monitoring',
    desc: 'Continuous uptime checks with configurable intervals alert you the moment your target goes down — no extra tooling required.',
    color: '#ef4444',
    dim: 'rgba(239,68,68,0.12)',
  },
];

const SCANNERS = [
  'SQL Injection', 'XSS (Reflected)', 'SSL/TLS', 'HTTP Headers', 'OWASP ZAP',
  'WordPress Hardening', 'DNS / SPF / DMARC', 'Open Redirect', 'Subdomain Takeover',
  'Sensitive File Exposure', 'Hardcoded Secrets', 'Tech Fingerprinting',
  'SSRF (A10)', 'Auth Controls (A07)', 'Software Integrity (A08)', 'Logging & Monitoring (A09)',
  'Accessibility (WCAG)', 'Responsive UX', 'Performance UX', 'Form Usability',
  'SEO Readiness', 'Broken Links', 'Application Controls', 'Exposed Services',
  'Abuse Controls', 'Visual AI Review',
];

const HOW_IT_WORKS = [
  { step: '01', title: 'Enter your URL', desc: 'Paste any web URL — no agent installation or code changes required.' },
  { step: '02', title: 'Choose a scan profile', desc: 'Full security scan, product readiness audit, or full launch audit — each scoped to your goal.' },
  { step: '03', title: 'Get your verdict', desc: 'In minutes you receive a detailed report, OWASP coverage table, and a clear launch verdict.' },
  { step: '04', title: 'Fix, rescan, ship', desc: 'Apply fixes and run a comparison scan to confirm every blocker is resolved before launch.' },
];

const PRICING_TIERS = [
  {
    name: 'Starter',
    price: 'Free',
    period: '',
    desc: 'For indie hackers and early-stage projects.',
    features: ['5 scans / month', 'Full OWASP scanner suite', 'PDF + SBOM reports', 'Launch verdict engine', '1 verified target'],
    cta: 'Get started free',
    highlight: false,
  },
  {
    name: 'Pro',
    price: '$29',
    period: '/ month',
    desc: 'For teams shipping products to real users.',
    features: ['Unlimited scans', 'Active SSRF probing', 'Rescan comparisons', 'Uptime monitoring', '10 verified targets', 'Priority support'],
    cta: 'Start free trial',
    highlight: true,
  },
  {
    name: 'Enterprise',
    price: 'Custom',
    period: '',
    desc: 'For compliance-driven organisations.',
    features: ['Everything in Pro', 'SSO / SAML', 'Custom scan profiles', 'Dedicated SLA', 'Audit log export', 'Custom integrations'],
    cta: 'Contact us',
    highlight: false,
  },
];

const LandingPage = ({ navigateTo }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    document.title = 'LaunchGuard — Security & UX Scanner for Launches';
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const goApp = () => navigateTo('login');
  const goNews = () => navigateTo('news');

  return (
    <div style={{ background: '#09090b', color: '#fafafa', fontFamily: "'Plus Jakarta Sans', system-ui, sans-serif", minHeight: '100vh' }}>

      {/* ── Navbar ── */}
      <header style={{
        position: 'sticky', top: 0, zIndex: 40,
        background: scrolled ? 'rgba(9,9,11,0.92)' : 'transparent',
        backdropFilter: scrolled ? 'blur(16px)' : 'none',
        borderBottom: scrolled ? '1px solid rgba(39,39,42,0.8)' : '1px solid transparent',
        transition: 'all 300ms ease',
      }}>
        <div style={{ maxWidth: 1120, margin: '0 auto', padding: '0 24px', height: 64, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          {/* Logo */}
          <button onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
            style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'none', border: 'none', cursor: 'pointer' }}>
            <div style={{
              width: 32, height: 32, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
              boxShadow: '0 0 18px rgba(99,102,241,0.4)',
            }}>
              <Shield size={16} color="white" />
            </div>
            <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: '-0.02em', background: 'linear-gradient(135deg, #818cf8 0%, #6366f1 40%, #a78bfa 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
              LaunchGuard
            </span>
          </button>

          {/* Desktop nav */}
          <nav style={{ display: 'flex', alignItems: 'center', gap: 4 }} className="hidden-mobile">
            {NAV_LINKS.map(({ label, href }) => (
              href.startsWith('/') ? (
                <button key={label} onClick={href === '/news' ? goNews : goApp}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '6px 14px', borderRadius: 8, fontSize: 14, color: '#a1a1aa', fontFamily: 'inherit', transition: 'color 150ms' }}
                  onMouseEnter={e => e.target.style.color = '#fafafa'}
                  onMouseLeave={e => e.target.style.color = '#a1a1aa'}>
                  {label}
                </button>
              ) : (
                <a key={label} href={href}
                  style={{ padding: '6px 14px', borderRadius: 8, fontSize: 14, color: '#a1a1aa', textDecoration: 'none', transition: 'color 150ms' }}
                  onMouseEnter={e => e.target.style.color = '#fafafa'}
                  onMouseLeave={e => e.target.style.color = '#a1a1aa'}>
                  {label}
                </a>
              )
            ))}
          </nav>

          {/* CTA */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button onClick={goApp}
              style={{ display: 'none', padding: '7px 14px', borderRadius: 8, fontSize: 13, fontWeight: 600, background: 'none', border: '1px solid #3f3f46', color: '#a1a1aa', cursor: 'pointer', fontFamily: 'inherit' }}
              className="show-desktop">
              Sign in
            </button>
            <button onClick={goApp}
              style={{ padding: '7px 16px', borderRadius: 8, fontSize: 13, fontWeight: 700, background: 'linear-gradient(135deg, #6366f1, #4f46e5)', border: 'none', color: 'white', cursor: 'pointer', fontFamily: 'inherit', boxShadow: '0 0 18px rgba(99,102,241,0.3)' }}>
              Get started
            </button>
            <button onClick={() => setMobileOpen(o => !o)}
              style={{ display: 'none', background: 'none', border: '1px solid #3f3f46', borderRadius: 8, padding: 7, cursor: 'pointer', color: '#a1a1aa' }}
              className="show-mobile" aria-label="Menu">
              {mobileOpen ? <X size={16} /> : <Menu size={16} />}
            </button>
          </div>
        </div>

        {/* Mobile nav */}
        {mobileOpen && (
          <div style={{ borderTop: '1px solid #27272a', padding: '8px 16px 16px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            {NAV_LINKS.map(({ label, href }) => (
              <button key={label}
                onClick={() => { setMobileOpen(false); if (href === '/news') goNews(); else if (href.startsWith('/')) goApp(); else document.querySelector(href)?.scrollIntoView({ behavior: 'smooth' }); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '10px 12px', borderRadius: 8, fontSize: 14, color: '#a1a1aa', fontFamily: 'inherit', textAlign: 'left' }}>
                {label}
              </button>
            ))}
          </div>
        )}
      </header>

      {/* ── Hero ── */}
      <section style={{ maxWidth: 1120, margin: '0 auto', padding: '96px 24px 80px', textAlign: 'center' }}>
        {/* Badge */}
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '5px 14px', borderRadius: 100, border: '1px solid rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)', marginBottom: 32 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#6366f1', boxShadow: '0 0 8px rgba(99,102,241,0.8)' }} />
          <span style={{ fontSize: 12, fontWeight: 600, color: '#818cf8', letterSpacing: '0.02em' }}>OWASP Top 10 2021 — Full Coverage</span>
        </div>

        <h1 style={{ fontSize: 'clamp(36px, 6vw, 68px)', fontWeight: 800, lineHeight: 1.08, letterSpacing: '-0.03em', margin: '0 0 24px' }}>
          Ship with confidence.<br />
          <span style={{ background: 'linear-gradient(135deg, #818cf8 0%, #6366f1 40%, #a78bfa 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
            Know your security score
          </span>{' '}before launch.
        </h1>

        <p style={{ fontSize: 'clamp(16px, 2vw, 20px)', color: '#71717a', lineHeight: 1.6, maxWidth: 620, margin: '0 auto 40px' }}>
          LaunchGuard runs 26 automated scanners — security, accessibility, UX, and SEO — and tells you
          exactly what blocks your launch, in minutes, with no agent to install.
        </p>

        <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
          <button onClick={goApp}
            style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 28px', borderRadius: 10, fontSize: 15, fontWeight: 700, background: 'linear-gradient(135deg, #6366f1, #4f46e5)', border: 'none', color: 'white', cursor: 'pointer', fontFamily: 'inherit', boxShadow: '0 0 32px rgba(99,102,241,0.35)' }}>
            Start a free scan <ArrowRight size={16} />
          </button>
          <button onClick={goNews}
            style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 28px', borderRadius: 10, fontSize: 15, fontWeight: 600, background: 'rgba(255,255,255,0.04)', border: '1px solid #3f3f46', color: '#a1a1aa', cursor: 'pointer', fontFamily: 'inherit' }}>
            Security news <ExternalLink size={14} />
          </button>
        </div>

        {/* Social proof */}
        <p style={{ marginTop: 32, fontSize: 13, color: '#52525b' }}>
          Trusted by pre-launch founders · No credit card required
        </p>
      </section>

      {/* ── Scanner coverage ticker ── */}
      <div style={{ borderTop: '1px solid #27272a', borderBottom: '1px solid #27272a', overflow: 'hidden', padding: '12px 0' }}>
        <div style={{ display: 'flex', gap: 32, animation: 'marquee 35s linear infinite', whiteSpace: 'nowrap' }}>
          {[...SCANNERS, ...SCANNERS].map((s, i) => (
            <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 12, fontWeight: 600, color: '#52525b', letterSpacing: '0.04em', fontFamily: "'IBM Plex Mono', monospace" }}>
              <span style={{ width: 4, height: 4, borderRadius: '50%', background: '#6366f1', display: 'inline-block', flexShrink: 0 }} />
              {s.toUpperCase()}
            </span>
          ))}
        </div>
      </div>

      {/* ── Features ── */}
      <section id="features" style={{ maxWidth: 1120, margin: '0 auto', padding: '100px 24px' }}>
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <p style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.12em', color: '#6366f1', marginBottom: 12, fontFamily: "'IBM Plex Mono', monospace" }}>WHAT YOU GET</p>
          <h2 style={{ fontSize: 'clamp(28px, 4vw, 44px)', fontWeight: 800, letterSpacing: '-0.025em', margin: '0 0 16px' }}>
            Everything you need to ship safely.
          </h2>
          <p style={{ fontSize: 16, color: '#71717a', maxWidth: 520, margin: '0 auto' }}>
            One scan, one report, one verdict. No 15-tab security dashboard.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
          {FEATURES.map(({ icon: Icon, title, desc, color, dim }) => (
            <div key={title} style={{ background: '#141418', border: '1px solid #27272a', borderRadius: 14, padding: '28px 28px', transition: 'border-color 200ms', cursor: 'default' }}
              onMouseEnter={e => e.currentTarget.style.borderColor = `${color}50`}
              onMouseLeave={e => e.currentTarget.style.borderColor = '#27272a'}>
              <div style={{ width: 44, height: 44, borderRadius: 12, background: dim, display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 20 }}>
                <Icon size={20} color={color} />
              </div>
              <p style={{ fontWeight: 700, fontSize: 15, marginBottom: 8, color: '#fafafa' }}>{title}</p>
              <p style={{ fontSize: 14, color: '#71717a', lineHeight: 1.6 }}>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Scanner list ── */}
      <section style={{ background: '#0f0f11', borderTop: '1px solid #27272a', borderBottom: '1px solid #27272a', padding: '80px 24px' }}>
        <div style={{ maxWidth: 1120, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 48 }}>
            <p style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.12em', color: '#6366f1', marginBottom: 12, fontFamily: "'IBM Plex Mono', monospace" }}>SCANNER SUITE</p>
            <h2 style={{ fontSize: 'clamp(24px, 3.5vw, 38px)', fontWeight: 800, letterSpacing: '-0.025em', margin: '0 0 12px' }}>26 scanners. One report.</h2>
            <p style={{ fontSize: 15, color: '#71717a' }}>Passive analysis on every scan. Active probing available for launch audits.</p>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
            {SCANNERS.map((s) => (
              <span key={s} style={{ padding: '6px 14px', borderRadius: 100, fontSize: 12, fontWeight: 600, background: '#1c1c22', border: '1px solid #3f3f46', color: '#a1a1aa', fontFamily: "'IBM Plex Mono', monospace" }}>
                {s}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── How it works ── */}
      <section id="how-it-works" style={{ maxWidth: 1120, margin: '0 auto', padding: '100px 24px' }}>
        <div style={{ textAlign: 'center', marginBottom: 64 }}>
          <p style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.12em', color: '#6366f1', marginBottom: 12, fontFamily: "'IBM Plex Mono', monospace" }}>HOW IT WORKS</p>
          <h2 style={{ fontSize: 'clamp(28px, 4vw, 44px)', fontWeight: 800, letterSpacing: '-0.025em', margin: 0 }}>
            From zero to launch-ready in minutes.
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 20 }}>
          {HOW_IT_WORKS.map(({ step, title, desc }, i) => (
            <div key={step} style={{ position: 'relative' }}>
              <div style={{ background: '#141418', border: '1px solid #27272a', borderRadius: 14, padding: '28px 24px' }}>
                <div style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, fontWeight: 700, color: '#6366f1', marginBottom: 16, letterSpacing: '0.08em' }}>{step}</div>
                <p style={{ fontWeight: 700, fontSize: 15, marginBottom: 8, color: '#fafafa' }}>{title}</p>
                <p style={{ fontSize: 13, color: '#71717a', lineHeight: 1.6 }}>{desc}</p>
              </div>
              {i < HOW_IT_WORKS.length - 1 && (
                <div style={{ display: 'none', position: 'absolute', right: -16, top: '50%', transform: 'translateY(-50%)', color: '#3f3f46' }}>
                  <ChevronRight size={20} />
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* ── Pricing ── */}
      <section id="pricing" style={{ background: '#0f0f11', borderTop: '1px solid #27272a', padding: '100px 24px' }}>
        <div style={{ maxWidth: 1120, margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: 64 }}>
            <p style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.12em', color: '#6366f1', marginBottom: 12, fontFamily: "'IBM Plex Mono', monospace" }}>PRICING</p>
            <h2 style={{ fontSize: 'clamp(28px, 4vw, 44px)', fontWeight: 800, letterSpacing: '-0.025em', margin: '0 0 16px' }}>Simple, honest pricing.</h2>
            <p style={{ fontSize: 16, color: '#71717a' }}>Start free. Upgrade when you need more.</p>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20, maxWidth: 940, margin: '0 auto' }}>
            {PRICING_TIERS.map(({ name, price, period, desc, features, cta, highlight }) => (
              <div key={name} style={{
                background: highlight ? 'rgba(99,102,241,0.06)' : '#141418',
                border: highlight ? '2px solid #6366f1' : '1px solid #27272a',
                borderRadius: 16, padding: '32px 28px',
                position: 'relative',
                boxShadow: highlight ? '0 0 40px rgba(99,102,241,0.15)' : 'none',
              }}>
                {highlight && (
                  <span style={{ position: 'absolute', top: -12, left: '50%', transform: 'translateX(-50%)', padding: '3px 12px', borderRadius: 100, background: '#6366f1', fontSize: 11, fontWeight: 700, color: 'white', whiteSpace: 'nowrap' }}>
                    Most popular
                  </span>
                )}
                <p style={{ fontSize: 13, fontWeight: 700, color: '#6366f1', marginBottom: 8, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.06em' }}>{name.toUpperCase()}</p>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 8 }}>
                  <span style={{ fontSize: 40, fontWeight: 800, letterSpacing: '-0.04em', color: '#fafafa' }}>{price}</span>
                  {period && <span style={{ fontSize: 14, color: '#71717a' }}>{period}</span>}
                </div>
                <p style={{ fontSize: 13, color: '#71717a', marginBottom: 28, lineHeight: 1.5 }}>{desc}</p>
                <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 28px', display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {features.map((f) => (
                    <li key={f} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, color: '#a1a1aa' }}>
                      <CheckCircle size={14} color="#22c55e" style={{ flexShrink: 0 }} />
                      {f}
                    </li>
                  ))}
                </ul>
                <button onClick={goApp}
                  style={{
                    width: '100%', padding: '11px 20px', borderRadius: 9, fontSize: 14, fontWeight: 700,
                    background: highlight ? 'linear-gradient(135deg, #6366f1, #4f46e5)' : 'rgba(255,255,255,0.04)',
                    border: highlight ? 'none' : '1px solid #3f3f46',
                    color: highlight ? 'white' : '#a1a1aa',
                    cursor: 'pointer', fontFamily: 'inherit',
                    boxShadow: highlight ? '0 0 20px rgba(99,102,241,0.3)' : 'none',
                  }}>
                  {cta}
                </button>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA banner ── */}
      <section style={{ maxWidth: 1120, margin: '0 auto', padding: '100px 24px' }}>
        <div style={{
          background: 'linear-gradient(135deg, rgba(99,102,241,0.12) 0%, rgba(167,139,250,0.06) 100%)',
          border: '1px solid rgba(99,102,241,0.25)',
          borderRadius: 20, padding: '64px 48px', textAlign: 'center',
        }}>
          <div style={{ width: 52, height: 52, borderRadius: 14, background: 'rgba(99,102,241,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 24px' }}>
            <Lock size={24} color="#818cf8" />
          </div>
          <h2 style={{ fontSize: 'clamp(28px, 4vw, 44px)', fontWeight: 800, letterSpacing: '-0.03em', margin: '0 0 16px' }}>
            Ready to launch securely?
          </h2>
          <p style={{ fontSize: 16, color: '#71717a', marginBottom: 36, maxWidth: 480, margin: '0 auto 36px' }}>
            Run your first scan free. No credit card. No agent. Results in minutes.
          </p>
          <button onClick={goApp}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 10, padding: '14px 32px', borderRadius: 10, fontSize: 15, fontWeight: 700, background: 'linear-gradient(135deg, #6366f1, #4f46e5)', border: 'none', color: 'white', cursor: 'pointer', fontFamily: 'inherit', boxShadow: '0 0 40px rgba(99,102,241,0.4)' }}>
            Scan your site now <ArrowRight size={16} />
          </button>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer style={{ borderTop: '1px solid #27272a', padding: '40px 24px' }}>
        <div style={{ maxWidth: 1120, margin: '0 auto', display: 'flex', flexWrap: 'wrap', gap: 24, alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 26, height: 26, borderRadius: 7, background: 'linear-gradient(135deg, #6366f1, #4f46e5)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={13} color="white" />
            </div>
            <span style={{ fontWeight: 700, fontSize: 13, color: '#52525b' }}>LaunchGuard</span>
          </div>
          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
            {['Security News', 'Sign in', 'Get started'].map((label) => (
              <button key={label} onClick={label === 'Security News' ? goNews : goApp}
                style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, color: '#52525b', fontFamily: 'inherit', padding: 0, transition: 'color 150ms' }}
                onMouseEnter={e => e.target.style.color = '#a1a1aa'}
                onMouseLeave={e => e.target.style.color = '#52525b'}>
                {label}
              </button>
            ))}
          </div>
          <p style={{ fontSize: 12, color: '#3f3f46', margin: 0 }}>© {new Date().getFullYear()} LaunchGuard. All rights reserved.</p>
        </div>
      </footer>

      <style>{`
        @keyframes marquee {
          from { transform: translateX(0); }
          to { transform: translateX(-50%); }
        }
        @media (min-width: 768px) {
          .hidden-mobile { display: flex !important; }
          .show-desktop { display: block !important; }
        }
        @media (max-width: 767px) {
          .hidden-mobile { display: none !important; }
          .show-mobile { display: flex !important; }
        }
      `}</style>
    </div>
  );
};

export default LandingPage;
