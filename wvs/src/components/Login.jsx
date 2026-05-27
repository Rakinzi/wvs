import React, { useState, useEffect, useContext } from 'react';
import { Shield, Lock, AlertTriangle, Eye, EyeOff, ArrowRight, Mail, X, CheckCircle, AtSign, ShieldCheck, Activity, Globe, Zap } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { saveSession } from '../lib/auth';
import { apiJson, ApiError } from '../lib/api';
import { ThemeContext } from '../hooks/useTheme';
import Spinner from './Spinner';

const ForgotPasswordModal = ({ onClose }) => {
  const [email, setEmail]     = useState('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent]       = useState(false);
  const [error, setError]     = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email) { setError('Please enter your email address'); return; }
    setLoading(true); setError('');
    try {
      await apiJson('/forgot-password', { method: 'POST', json: true, body: { email } });
      setSent(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to send reset email');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(12px)' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-sm rounded-2xl overflow-hidden shadow-2xl"
        style={{ background: 'var(--color-card)', border: '1px solid var(--color-border-bright)', animation: 'modalIn 200ms cubic-bezier(0.34,1.56,0.64,1) both' }}>
        <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: 'var(--color-primary-dim)' }}>
              <Lock size={13} style={{ color: 'var(--color-primary)' }} />
            </div>
            <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Reset password</h3>
          </div>
          <button onClick={onClose} className="w-6 h-6 flex items-center justify-center rounded-md cursor-pointer hover:bg-[var(--color-elevated)]" style={{ color: 'var(--color-text-dim)' }}>
            <X size={14} />
          </button>
        </div>
        <div className="px-6 py-5">
          {sent ? (
            <div className="flex flex-col items-center gap-3 py-4 text-center">
              <div className="w-12 h-12 rounded-2xl flex items-center justify-center" style={{ background: 'var(--color-secure-dim)' }}>
                <CheckCircle size={22} style={{ color: 'var(--color-secure)' }} />
              </div>
              <p className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Check your inbox</p>
              <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-muted)' }}>
                If an account exists for <strong style={{ color: 'var(--color-text)' }}>{email}</strong>, a reset link is on its way.
              </p>
              <button onClick={onClose} className="btn-primary w-full justify-center mt-1">Back to sign in</button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <p className="text-sm" style={{ color: 'var(--color-text-muted)', lineHeight: 1.6 }}>Enter your email and we'll send a secure reset link.</p>
              <div className="flex flex-col gap-1.5">
                <label htmlFor="reset-email" className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)' }}>Email address</label>
                <div className="relative">
                  <Mail size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)', pointerEvents: 'none' }} />
                  <input id="reset-email" type="email" autoComplete="email" value={email}
                    onChange={e => { setEmail(e.target.value); setError(''); }}
                    placeholder="you@example.com" className="input"
                    style={{ paddingLeft: '2.25rem', borderColor: error ? 'var(--color-danger)' : undefined }} />
                </div>
                {error && <p className="text-xs" style={{ color: 'var(--color-danger)' }}>{error}</p>}
              </div>
              <div className="flex gap-2">
                <button type="button" onClick={onClose} className="btn-secondary flex-1 justify-center">Cancel</button>
                <button type="submit" disabled={loading} className="btn-primary flex-1 justify-center" style={{ opacity: loading ? 0.7 : 1 }}>
                  {loading ? <Spinner size="sm" /> : 'Send link'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

/* Shared split-screen wrapper used by Login and Register */
export const AuthLayout = ({ visible, isDark, heroContent, children }) => {
  const heroBg = isDark
    ? 'linear-gradient(140deg, #0c0c16 0%, #0a0a13 60%, #0e0e1c 100%)'
    : 'linear-gradient(140deg, #eef2ff 0%, #e0e7ff 55%, #ede9fe 100%)';
  const heroMesh = isDark
    ? 'radial-gradient(ellipse 70% 55% at 65% 25%, rgba(99,102,241,0.13) 0%, transparent 65%), radial-gradient(ellipse 45% 45% at 25% 85%, rgba(79,70,229,0.07) 0%, transparent 60%)'
    : 'radial-gradient(ellipse 70% 55% at 65% 25%, rgba(99,102,241,0.2) 0%, transparent 65%), radial-gradient(ellipse 45% 45% at 25% 85%, rgba(79,70,229,0.1) 0%, transparent 60%)';
  const dotColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(99,102,241,0.15)';

  return (
    <div style={{ display: 'flex', minHeight: '100dvh', background: 'var(--color-bg)' }}>
      {/* 40% form side */}
      <div style={{
        flex: '0 0 40%', display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: '48px 40px', borderRight: '1px solid var(--color-border)',
        opacity: visible ? 1 : 0, transform: visible ? 'none' : 'translateX(-14px)',
        transition: 'opacity 380ms ease, transform 380ms ease',
      }}>
        <div style={{ width: '100%', maxWidth: 340 }}>
          {children}
        </div>
      </div>

      {/* 60% hero side */}
      <div style={{
        flex: '0 0 60%', position: 'relative', overflow: 'hidden', background: heroBg,
        opacity: visible ? 1 : 0, transform: visible ? 'none' : 'translateX(14px)',
        transition: 'opacity 480ms ease 80ms, transform 480ms ease 80ms, background 300ms ease',
      }}>
        <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', background: heroMesh }} />
        <div style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          backgroundImage: `radial-gradient(circle, ${dotColor} 1px, transparent 1px)`,
          backgroundSize: '26px 26px', opacity: isDark ? 0.4 : 0.6,
        }} />
        <div style={{ position: 'relative', height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '52px 48px', gap: 20 }}>
          {heroContent}
        </div>
      </div>

      <style>{`
        @keyframes modalIn {
          from { opacity: 0; transform: scale(0.95) translateY(8px); }
          to   { opacity: 1; transform: scale(1) translateY(0); }
        }
        @media (max-width: 900px) {
          .auth-split { flex-direction: column !important; }
          .auth-form-panel { flex: unset !important; width: 100% !important; border-right: none !important; border-bottom: 1px solid var(--color-border) !important; }
          .auth-hero-panel { flex: unset !important; min-height: 260px !important; }
        }
      `}</style>
    </div>
  );
};

const HeroContent = ({ isDark }) => {
  const bars = [52, 38, 70, 48, 85, 36, 76, 60, 68, 50, 92, 64];
  const threats = [
    { label: 'SQL Injection',  severity: 'critical', count: 3 },
    { label: 'XSS Reflected',  severity: 'high',     count: 7 },
    { label: 'Open Redirect',  severity: 'medium',   count: 12 },
  ];
  const sev = { critical: '#ef4444', high: '#f59e0b', medium: '#38bdf8' };
  const txt  = isDark ? 'rgba(255,255,255,0.88)' : 'rgba(10,10,20,0.88)';
  const dim  = isDark ? 'rgba(255,255,255,0.38)' : 'rgba(10,10,20,0.38)';
  const card = isDark ? 'rgba(255,255,255,0.05)' : 'rgba(10,10,20,0.04)';
  const bdr  = isDark ? 'rgba(255,255,255,0.09)' : 'rgba(10,10,20,0.09)';
  const bar  = isDark ? 'rgba(255,255,255,0.1)'  : 'rgba(10,10,20,0.08)';

  return (
    <>
      {/* Headline */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(99,102,241,0.14)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 100, padding: '4px 12px', marginBottom: 18 }}>
          <span style={{ position: 'relative', display: 'inline-block' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', display: 'block', boxShadow: '0 0 8px #22c55e' }} />
          </span>
          <span style={{ fontSize: 10.5, fontWeight: 700, color: '#a5b4fc', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Live protection active</span>
        </div>
        <h2 style={{ fontSize: 30, fontWeight: 800, lineHeight: 1.2, color: txt, letterSpacing: '-0.035em', margin: '0 0 12px' }}>
          Security intelligence<br />
          <span style={{ background: 'linear-gradient(135deg, #818cf8 0%, #6366f1 50%, #a78bfa 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
            for modern teams.
          </span>
        </h2>
        <p style={{ fontSize: 13.5, color: dim, lineHeight: 1.7, maxWidth: 340, margin: 0 }}>
          Continuous scanning, instant threat detection, and actionable reports — all in one platform.
        </p>
      </div>

      {/* Scan activity card */}
      <div style={{ background: card, border: `1px solid ${bdr}`, borderRadius: 14, padding: '18px 18px 14px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div>
            <p style={{ fontSize: 10, fontWeight: 700, color: dim, letterSpacing: '0.07em', textTransform: 'uppercase', margin: 0 }}>Scan Activity</p>
            <p style={{ fontSize: 19, fontWeight: 700, color: txt, margin: '3px 0 0', letterSpacing: '-0.03em' }}>
              1,284 <span style={{ fontSize: 12, fontWeight: 500, color: dim }}>this month</span>
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 100, padding: '3px 9px' }}>
            <Activity size={10} color="#22c55e" />
            <span style={{ fontSize: 10.5, fontWeight: 700, color: '#22c55e' }}>+18%</span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 44 }}>
          {bars.map((h, i) => (
            <div key={i} style={{ flex: 1, borderRadius: 3, background: i === bars.length - 1 ? '#6366f1' : bar, height: `${h}%` }} />
          ))}
        </div>
      </div>

      {/* Findings card */}
      <div style={{ background: card, border: `1px solid ${bdr}`, borderRadius: 14, padding: '14px 18px' }}>
        <p style={{ fontSize: 10, fontWeight: 700, color: dim, letterSpacing: '0.07em', textTransform: 'uppercase', margin: '0 0 10px' }}>Recent Findings</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {threats.map((t, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 5, height: 5, borderRadius: '50%', background: sev[t.severity], flexShrink: 0 }} />
                <span style={{ fontSize: 12.5, color: txt, fontWeight: 500 }}>{t.label}</span>
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, color: sev[t.severity], background: `${sev[t.severity]}18`, borderRadius: 6, padding: '1px 7px' }}>{t.count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'flex', gap: 10 }}>
        {[{ icon: Globe, label: 'Targets', value: '48' }, { icon: ShieldCheck, label: 'Protected', value: '99.9%' }, { icon: Zap, label: 'Avg. Scan', value: '2.4s' }].map(({ icon: Icon, label, value }) => (
          <div key={label} style={{ flex: 1, background: card, border: `1px solid ${bdr}`, borderRadius: 12, padding: '11px 13px' }}>
            <Icon size={13} color={dim} />
            <p style={{ fontSize: 15, fontWeight: 700, color: txt, margin: '5px 0 1px', letterSpacing: '-0.02em' }}>{value}</p>
            <p style={{ fontSize: 10.5, color: dim, margin: 0 }}>{label}</p>
          </div>
        ))}
      </div>
    </>
  );
};

const Login = () => {
  const [identifier, setIdentifier]     = useState('');
  const [password, setPassword]         = useState('');
  const [error, setError]               = useState('');
  const [isLoading, setIsLoading]       = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [visible, setVisible]           = useState(false);
  const [showForgot, setShowForgot]     = useState(false);
  const navigate  = useNavigate();
  const { theme } = useContext(ThemeContext) || {};
  const isDark    = theme !== 'light';

  useEffect(() => {
    document.title = 'Sign In — LaunchGuard';
    requestAnimationFrame(() => setVisible(true));
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!identifier || !password) { setError('Please enter your credentials'); return; }
    setIsLoading(true); setError('');
    try {
      const { data } = await apiJson('/login', { method: 'POST', json: true, credentials: 'include', body: { identifier, password } });
      saveSession({ username: data.username, userId: data.user_id, expiresInSeconds: data.expires_in, isAdmin: data.is_admin });
      navigate('/');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to connect to server');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <AuthLayout visible={visible} isDark={isDark} heroContent={<HeroContent isDark={isDark} />}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 44 }}>
          <div style={{ width: 34, height: 34, borderRadius: 9, background: 'linear-gradient(135deg, #6366f1, #4f46e5)', boxShadow: '0 0 18px rgba(99,102,241,0.32)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Shield size={17} color="white" />
          </div>
          <span style={{ fontSize: 14.5, fontWeight: 700, color: 'var(--color-text)', letterSpacing: '-0.02em' }}>LaunchGuard</span>
        </div>

        <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--color-text)', letterSpacing: '-0.03em', margin: '0 0 6px' }}>Welcome back</h1>
        <p style={{ fontSize: 13.5, color: 'var(--color-text-muted)', margin: '0 0 28px', lineHeight: 1.5 }}>Sign in to your security dashboard</p>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }} noValidate>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <label htmlFor="identifier" style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-muted)' }}>Username or email</label>
            <div style={{ position: 'relative' }}>
              <AtSign size={14} style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)', pointerEvents: 'none' }} />
              <input id="identifier" type="text" autoComplete="username" value={identifier}
                onChange={e => setIdentifier(e.target.value)} placeholder="you@example.com"
                className="input" style={{ paddingLeft: '2.1rem' }} />
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <label htmlFor="password" style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-muted)' }}>Password</label>
              <button type="button" onClick={() => setShowForgot(true)}
                style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-primary)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
                Forgot password?
              </button>
            </div>
            <div style={{ position: 'relative' }}>
              <Lock size={14} style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)', pointerEvents: 'none' }} />
              <input id="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password"
                value={password} onChange={e => setPassword(e.target.value)} placeholder="Enter your password"
                className="input" style={{ paddingLeft: '2.1rem', paddingRight: '2.4rem' }} />
              <button type="button" onClick={() => setShowPassword(v => !v)}
                style={{ position: 'absolute', right: 11, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'flex' }}
                aria-label={showPassword ? 'Hide password' : 'Show password'}>
                {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          {error && (
            <div role="alert" style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '9px 11px', borderRadius: 9, background: 'var(--color-danger-dim)', border: '1px solid rgba(239,68,68,0.2)', color: 'var(--color-danger)', fontSize: 13 }}>
              <AlertTriangle size={13} style={{ flexShrink: 0 }} />{error}
            </div>
          )}

          <button type="submit" disabled={isLoading} className="btn-primary w-full justify-center"
            style={{ marginTop: 2, padding: '10px 0', fontSize: 14, opacity: isLoading ? 0.75 : 1 }}>
            {isLoading ? <><Spinner size="sm" /> Signing in…</> : <>Sign in <ArrowRight size={14} /></>}
          </button>
        </form>

        <p style={{ fontSize: 13, textAlign: 'center', marginTop: 24, color: 'var(--color-text-dim)' }}>
          Don't have an account?{' '}
          <button type="button" onClick={() => navigate('/register')}
            style={{ fontWeight: 600, color: 'var(--color-primary)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
            Create one
          </button>
        </p>
        <p style={{ fontSize: 11, color: 'var(--color-text-dim)', textAlign: 'center', marginTop: 32 }}>
          Protected by LaunchGuard · End-to-end encrypted
        </p>
      </AuthLayout>

      {showForgot && <ForgotPasswordModal onClose={() => setShowForgot(false)} />}
    </>
  );
};

export default Login;
