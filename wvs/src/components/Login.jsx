import React, { useState, useEffect } from 'react';
import { Shield, Lock, AlertTriangle, Eye, EyeOff, ArrowRight, Mail, X, CheckCircle, AtSign } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { saveSession } from '../lib/auth';
import { apiJson, ApiError } from '../lib/api';

const ForgotPasswordModal = ({ onClose }) => {
  const [email, setEmail]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [sent, setSent]         = useState(false);
  const [error, setError]       = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email) { setError('Please enter your email address'); return; }
    setLoading(true);
    setError('');
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.75)' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="w-full max-w-sm rounded-2xl overflow-hidden shadow-2xl"
        style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: '#3B82F620' }}>
              <Lock size={13} style={{ color: 'var(--color-primary)' }} />
            </div>
            <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Reset Password</h3>
          </div>
          <button onClick={onClose} className="cursor-pointer" style={{ color: 'var(--color-text-dim)' }} aria-label="Close">
            <X size={16} />
          </button>
        </div>

        <div className="px-6 py-5">
          {sent ? (
            <div className="flex flex-col items-center gap-3 py-3 text-center">
              <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: '#22C55E20' }}>
                <CheckCircle size={22} style={{ color: '#22C55E' }} />
              </div>
              <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>Check your inbox</p>
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                If an account exists for <strong style={{ color: 'var(--color-text)' }}>{email}</strong>, you'll receive a password reset link shortly.
              </p>
              <button onClick={onClose} className="mt-2 w-full py-2.5 rounded-lg text-sm font-semibold text-white cursor-pointer"
                style={{ background: 'var(--color-primary)' }}>
                Back to Sign In
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                Enter the email address associated with your account and we'll send you a reset link.
              </p>
              <div className="flex flex-col gap-1.5">
                <label htmlFor="reset-email" className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                  Email address
                </label>
                <div className="relative">
                  <Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--color-text-dim)' }} />
                  <input
                    id="reset-email"
                    type="email"
                    autoComplete="email"
                    value={email}
                    onChange={e => { setEmail(e.target.value); setError(''); }}
                    placeholder="you@example.com"
                    className="w-full pl-9 pr-4 py-2.5 rounded-lg text-sm outline-none"
                    style={{
                      background: 'var(--color-card)',
                      border: `1px solid ${error ? 'var(--color-danger)' : 'var(--color-border)'}`,
                      color: 'var(--color-text)',
                    }}
                  />
                </div>
                {error && <p className="text-xs" style={{ color: 'var(--color-danger)' }}>{error}</p>}
              </div>
              <div className="flex gap-2 pt-1">
                <button type="button" onClick={onClose}
                  className="flex-1 py-2.5 rounded-lg text-sm cursor-pointer"
                  style={{ background: 'var(--color-card)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
                  Cancel
                </button>
                <button type="submit" disabled={loading}
                  className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold text-white cursor-pointer"
                  style={{ background: 'var(--color-primary)', opacity: loading ? 0.7 : 1 }}>
                  {loading ? (
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : 'Send Reset Link'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
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
  const navigate = useNavigate();

  useEffect(() => {
    document.title = 'Sign In — LaunchGuard';
    requestAnimationFrame(() => setVisible(true));
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!identifier || !password) {
      setError('Please enter your username or email and password');
      return;
    }
    setIsLoading(true);
    setError('');
    try {
      const { data } = await apiJson('/login', {
        method: 'POST',
        json: true,
        credentials: 'include',
        body: { identifier, password },
      });
      saveSession({
        username: data.username,
        userId: data.user_id,
        expiresInSeconds: data.expires_in,
      });
      navigate('/');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to connect to server');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{ background: 'var(--color-bg)' }}
    >
      {/* Background grid */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            'linear-gradient(var(--color-border-subtle) 1px, transparent 1px), linear-gradient(90deg, var(--color-border-subtle) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
          opacity: 0.4,
        }}
      />

      <div
        className="relative w-full max-w-md transition-all duration-500"
        style={{ opacity: visible ? 1 : 0, transform: visible ? 'translateY(0)' : 'translateY(16px)' }}
      >
        {/* Card */}
        <div
          className="rounded-2xl overflow-hidden"
          style={{
            background: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            boxShadow: '0 24px 64px rgba(0,0,0,0.5)',
          }}
        >
          {/* Header band */}
          <div
            className="px-8 pt-8 pb-6 flex flex-col items-center gap-3"
            style={{ borderBottom: '1px solid var(--color-border-subtle)' }}
          >
            <div
              className="w-14 h-14 rounded-2xl flex items-center justify-center"
              style={{ background: 'var(--color-primary)', boxShadow: '0 0 32px #3B82F640' }}
            >
              <Shield size={26} className="text-white" />
            </div>
            <div className="text-center">
              <h1 className="text-xl font-semibold" style={{ color: 'var(--color-text)' }}>LaunchGuard</h1>
              <p className="text-sm mt-0.5" style={{ color: 'var(--color-text-muted)' }}>Security Intelligence Platform</p>
            </div>
          </div>

          {/* Form */}
          <div className="px-8 py-7">
            <h2 className="text-lg font-semibold mb-6" style={{ color: 'var(--color-text)' }}>Sign in to continue</h2>

            <form onSubmit={handleSubmit} className="flex flex-col gap-4" noValidate>
              {/* Username or Email */}
              <div className="flex flex-col gap-1.5">
                <label htmlFor="identifier" className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                  Username or Email
                </label>
                <div className="relative">
                  <AtSign size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--color-text-dim)' }} />
                  <input
                    id="identifier"
                    type="text"
                    autoComplete="username"
                    value={identifier}
                    onChange={(e) => setIdentifier(e.target.value)}
                    placeholder="Username or email address"
                    className="w-full pl-9 pr-4 py-2.5 rounded-lg text-sm outline-none transition-all duration-150"
                    style={{
                      background: 'var(--color-card)',
                      border: '1px solid var(--color-border)',
                      color: 'var(--color-text)',
                    }}
                  />
                </div>
              </div>

              {/* Password */}
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <label htmlFor="password" className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                    Password
                  </label>
                  <button type="button" onClick={() => setShowForgot(true)}
                    className="text-xs cursor-pointer transition-colors duration-150"
                    style={{ color: 'var(--color-primary)' }}>
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--color-text-dim)' }} />
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password"
                    className="w-full pl-9 pr-10 py-2.5 rounded-lg text-sm outline-none transition-all duration-150"
                    style={{
                      background: 'var(--color-card)',
                      border: '1px solid var(--color-border)',
                      color: 'var(--color-text)',
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 cursor-pointer"
                    style={{ color: 'var(--color-text-dim)' }}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              {error && (
                <div
                  className="flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm"
                  role="alert"
                  style={{ background: 'var(--color-danger-dim)', color: 'var(--color-danger)', border: '1px solid #EF444430' }}
                >
                  <AlertTriangle size={14} className="flex-shrink-0" />
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg text-sm font-semibold text-white transition-all duration-150 cursor-pointer mt-1"
                style={{
                  background: isLoading ? 'var(--color-primary-dim)' : 'var(--color-primary)',
                  opacity: isLoading ? 0.7 : 1,
                }}
              >
                {isLoading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Signing in…
                  </>
                ) : (
                  <>
                    Sign in
                    <ArrowRight size={15} />
                  </>
                )}
              </button>
            </form>

            <p className="text-sm text-center mt-5" style={{ color: 'var(--color-text-dim)' }}>
              Don't have an account?{' '}
              <button
                type="button"
                onClick={() => navigate('/register')}
                className="font-medium cursor-pointer"
                style={{ color: 'var(--color-primary)' }}
              >
                Register now
              </button>
            </p>
          </div>
        </div>
      </div>
    </div>

    {showForgot && <ForgotPasswordModal onClose={() => setShowForgot(false)} />}
    </>
  );
};

export default Login;
