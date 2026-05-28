import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ArrowRight, CheckCircle, Eye, EyeOff, Lock } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { apiJson, ApiError } from '../lib/api';
import Spinner from './Spinner';

const ResetPassword = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = useMemo(() => searchParams.get('token') || '', [searchParams]);

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [success, setSuccess] = useState(false);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    document.title = 'Reset Password — LaunchGuard';
    requestAnimationFrame(() => setVisible(true));
  }, []);

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!token) {
      setError('This password reset link is invalid or incomplete');
      return;
    }

    if (password.length < 8) {
      setError('Your new password must be at least 8 characters long');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      await apiJson('/reset-password', {
        method: 'POST',
        json: true,
        body: { token, password },
      });
      setSuccess(true);
      setTimeout(() => navigate('/login'), 1800);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to connect to server');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4" style={{ background: 'var(--color-bg)' }}>
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
        <div
          className="rounded-2xl overflow-hidden"
          style={{
            background: 'var(--color-surface)',
            border: '1px solid var(--color-border)',
            boxShadow: '0 24px 64px rgba(0,0,0,0.5)',
          }}
        >
          <div
            className="px-8 pt-8 pb-6 flex flex-col items-center gap-3"
            style={{ borderBottom: '1px solid var(--color-border-subtle)' }}
          >
            <div
              className="w-14 h-14 rounded-2xl flex items-center justify-center"
              style={{ boxShadow: '0 0 32px rgba(45,212,191,0.28)' }}
            >
              <img src="/launchguard-icon.svg" alt="" className="w-14 h-14 rounded-2xl" />
            </div>
            <div className="text-center">
              <h1 className="text-xl font-semibold" style={{ color: 'var(--color-text)' }}>Choose a new password</h1>
              <p className="text-sm mt-0.5" style={{ color: 'var(--color-text-muted)' }}>LaunchGuard account recovery</p>
            </div>
          </div>

          <div className="px-8 py-7">
            {success ? (
              <div
                className="flex items-start gap-3 px-4 py-4 rounded-xl"
                style={{ background: 'var(--color-secure-dim)', border: '1px solid #22C55E30', color: 'var(--color-secure)' }}
              >
                <CheckCircle size={18} className="flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-sm">Password updated</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>Redirecting to sign in…</p>
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="flex flex-col gap-4" noValidate>
                <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                  Enter a new password for your account. This reset link can only be used once.
                </p>

                <div className="flex flex-col gap-1.5">
                  <label htmlFor="password" className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                    New password
                  </label>
                  <div className="relative">
                    <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--color-text-dim)' }} />
                    <input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                      placeholder="At least 8 characters"
                      className="input pl-9 pr-10 text-sm"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((value) => !value)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 cursor-pointer"
                      style={{ color: 'var(--color-text-dim)' }}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                </div>

                <div className="flex flex-col gap-1.5">
                  <label htmlFor="confirmPassword" className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                    Confirm password
                  </label>
                  <div className="relative">
                    <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--color-text-dim)' }} />
                    <input
                      id="confirmPassword"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      value={confirmPassword}
                      onChange={(event) => setConfirmPassword(event.target.value)}
                      placeholder="Repeat your new password"
                      className="input pl-9 text-sm"
                    />
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

                <button type="submit" disabled={isLoading}
                  className="btn-primary justify-center w-full mt-1"
                  style={{ opacity: isLoading ? 0.75 : 1 }}>
                  {isLoading ? <><Spinner size="sm" /> Updating password…</> : <>Reset password <ArrowRight size={15} /></>}
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;
