import React, { useEffect, useState } from 'react';
import { CheckCircle, AlertTriangle, Mail } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { apiJson, ApiError } from '../lib/api';
import Spinner from './Spinner';

const VerifyEmail = () => {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const navigate = useNavigate();
  const [status, setStatus] = useState('verifying'); // verifying | success | error | no_token
  const [message, setMessage] = useState('');

  useEffect(() => {
    document.title = 'Verify Email — LaunchGuard';
    if (!token) { setStatus('no_token'); return; }

    apiJson('/verify-email/confirm', { method: 'POST', json: true, body: { token } })
      .then(() => setStatus('success'))
      .catch(err => {
        setMessage(err instanceof ApiError ? err.message : 'Verification failed');
        setStatus('error');
      });
  }, [token]);

  return (
    <div className="min-h-screen flex items-center justify-center px-4" style={{ background: 'var(--color-bg)' }}>
      <div className="w-full max-w-md rounded-2xl overflow-hidden"
        style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', boxShadow: '0 24px 64px rgba(0,0,0,0.5)' }}>

        <div className="px-8 pt-8 pb-6 flex flex-col items-center gap-3"
          style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
          <div className="w-14 h-14 rounded-2xl flex items-center justify-center"
            style={{ boxShadow: '0 0 32px rgba(45,212,191,0.28)' }}>
            <img src="/launchguard-icon.svg" alt="" className="w-14 h-14 rounded-2xl" />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-semibold" style={{ color: 'var(--color-text)' }}>Email Verification</h1>
            <p className="text-sm mt-0.5" style={{ color: 'var(--color-text-muted)' }}>LaunchGuard account</p>
          </div>
        </div>

        <div className="px-8 py-8 flex flex-col items-center gap-5 text-center">
          {status === 'verifying' && (
            <Spinner size="md" label="Verifying your email address…" />
          )}

          {status === 'success' && (
            <>
              <div className="w-16 h-16 rounded-full flex items-center justify-center" style={{ background: 'var(--color-secure-dim)' }}>
                <CheckCircle size={32} style={{ color: 'var(--color-secure)' }} />
              </div>
              <div>
                <p className="text-base font-semibold" style={{ color: 'var(--color-text)' }}>Email verified</p>
                <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>Your account is now fully active.</p>
              </div>
              <button onClick={() => navigate('/login')} className="btn-primary">
                Continue to login
              </button>
            </>
          )}

          {(status === 'error' || status === 'no_token') && (
            <>
              <div className="w-16 h-16 rounded-full flex items-center justify-center" style={{ background: 'var(--color-danger-dim)' }}>
                <AlertTriangle size={32} style={{ color: 'var(--color-danger)' }} />
              </div>
              <div>
                <p className="text-base font-semibold" style={{ color: 'var(--color-text)' }}>
                  {status === 'no_token' ? 'No verification token' : 'Verification failed'}
                </p>
                <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
                  {status === 'no_token'
                    ? 'Use the link from your verification email.'
                    : message || 'This link may have expired or already been used.'}
                </p>
              </div>
              <div className="flex flex-col items-center gap-2 w-full">
                <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>
                  Log in and go to Settings to resend the verification email.
                </p>
                <button onClick={() => navigate('/login')} className="btn-primary">
                  <Mail size={14} /> Go to login
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default VerifyEmail;
