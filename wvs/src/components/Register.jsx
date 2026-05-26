import React, { useState, useEffect } from 'react';
import { Shield, Lock, User, Mail, AlertTriangle, Eye, EyeOff, CheckCircle, ArrowLeft, ArrowRight } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiJson, ApiError } from '../lib/api';
import Spinner from './Spinner';

const Field = ({ id, name, label, type = 'text', icon: Icon, value, onChange, error, placeholder, extra }) => (
  <div className="flex flex-col gap-1.5">
    <label htmlFor={id} className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
      {label}
    </label>
    <div className="relative">
      <Icon size={15} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--color-text-dim)' }} />
      <input
        id={id}
        name={name}
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoComplete={id}
        className="w-full pl-9 py-2.5 rounded-lg text-sm outline-none transition-all duration-150"
        style={{
          background: 'var(--color-card)',
          border: `1px solid ${error ? 'var(--color-danger)' : 'var(--color-border)'}`,
          color: 'var(--color-text)',
          paddingRight: extra ? '2.5rem' : '1rem',
        }}
        aria-invalid={!!error}
        aria-describedby={error ? `${id}-error` : undefined}
      />
      {extra}
    </div>
    {error && (
      <p id={`${id}-error`} className="text-xs" style={{ color: 'var(--color-danger)' }} role="alert">
        {error}
      </p>
    )}
  </div>
);

const Register = () => {
  const [formData, setFormData] = useState({ username: '', email: '', password: '', confirmPassword: '' });
  const [errors, setErrors]       = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [success, setSuccess]     = useState(false);
  const [visible, setVisible]     = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    document.title = 'Register — LaunchGuard';
    requestAnimationFrame(() => setVisible(true));
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(p => ({ ...p, [name]: value }));
    if (errors[name]) setErrors(p => ({ ...p, [name]: '' }));
  };

  const validate = () => {
    const e = {};
    if (!formData.username.trim())       e.username = 'Username is required';
    else if (formData.username.length < 4) e.username = 'At least 4 characters';
    if (!formData.email.trim())          e.email = 'Email is required';
    else if (!/\S+@\S+\.\S+/.test(formData.email)) e.email = 'Invalid email address';
    if (!formData.password)              e.password = 'Password is required';
    else if (formData.password.length < 8) e.password = 'At least 8 characters';
    if (formData.password !== formData.confirmPassword) e.confirmPassword = 'Passwords do not match';
    return e;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const errs = validate();
    if (Object.keys(errs).length) { setErrors(errs); return; }
    setIsLoading(true);
    try {
      await apiJson('/register', {
        method: 'POST',
        json: true,
        body: { username: formData.username, email: formData.email, password: formData.password },
      });
      setSuccess(true);
    } catch (err) {
      setErrors({ form: err instanceof ApiError ? err.message : 'Failed to connect to server' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4 py-8"
      style={{ background: 'var(--color-bg)' }}
    >
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
          style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', boxShadow: '0 24px 64px rgba(0,0,0,0.5)' }}
        >
          {/* Header */}
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
              <h1 className="text-xl font-semibold" style={{ color: 'var(--color-text)' }}>Create Account</h1>
              <p className="text-sm mt-0.5" style={{ color: 'var(--color-text-muted)' }}>Join LaunchGuard</p>
            </div>
          </div>

          <div className="px-8 py-7">
            {success ? (
              <div className="flex flex-col items-center gap-4 py-4 text-center">
                <div className="w-14 h-14 rounded-full flex items-center justify-center" style={{ background: 'var(--color-secure-dim)' }}>
                  <Mail size={24} style={{ color: 'var(--color-secure)' }} />
                </div>
                <div>
                  <p className="font-semibold text-sm" style={{ color: 'var(--color-text)' }}>Account created — check your email</p>
                  <p className="text-xs mt-1 leading-relaxed" style={{ color: 'var(--color-text-muted)' }}>
                    We sent a verification link to <strong>{formData.email}</strong>. Click it to activate your account, then log in.
                  </p>
                </div>
                <button onClick={() => navigate('/login')} className="text-sm font-medium cursor-pointer" style={{ color: 'var(--color-primary)' }}>
                  Go to login
                </button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="flex flex-col gap-4" noValidate>
                <Field
                  id="username" name="username" label="Username" icon={User}
                  value={formData.username} onChange={handleChange} error={errors.username}
                  placeholder="Choose a username"
                />
                <Field
                  id="email" name="email" label="Email" type="email" icon={Mail}
                  value={formData.email} onChange={handleChange} error={errors.email}
                  placeholder="your@email.com"
                />
                <Field
                  id="password" name="password" label="Password"
                  type={showPassword ? 'text' : 'password'} icon={Lock}
                  value={formData.password} onChange={handleChange} error={errors.password}
                  placeholder="Min. 8 characters"
                  extra={
                    <button
                      type="button"
                      onClick={() => setShowPassword(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 cursor-pointer"
                      style={{ color: 'var(--color-text-dim)' }}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  }
                />
                <Field
                  id="confirmPassword" name="confirmPassword" label="Confirm password"
                  type={showPassword ? 'text' : 'password'} icon={Lock}
                  value={formData.confirmPassword} onChange={handleChange} error={errors.confirmPassword}
                  placeholder="Repeat password"
                />

                {errors.form && (
                  <div
                    className="flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm"
                    role="alert"
                    style={{ background: 'var(--color-danger-dim)', color: 'var(--color-danger)', border: '1px solid #EF444430' }}
                  >
                    <AlertTriangle size={14} className="flex-shrink-0" />
                    {errors.form}
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isLoading}
                  className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg text-sm font-semibold text-white transition-all duration-150 cursor-pointer mt-1"
                  style={{ background: isLoading ? 'var(--color-primary-dim)' : 'var(--color-primary)', opacity: isLoading ? 0.7 : 1 }}
                >
                  {isLoading ? (
                    <><Spinner size="sm" /> Creating account…</>
                  ) : (
                    <>Create Account <ArrowRight size={15} /></>
                  )}
                </button>
              </form>
            )}

            <p className="text-sm text-center mt-5" style={{ color: 'var(--color-text-dim)' }}>
              Already have an account?{' '}
              <button
                type="button"
                onClick={() => navigate('/login')}
                className="font-medium cursor-pointer"
                style={{ color: 'var(--color-primary)' }}
              >
                <ArrowLeft size={12} className="inline mr-0.5" />
                Sign in
              </button>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;
