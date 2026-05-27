import React, { useState, useEffect, useContext } from 'react';
import { Shield, Lock, User, Mail, AlertTriangle, Eye, EyeOff, ArrowRight, CheckCircle, ShieldCheck, Zap, BarChart2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiJson, ApiError } from '../lib/api';
import { ThemeContext } from '../hooks/useTheme';
import { AuthLayout } from './Login';
import Spinner from './Spinner';

const features = [
  { icon: ShieldCheck, title: 'Automated scanning',    desc: 'Run OWASP-grade scans on any target, on demand or on a schedule.' },
  { icon: Zap,         title: 'Instant alerts',        desc: 'Get notified the moment a new vulnerability is discovered.' },
  { icon: BarChart2,   title: 'Actionable reports',    desc: 'Export detailed PDF reports with severity ratings and remediation steps.' },
  { icon: Shield,      title: 'Continuous protection', desc: 'Uptime monitoring and exposure tracking, 24/7.' },
];

const RegisterHero = ({ isDark }) => {
  const txt  = isDark ? 'rgba(255,255,255,0.88)' : 'rgba(10,10,20,0.88)';
  const dim  = isDark ? 'rgba(255,255,255,0.38)' : 'rgba(10,10,20,0.38)';
  const card = isDark ? 'rgba(255,255,255,0.05)' : 'rgba(10,10,20,0.04)';
  const bdr  = isDark ? 'rgba(255,255,255,0.09)' : 'rgba(10,10,20,0.09)';
  const iconBg = isDark ? 'rgba(99,102,241,0.15)' : 'rgba(99,102,241,0.1)';

  return (
    <>
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(99,102,241,0.14)', border: '1px solid rgba(99,102,241,0.28)', borderRadius: 100, padding: '3px 11px', marginBottom: 16 }}>
          <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#6366f1', boxShadow: '0 0 6px #6366f1' }} />
          <span style={{ fontSize: 10.5, fontWeight: 600, color: '#a5b4fc', letterSpacing: '0.07em', textTransform: 'uppercase' }}>Free to get started</span>
        </div>
        <h2 style={{ fontSize: 28, fontWeight: 700, lineHeight: 1.22, color: txt, letterSpacing: '-0.03em', margin: '0 0 10px' }}>
          Everything you need to<br /><span style={{ color: '#6366f1' }}>ship securely.</span>
        </h2>
        <p style={{ fontSize: 13, color: dim, lineHeight: 1.65, maxWidth: 340, margin: 0 }}>
          LaunchGuard gives your team a complete security toolkit — from discovery to remediation.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {features.map(({ icon: Icon, title, desc }) => (
          <div key={title} style={{ display: 'flex', alignItems: 'flex-start', gap: 14, background: card, border: `1px solid ${bdr}`, borderRadius: 13, padding: '14px 16px' }}>
            <div style={{ width: 34, height: 34, borderRadius: 9, background: iconBg, border: '1px solid rgba(99,102,241,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
              <Icon size={15} color="#6366f1" />
            </div>
            <div>
              <p style={{ fontSize: 13, fontWeight: 600, color: txt, margin: '0 0 3px' }}>{title}</p>
              <p style={{ fontSize: 12, color: dim, margin: 0, lineHeight: 1.55 }}>{desc}</p>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', background: card, border: `1px solid ${bdr}`, borderRadius: 12 }}>
        <CheckCircle size={15} color="#22c55e" style={{ flexShrink: 0 }} />
        <p style={{ fontSize: 12, color: dim, margin: 0 }}>No credit card required · Free plan available · Cancel anytime</p>
      </div>
    </>
  );
};

const InputField = ({ id, name, label, type = 'text', icon: Icon, value, onChange, error, placeholder, rightEl }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
    <label htmlFor={id} style={{ fontSize: 12, fontWeight: 600, color: 'var(--color-text-muted)' }}>{label}</label>
    <div style={{ position: 'relative' }}>
      <Icon size={14} style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)', pointerEvents: 'none' }} />
      <input
        id={id} name={name} type={type} value={value} onChange={onChange} placeholder={placeholder}
        autoComplete={id} className="input"
        style={{ paddingLeft: '2.1rem', paddingRight: rightEl ? '2.4rem' : undefined, borderColor: error ? 'var(--color-danger)' : undefined }}
        aria-invalid={!!error} aria-describedby={error ? `${id}-err` : undefined}
      />
      {rightEl}
    </div>
    {error && <p id={`${id}-err`} role="alert" style={{ fontSize: 11.5, color: 'var(--color-danger)', margin: 0 }}>{error}</p>}
  </div>
);

const Register = () => {
  const [formData, setFormData]         = useState({ username: '', email: '', password: '', confirmPassword: '' });
  const [errors, setErrors]             = useState({});
  const [isLoading, setIsLoading]       = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [success, setSuccess]           = useState(false);
  const [visible, setVisible]           = useState(false);
  const navigate  = useNavigate();
  const { theme } = useContext(ThemeContext) || {};
  const isDark    = theme !== 'light';

  useEffect(() => {
    document.title = 'Create Account — LaunchGuard';
    requestAnimationFrame(() => setVisible(true));
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(p => ({ ...p, [name]: value }));
    if (errors[name]) setErrors(p => ({ ...p, [name]: '' }));
  };

  const validate = () => {
    const e = {};
    if (!formData.username.trim())                              e.username = 'Username is required';
    else if (formData.username.length < 4)                     e.username = 'At least 4 characters';
    if (!formData.email.trim())                                e.email = 'Email is required';
    else if (!/\S+@\S+\.\S+/.test(formData.email))            e.email = 'Invalid email address';
    if (!formData.password)                                    e.password = 'Password is required';
    else if (formData.password.length < 8)                     e.password = 'At least 8 characters';
    else if (!/[a-z]/.test(formData.password))                 e.password = 'Include a lowercase letter';
    else if (!/[A-Z]/.test(formData.password))                 e.password = 'Include an uppercase letter';
    else if (!/[0-9]/.test(formData.password))                 e.password = 'Include a number';
    if (formData.password !== formData.confirmPassword)        e.confirmPassword = 'Passwords do not match';
    return e;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const errs = validate();
    if (Object.keys(errs).length) { setErrors(errs); return; }
    setIsLoading(true);
    try {
      await apiJson('/register', { method: 'POST', json: true, body: { username: formData.username, email: formData.email, password: formData.password } });
      setSuccess(true);
    } catch (err) {
      setErrors({ form: err instanceof ApiError ? err.message : 'Failed to connect to server' });
    } finally {
      setIsLoading(false);
    }
  };

  const eyeBtn = (
    <button type="button" onClick={() => setShowPassword(v => !v)}
      style={{ position: 'absolute', right: 11, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'flex' }}
      aria-label={showPassword ? 'Hide password' : 'Show password'}>
      {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
    </button>
  );

  return (
    <AuthLayout visible={visible} isDark={isDark} heroContent={<RegisterHero isDark={isDark} />}>
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 36 }}>
        <div style={{ width: 34, height: 34, borderRadius: 9, background: 'linear-gradient(135deg, #6366f1, #4f46e5)', boxShadow: '0 0 18px rgba(99,102,241,0.32)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <Shield size={17} color="white" />
        </div>
        <span style={{ fontSize: 14.5, fontWeight: 700, color: 'var(--color-text)', letterSpacing: '-0.02em' }}>LaunchGuard</span>
      </div>

      {success ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14, padding: '24px 0', textAlign: 'center' }}>
          <div style={{ width: 52, height: 52, borderRadius: '50%', background: 'var(--color-secure-dim)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Mail size={22} style={{ color: 'var(--color-secure)' }} />
          </div>
          <div>
            <p style={{ fontSize: 15, fontWeight: 700, color: 'var(--color-text)', margin: '0 0 6px' }}>Account created!</p>
            <p style={{ fontSize: 13, color: 'var(--color-text-muted)', margin: 0, lineHeight: 1.6 }}>
              We sent a verification link to <strong style={{ color: 'var(--color-text)' }}>{formData.email}</strong>. Click it to activate your account.
            </p>
          </div>
          <button onClick={() => navigate('/login')} className="btn-primary justify-center" style={{ width: '100%', padding: '10px 0', fontSize: 14, marginTop: 4 }}>
            Go to sign in <ArrowRight size={14} />
          </button>
        </div>
      ) : (
        <>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-text)', letterSpacing: '-0.03em', margin: '0 0 5px' }}>Create your account</h1>
          <p style={{ fontSize: 13.5, color: 'var(--color-text-muted)', margin: '0 0 24px', lineHeight: 1.5 }}>Start securing your products today</p>

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 12 }} noValidate>
            <InputField id="username" name="username" label="Username" icon={User}
              value={formData.username} onChange={handleChange} error={errors.username} placeholder="Choose a username" />
            <InputField id="email" name="email" label="Email" type="email" icon={Mail}
              value={formData.email} onChange={handleChange} error={errors.email} placeholder="you@example.com" />
            <InputField id="password" name="password" label="Password" type={showPassword ? 'text' : 'password'} icon={Lock}
              value={formData.password} onChange={handleChange} error={errors.password} placeholder="8+ chars, Aa, 0-9" rightEl={eyeBtn} />
            <InputField id="confirmPassword" name="confirmPassword" label="Confirm password" type={showPassword ? 'text' : 'password'} icon={Lock}
              value={formData.confirmPassword} onChange={handleChange} error={errors.confirmPassword} placeholder="Repeat password" />

            {errors.form && (
              <div role="alert" style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '9px 11px', borderRadius: 9, background: 'var(--color-danger-dim)', border: '1px solid rgba(239,68,68,0.2)', color: 'var(--color-danger)', fontSize: 13 }}>
                <AlertTriangle size={13} style={{ flexShrink: 0 }} />{errors.form}
              </div>
            )}

            <button type="submit" disabled={isLoading} className="btn-primary w-full justify-center"
              style={{ marginTop: 4, padding: '10px 0', fontSize: 14, opacity: isLoading ? 0.75 : 1 }}>
              {isLoading ? <><Spinner size="sm" /> Creating account…</> : <>Create account <ArrowRight size={14} /></>}
            </button>
          </form>

          <p style={{ fontSize: 13, textAlign: 'center', marginTop: 22, color: 'var(--color-text-dim)' }}>
            Already have an account?{' '}
            <button type="button" onClick={() => navigate('/login')}
              style={{ fontWeight: 600, color: 'var(--color-primary)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
              Sign in
            </button>
          </p>
          <p style={{ fontSize: 11, color: 'var(--color-text-dim)', textAlign: 'center', marginTop: 28 }}>
            By creating an account you agree to our Terms of Service
          </p>
        </>
      )}
    </AuthLayout>
  );
};

export default Register;
