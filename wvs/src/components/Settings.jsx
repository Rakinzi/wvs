import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon, ArrowLeft, Save,
  User, Lock, Mail, Shield,
  Bell, Check, AlertTriangle, Key, Info
} from 'lucide-react';
import { apiJson, ApiError } from '../lib/api';
import Spinner from './Spinner';

const Toggle = ({ checked, onChange, label, description }) => (
  <div className="flex items-center justify-between py-4" style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
    <div className="pr-4">
      <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>{label}</p>
      {description && <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>{description}</p>}
    </div>
    <button type="button" role="switch" aria-checked={checked} onClick={onChange}
      className="relative w-10 h-6 rounded-full transition-colors duration-200 cursor-pointer flex-shrink-0"
      style={{ background: checked ? 'var(--color-primary)' : 'var(--color-border)' }}>
      <span className="absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform duration-200"
        style={{ left: '2px', transform: checked ? 'translateX(16px)' : 'translateX(0)' }} />
    </button>
  </div>
);

const Field = ({ id, name, label, type = 'text', icon: Icon, value, onChange, placeholder, error }) => (
  <div className="flex flex-col gap-1.5">
    <label htmlFor={id} className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>{label}</label>
    <div className="relative">
      <Icon size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--color-text-dim)' }} />
      <input id={id} name={name} type={type} value={value} onChange={onChange} placeholder={placeholder}
        autoComplete={id}
        className="input pl-9"
        style={{ borderColor: error ? 'var(--color-danger)' : undefined }} />
    </div>
    {error && <p className="text-xs" style={{ color: 'var(--color-danger)' }}>{error}</p>}
  </div>
);

const TABS = [
  { id: 'profile',       label: 'Profile',        icon: User,   desc: 'Username and password' },
  { id: 'notifications', label: 'Notifications',  icon: Bell,   desc: 'Alert preferences' },
  { id: 'scanSettings',  label: 'Scan Settings',  icon: Shield, desc: 'Scanner configuration' },
];

const Settings = ({ navigateTo, userData }) => {
  const [tab, setTab]         = useState('profile');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError]     = useState(null);
  const [formData, setFormData] = useState({ name: '', email: '', currentPassword: '', newPassword: '', confirmPassword: '' });
  const [resendState, setResendState] = useState('idle');
  const [notifs, setNotifs]   = useState({ email: true, browser: true, vulnerabilities: true, newScans: false, reports: true });
  const [scan,  setScan]      = useState({ automaticScans: false, scanFrequency: 'weekly', deepScan: true, customPayloads: false });
  const [attempted, setAttempted] = useState(false);

  useEffect(() => {
    document.title = 'Settings — LaunchGuard';
    if (userData) setFormData(p => ({ ...p, name: userData.username || '' }));
  }, [userData]);

  const handleInput  = (e) => setFormData(p => ({ ...p, [e.target.name]: e.target.value }));
  const toggleNotif  = (k) => setNotifs(p => ({ ...p, [k]: !p[k] }));
  const toggleScan   = (k) => setScan(p => ({ ...p, [k]: !p[k] }));

  const resendVerification = async () => {
    setResendState('sending');
    try {
      await apiJson('/verify-email/resend', { method: 'POST', auth: true });
      setResendState('sent');
    } catch { setResendState('error'); }
  };

  const pwInvalid  = attempted && formData.newPassword && formData.newPassword.length < 8;
  const pwMismatch = attempted && formData.newPassword && formData.newPassword !== formData.confirmPassword;

  const save = async () => {
    setAttempted(true);
    if (tab !== 'profile') {
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
      return;
    }
    if (!formData.name) { setError('Username is required'); return; }
    if (pwInvalid || pwMismatch) { setError('Fix password errors first'); return; }

    setLoading(true); setError(null);
    try {
      const body = { username: formData.name };
      if (formData.newPassword) {
        body.current_password = formData.currentPassword;
        body.new_password = formData.newPassword;
      }
      await apiJson('/profile', { method: 'PATCH', body, auth: true });
      setSuccess(true);
      setFormData(p => ({ ...p, currentPassword: '', newPassword: '', confirmPassword: '' }));
      setAttempted(false);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save settings');
    } finally {
      setLoading(false);
    }
  };

  const activeTab = TABS.find(t => t.id === tab);

  return (
    <div className="min-h-screen" style={{ background: 'var(--color-bg)' }}>

      {/* Page header */}
      <div className="page-header px-6 lg:px-10 py-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button onClick={() => navigateTo('dashboard')} className="btn-secondary flex items-center gap-1.5 text-xs">
            <ArrowLeft size={13} /> Back
          </button>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: 'var(--color-primary-dim)' }}>
              <SettingsIcon size={15} style={{ color: 'var(--color-primary)' }} />
            </div>
            <div>
              <h1 className="text-base font-bold leading-tight" style={{ color: 'var(--color-text)' }}>Settings</h1>
              <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>{activeTab?.desc}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6">

        {success && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl mb-5"
            style={{ background: 'var(--color-secure-dim)', border: '1px solid rgba(34,197,94,0.2)', color: 'var(--color-secure)' }}>
            <Check size={14} /> Settings saved successfully
          </div>
        )}
        {error && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl mb-5"
            style={{ background: 'var(--color-danger-dim)', border: '1px solid rgba(239,68,68,0.2)', color: 'var(--color-danger)' }}>
            <AlertTriangle size={14} /> {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-6 items-start">

          {/* Left nav */}
          <div className="lg:sticky lg:top-20 card overflow-hidden">
            {TABS.map(({ id, label, icon: Icon, desc }) => (
              <button key={id} onClick={() => setTab(id)}
                className="w-full flex items-center gap-3 px-4 py-3.5 text-left cursor-pointer transition-all"
                style={{
                  background: tab === id ? 'var(--color-primary-dim)' : 'transparent',
                  borderLeft: `2px solid ${tab === id ? 'var(--color-primary)' : 'transparent'}`,
                }}>
                <div className="w-7 h-7 rounded-md flex items-center justify-center flex-shrink-0"
                  style={{ background: tab === id ? 'rgba(99,102,241,0.15)' : 'var(--color-surface)' }}>
                  <Icon size={13} style={{ color: tab === id ? 'var(--color-primary)' : 'var(--color-text-dim)' }} />
                </div>
                <div>
                  <p className="text-xs font-semibold" style={{ color: tab === id ? 'var(--color-text)' : 'var(--color-text-muted)' }}>{label}</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>{desc}</p>
                </div>
              </button>
            ))}
          </div>

          {/* Right panel */}
          <div className="card overflow-hidden">
            <div className="px-6 py-4 flex items-center gap-2" style={{ borderBottom: '1px solid var(--color-border)', background: 'var(--color-surface)' }}>
              {TABS.filter(t => t.id === tab).map(({ label, icon: Icon }) => (
                <React.Fragment key={label}>
                  <Icon size={15} style={{ color: 'var(--color-primary)' }} />
                  <h2 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>{label}</h2>
                </React.Fragment>
              ))}
            </div>

            <div className="p-6">

              {tab === 'profile' && (
                <div className="flex flex-col gap-6">
                  {userData && !userData.email_verified && (
                    <div className="flex items-center justify-between gap-3 px-4 py-3 rounded-xl"
                      style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)' }}>
                      <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--color-warn)' }}>
                        <AlertTriangle size={13} />
                        Email not verified. Check your inbox or resend the verification link.
                      </div>
                      <button onClick={resendVerification} disabled={resendState === 'sending' || resendState === 'sent'}
                        className="flex-shrink-0 text-xs font-semibold cursor-pointer disabled:opacity-60"
                        style={{ color: 'var(--color-warn)' }}>
                        {resendState === 'sending' ? 'Sending…' : resendState === 'sent' ? 'Sent' : 'Resend'}
                      </button>
                    </div>
                  )}
                  <div>
                    <p className="section-label mb-4">Profile Information</p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <Field id="name" name="name" label="Username" icon={User}
                        value={formData.name} onChange={handleInput} placeholder="Your username" />
                      <Field id="email" name="email" label="Email" type="email" icon={Mail}
                        value={formData.email} onChange={handleInput} placeholder="you@example.com" />
                    </div>
                  </div>

                  <div style={{ borderTop: '1px solid var(--color-border-subtle)', paddingTop: '1.5rem' }}>
                    <p className="section-label mb-4">Change Password</p>
                    <div className="flex flex-col gap-4">
                      <Field id="currentPassword" name="currentPassword" label="Current Password" type="password" icon={Key}
                        value={formData.currentPassword} onChange={handleInput} placeholder="••••••••" />
                      <Field id="newPassword" name="newPassword" label="New Password" type="password" icon={Lock}
                        value={formData.newPassword} onChange={handleInput} placeholder="Min. 8 characters"
                        error={pwInvalid ? 'At least 8 characters required' : undefined} />
                      <Field id="confirmPassword" name="confirmPassword" label="Confirm Password" type="password" icon={Lock}
                        value={formData.confirmPassword} onChange={handleInput} placeholder="Repeat new password"
                        error={pwMismatch ? 'Passwords do not match' : undefined} />
                    </div>
                  </div>
                </div>
              )}

              {tab === 'notifications' && (
                <div>
                  <p className="section-label">Notification Preferences</p>
                  <p className="text-xs mt-1 mb-5" style={{ color: 'var(--color-text-muted)' }}>Configure how you receive security alerts and scan updates.</p>
                  <Toggle checked={notifs.email}           onChange={() => toggleNotif('email')}           label="Email Notifications"   description="Receive notifications via email" />
                  <Toggle checked={notifs.browser}         onChange={() => toggleNotif('browser')}         label="Browser Notifications" description="Show browser push notifications" />
                  <Toggle checked={notifs.vulnerabilities} onChange={() => toggleNotif('vulnerabilities')} label="Vulnerability Alerts"  description="Notify when vulnerabilities are found" />
                  <Toggle checked={notifs.newScans}        onChange={() => toggleNotif('newScans')}        label="Scan Completion"       description="Notify when scans complete" />
                  <Toggle checked={notifs.reports}         onChange={() => toggleNotif('reports')}         label="Report Available"      description="Notify when new reports are ready" />
                </div>
              )}

              {tab === 'scanSettings' && (
                <div>
                  <p className="section-label">Scanner Configuration</p>
                  <p className="text-xs mt-1 mb-5" style={{ color: 'var(--color-text-muted)' }}>Configure how the scanner operates on your targets.</p>
                  <Toggle checked={scan.automaticScans} onChange={() => toggleScan('automaticScans')} label="Automatic Scans"     description="Schedule periodic scans of your sites" />
                  {scan.automaticScans && (
                    <div className="ml-4 my-3">
                      <label htmlFor="scanFreq" className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--color-text-muted)' }}>Frequency</label>
                      <select id="scanFreq" value={scan.scanFrequency}
                        onChange={(e) => setScan(p => ({ ...p, scanFrequency: e.target.value }))}
                        className="input text-xs cursor-pointer w-40">
                        <option value="daily">Daily</option>
                        <option value="weekly">Weekly</option>
                        <option value="monthly">Monthly</option>
                      </select>
                    </div>
                  )}
                  <Toggle checked={scan.deepScan}       onChange={() => toggleScan('deepScan')}       label="Deep Scanning"       description="More thorough scans — slower but more complete" />
                  <Toggle checked={scan.customPayloads} onChange={() => toggleScan('customPayloads')} label="Custom SQL Payloads" description="Test with payloads beyond the default set" />

                  <div className="mt-5 flex items-start gap-3 p-4 rounded-xl"
                    style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}>
                    <Info size={13} className="flex-shrink-0 mt-0.5" style={{ color: 'var(--color-info)' }} />
                    <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-muted)' }}>
                      Deep scanning performs more checks but takes longer. Custom SQL payloads let you extend beyond the default injection test set.
                    </p>
                  </div>
                </div>
              )}

              <div className="flex justify-end mt-6 pt-5" style={{ borderTop: '1px solid var(--color-border-subtle)' }}>
                <button type="button" onClick={save} disabled={loading} className="btn-primary" style={{ opacity: loading ? 0.75 : 1 }}>
                  {loading
                    ? <><Spinner size="sm" /> Saving…</>
                    : <><Save size={13} /> Save Settings</>}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
