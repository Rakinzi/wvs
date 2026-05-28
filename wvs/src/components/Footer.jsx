import React from 'react';

const T = {
  bg:          'var(--color-bg)',
  surface:     'var(--color-surface)',
  border:      'var(--color-border)',
  borderSubtle:'var(--color-border-subtle)',
  text:        'var(--color-text)',
  muted:       'var(--color-text-muted)',
  dim:         'var(--color-text-dim)',
  primary:     'var(--color-primary)',
};

const Footer = () => (
  <footer style={{ background: T.surface, borderTop: `1px solid ${T.borderSubtle}` }}>
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <img src="/launchguard-icon.svg" alt="" className="w-7 h-7 rounded-lg" style={{ boxShadow: '0 0 14px rgba(45,212,191,0.22)' }} />
          <span className="text-sm font-semibold" style={{ color: T.text }}>LaunchGuard</span>
        </div>

        <div className="flex items-center gap-6">
          {['About', 'Privacy Policy', 'Contact'].map(label => (
            <a key={label} href="#" className="text-xs transition-colors duration-150" style={{ color: T.dim }}
              onMouseEnter={e => e.currentTarget.style.color = T.muted}
              onMouseLeave={e => e.currentTarget.style.color = T.dim}>
              {label}
            </a>
          ))}
        </div>

        <p className="text-xs" style={{ color: T.dim }}>
          © {new Date().getFullYear()} LaunchGuard. All rights reserved.
        </p>
      </div>

      <div className="mt-5 pt-5 text-center" style={{ borderTop: `1px solid ${T.borderSubtle}` }}>
        <p className="text-xs" style={{ color: T.dim }}>
          LaunchGuard helps identify SQL injection, SSL vulnerabilities, and malicious content. Use responsibly on authorized targets only.
        </p>
      </div>
    </div>
  </footer>
);

export default Footer;
