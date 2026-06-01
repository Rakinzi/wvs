import React, { useEffect } from 'react';
import { ArrowLeft } from 'lucide-react';

const T = {
  bg:      'var(--color-bg)',
  surface: 'var(--color-surface)',
  card:    'var(--color-card)',
  border:  'var(--color-border)',
  borderBright: 'var(--color-border-bright)',
  text:    'var(--color-text)',
  muted:   'var(--color-text-muted)',
  dim:     'var(--color-text-dim)',
  primary: 'var(--color-primary)',
  info:    'var(--color-info)',
};

const LAST_UPDATED = 'June 1, 2026';

const Section = ({ id, title, children }) => (
  <section id={id} style={{ marginBottom: 48 }}>
    <h2 style={{
      fontFamily: "'Syne', system-ui, sans-serif",
      fontSize: 18, fontWeight: 700, color: T.text,
      letterSpacing: '-0.02em', margin: '0 0 16px',
      paddingLeft: 12, borderLeft: `2px solid ${T.info}`,
    }}>{title}</h2>
    <div style={{ color: T.muted, fontSize: 14, lineHeight: 1.8 }}>
      {children}
    </div>
  </section>
);

const P = ({ children, style }) => (
  <p style={{ margin: '0 0 14px', ...style }}>{children}</p>
);

const Ul = ({ items }) => (
  <ul style={{ margin: '0 0 14px', paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 6 }}>
    {items.map((item, i) => <li key={i}>{item}</li>)}
  </ul>
);

const DataTable = ({ rows }) => (
  <div style={{ border: `1px solid ${T.border}`, marginBottom: 16, overflowX: 'auto' }}>
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
      <thead>
        <tr style={{ background: T.surface }}>
          {['Category', 'Examples', 'Purpose'].map(h => (
            <th key={h} style={{ padding: '10px 14px', textAlign: 'left', color: T.dim, fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', borderBottom: `1px solid ${T.border}` }}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map(([cat, ex, purpose], i) => (
          <tr key={i} style={{ borderBottom: i < rows.length - 1 ? `1px solid ${T.border}` : 'none' }}>
            <td style={{ padding: '10px 14px', color: T.text, fontWeight: 600 }}>{cat}</td>
            <td style={{ padding: '10px 14px', color: T.muted, fontFamily: "'IBM Plex Mono', monospace", fontSize: 12 }}>{ex}</td>
            <td style={{ padding: '10px 14px', color: T.muted }}>{purpose}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

const TOC = [
  ['overview',    'Overview'],
  ['collection',  'Information We Collect'],
  ['usage',       'How We Use Your Information'],
  ['sharing',     'How We Share Your Information'],
  ['retention',   'Data Retention'],
  ['security',    'Security'],
  ['rights',      'Your Rights'],
  ['cookies',     'Cookies and Tracking'],
  ['third-party', 'Third-Party Links'],
  ['children',    'Children\'s Privacy'],
  ['transfers',   'International Transfers'],
  ['changes',     'Changes to This Policy'],
  ['contact',     'Contact Us'],
];

const PrivacyPolicy = ({ navigateTo }) => {
  useEffect(() => { document.title = 'Privacy Policy — LaunchGuard'; }, []);

  return (
    <div style={{ background: T.bg, color: T.text, minHeight: '100vh', fontFamily: "'Inter', system-ui, sans-serif" }}>

      {/* Header */}
      <div style={{ borderBottom: `1px solid ${T.border}`, padding: '16px 24px', display: 'flex', alignItems: 'center', gap: 16, background: T.surface }}>
        <button onClick={() => navigateTo('landing')}
          style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: T.muted, background: 'none', border: `1px solid ${T.border}`, padding: '6px 12px', borderRadius: 6, cursor: 'pointer', fontFamily: 'inherit' }}>
          <ArrowLeft size={12} /> Back
        </button>
        <div style={{ borderLeft: `2px solid ${T.info}`, paddingLeft: 12 }}>
          <h1 style={{ fontFamily: "'Syne', system-ui, sans-serif", fontSize: 15, fontWeight: 700, margin: 0, letterSpacing: '-0.02em', color: T.text }}>Privacy Policy</h1>
          <p style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, color: T.dim, margin: '2px 0 0' }}>Last updated: {LAST_UPDATED}</p>
        </div>
      </div>

      <div style={{ maxWidth: 860, margin: '0 auto', padding: '48px 24px 80px', display: 'grid', gridTemplateColumns: '200px 1fr', gap: 48, alignItems: 'start' }}>

        {/* Sticky TOC */}
        <nav style={{ position: 'sticky', top: 24 }}>
          <p style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 10, fontWeight: 700, color: T.dim, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 12 }}>Contents</p>
          {TOC.map(([id, label]) => (
            <a key={id} href={`#${id}`}
              style={{ display: 'block', fontSize: 12, color: T.muted, textDecoration: 'none', padding: '4px 0', borderBottom: `1px solid ${T.border}`, lineHeight: 1.5, transition: 'color 100ms' }}
              onMouseEnter={e => e.target.style.color = T.info}
              onMouseLeave={e => e.target.style.color = T.muted}>
              {label}
            </a>
          ))}
        </nav>

        {/* Body */}
        <main>

          <Section id="overview" title="Overview">
            <P>LaunchGuard ("we," "us," "our") is committed to protecting your privacy. This Privacy Policy explains what information we collect, how we use it, and your rights regarding your data when you use our web application security scanning platform ("Service").</P>
            <P>This policy applies to all users of the Service and is incorporated by reference into our Terms of Service. By using the Service, you consent to the data practices described here.</P>
          </Section>

          <Section id="collection" title="1. Information We Collect">
            <P>We collect information in three ways: information you provide directly, information collected automatically, and information derived from your use of the Service.</P>
            <DataTable rows={[
              ['Account data',   'Username, email address, password hash', 'Account creation and authentication'],
              ['Profile data',   'Email verification status', 'Service access control'],
              ['Scan targets',   'URLs and domains you submit for scanning', 'Performing scans on your behalf'],
              ['Scan results',   'Vulnerability findings, scores, verdicts', 'Displaying reports, enabling rescan comparison'],
              ['Usage data',     'Pages visited, features used, timestamps', 'Service improvement, abuse detection'],
              ['Log data',       'IP address, browser type, OS, request logs', 'Security, debugging, fraud prevention'],
              ['Session data',   'Session tokens (stored in browser session storage)', 'Maintaining your logged-in state'],
            ]} />
            <P>We do not collect payment card numbers directly. If payment is processed, it is handled by a PCI-DSS-compliant third-party processor and we receive only transaction metadata (e.g., plan type, renewal date).</P>
          </Section>

          <Section id="usage" title="2. How We Use Your Information">
            <P>We use the information we collect to:</P>
            <Ul items={[
              'Provide, operate, and maintain the Service',
              'Process and display scan results to you',
              'Send transactional emails (account verification, password reset, scan completion notifications)',
              'Detect, investigate, and prevent unauthorized access, fraud, and abuse',
              'Improve the Service, including analyzing usage patterns',
              'Comply with legal obligations',
              'Enforce our Terms of Service',
            ]} />
            <P>We do not use your scan results or target URLs to train machine-learning models, sell data to third parties, or share data for advertising purposes.</P>
          </Section>

          <Section id="sharing" title="3. How We Share Your Information">
            <P>We do not sell your personal data. We may share data only in the following circumstances:</P>
            <Ul items={[
              'Service providers: hosting, email delivery, payment processing — bound by confidentiality agreements and permitted to use data only to provide services to us',
              'Legal requirements: when required by law, court order, or governmental authority',
              'Safety: when we believe disclosure is necessary to protect the rights, property, or safety of LaunchGuard, our users, or the public',
              'Business transfers: in connection with a merger, acquisition, or sale of assets, provided the acquiring party agrees to this Privacy Policy',
            ]} />
          </Section>

          <Section id="retention" title="4. Data Retention">
            <P>We retain your data for as long as your account is active or as needed to provide the Service. Specific retention periods:</P>
            <Ul items={[
              'Account data: retained until you delete your account',
              'Scan results and reports: retained until you delete them or delete your account',
              'Server logs: retained for up to 90 days for security and debugging purposes',
              'Deleted account data: purged within 30 days of account deletion request, except where retention is required by law',
            ]} />
          </Section>

          <Section id="security" title="5. Security">
            <P>We implement reasonable technical and organizational security measures to protect your information, including:</P>
            <Ul items={[
              'Passwords stored as bcrypt hashes — never in plaintext',
              'HTTPS/TLS encryption for all data in transit',
              'Session tokens with server-side invalidation on logout',
              'Access controls limiting employee access to user data',
            ]} />
            <P>No method of transmission over the internet or electronic storage is 100% secure. We cannot guarantee absolute security but will notify you promptly of any breach affecting your personal data as required by applicable law.</P>
          </Section>

          <Section id="rights" title="6. Your Rights">
            <P>Depending on your jurisdiction, you may have the following rights regarding your personal data:</P>
            <Ul items={[
              'Access: request a copy of the personal data we hold about you',
              'Correction: request that we correct inaccurate or incomplete data',
              'Deletion: request deletion of your personal data ("right to be forgotten")',
              'Portability: receive your data in a structured, machine-readable format',
              'Objection: object to processing based on legitimate interests',
              'Restriction: request that we restrict processing of your data',
              'Withdraw consent: where processing is based on consent, withdraw at any time',
            ]} />
            <P>To exercise these rights, contact us at <span style={{ color: T.info, fontFamily: "'IBM Plex Mono', monospace" }}>privacy@launchguard.app</span>. We will respond within 30 days. We may require identity verification before processing requests.</P>
            <P>If you are in the EU/EEA, you also have the right to lodge a complaint with your local data protection authority.</P>
          </Section>

          <Section id="cookies" title="7. Cookies and Tracking">
            <P>LaunchGuard uses minimal tracking. Specifically:</P>
            <Ul items={[
              'Session storage: we use browser session storage (not cookies) for authentication tokens — this is cleared when you close the browser tab',
              'No third-party advertising cookies or tracking pixels',
              'No cross-site tracking',
            ]} />
            <P>If we introduce cookies in the future, we will update this policy and provide a consent mechanism where required by law.</P>
          </Section>

          <Section id="third-party" title="8. Third-Party Links">
            <P>The Service may contain links to third-party websites (e.g., scan target URLs in reports). This Privacy Policy does not apply to those sites. We encourage you to review the privacy policies of any third-party sites you visit.</P>
          </Section>

          <Section id="children" title="9. Children's Privacy">
            <P>The Service is not directed to children under 13 years of age. We do not knowingly collect personal information from children under 13. If you believe we have inadvertently collected such information, please contact us and we will promptly delete it.</P>
          </Section>

          <Section id="transfers" title="10. International Data Transfers">
            <P>Your information may be stored and processed in countries other than your own. By using the Service, you consent to the transfer of your information to countries that may have different data protection laws than your jurisdiction. Where required, we rely on appropriate transfer mechanisms (such as Standard Contractual Clauses) to protect your data.</P>
          </Section>

          <Section id="changes" title="11. Changes to This Policy">
            <P>We may update this Privacy Policy from time to time. We will notify you of material changes by updating the "Last Updated" date and, where appropriate, by sending an email notification. We encourage you to review this policy periodically.</P>
          </Section>

          <Section id="contact" title="12. Contact Us">
            <P>For privacy-related questions, data requests, or complaints, contact our privacy team:</P>
            <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderLeft: `2px solid ${T.info}`, padding: '12px 16px', fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, color: T.muted, lineHeight: 1.8 }}>
              LaunchGuard — Privacy<br />
              privacy@launchguard.app
            </div>
          </Section>

        </main>
      </div>
    </div>
  );
};

export default PrivacyPolicy;
