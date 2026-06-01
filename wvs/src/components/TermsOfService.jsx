import React, { useEffect } from 'react';
import { ArrowLeft, Shield } from 'lucide-react';

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
};

const LAST_UPDATED = 'June 1, 2026';

const Section = ({ id, title, children }) => (
  <section id={id} style={{ marginBottom: 48 }}>
    <h2 style={{
      fontFamily: "'Syne', system-ui, sans-serif",
      fontSize: 18, fontWeight: 700, color: T.text,
      letterSpacing: '-0.02em', margin: '0 0 16px',
      paddingLeft: 12, borderLeft: `2px solid ${T.primary}`,
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

const Warn = ({ children }) => (
  <div style={{
    background: 'rgba(255,79,79,0.06)', border: '1px solid rgba(255,79,79,0.2)',
    borderLeft: '3px solid #ff4f4f', padding: '12px 16px', borderRadius: 4,
    color: '#ff8080', fontSize: 13, lineHeight: 1.7, marginBottom: 16,
  }}>
    {children}
  </div>
);

const TOC = [
  ['acceptance',     'Acceptance of Terms'],
  ['description',    'Description of Service'],
  ['authorization',  'Authorized Use — Critical'],
  ['eligibility',    'Eligibility'],
  ['accounts',       'Accounts and Security'],
  ['prohibited',     'Prohibited Conduct'],
  ['ip',             'Intellectual Property'],
  ['disclaimers',    'Disclaimers'],
  ['liability',      'Limitation of Liability'],
  ['indemnification','Indemnification'],
  ['termination',    'Termination'],
  ['governing',      'Governing Law'],
  ['changes',        'Changes to Terms'],
  ['contact',        'Contact'],
];

const TermsOfService = ({ navigateTo }) => {
  useEffect(() => { document.title = 'Terms of Service — LaunchGuard'; }, []);

  return (
    <div style={{ background: T.bg, color: T.text, minHeight: '100vh', fontFamily: "'Inter', system-ui, sans-serif" }}>

      {/* Header */}
      <div style={{ borderBottom: `1px solid ${T.border}`, padding: '16px 24px', display: 'flex', alignItems: 'center', gap: 16, background: T.surface }}>
        <button onClick={() => navigateTo('landing')}
          style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: T.muted, background: 'none', border: `1px solid ${T.border}`, padding: '6px 12px', borderRadius: 6, cursor: 'pointer', fontFamily: 'inherit' }}>
          <ArrowLeft size={12} /> Back
        </button>
        <div style={{ borderLeft: `2px solid ${T.primary}`, paddingLeft: 12 }}>
          <h1 style={{ fontFamily: "'Syne', system-ui, sans-serif", fontSize: 15, fontWeight: 700, margin: 0, letterSpacing: '-0.02em', color: T.text }}>Terms of Service</h1>
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
              onMouseEnter={e => e.target.style.color = T.primary}
              onMouseLeave={e => e.target.style.color = T.muted}>
              {label}
            </a>
          ))}
        </nav>

        {/* Body */}
        <main>

          <Section id="acceptance" title="1. Acceptance of Terms">
            <P>By accessing or using LaunchGuard ("the Service," "we," "us," "our"), you agree to be bound by these Terms of Service ("Terms"). If you do not agree to these Terms, do not use the Service.</P>
            <P>These Terms constitute a legally binding agreement between you ("User," "you") and LaunchGuard. Your continued use of the Service after any modifications to these Terms constitutes acceptance of those changes.</P>
          </Section>

          <Section id="description" title="2. Description of Service">
            <P>LaunchGuard is a web-based security and product-readiness scanning platform that enables users to scan web applications for security vulnerabilities, UX issues, and launch-readiness factors. The Service includes, but is not limited to:</P>
            <Ul items={[
              'Automated vulnerability scanning (SQL injection, XSS, SSL/TLS, HTTP headers, etc.)',
              'OWASP Top 10 coverage reporting',
              'Product readiness and UX analysis',
              'Launch verdict engine',
              'Uptime monitoring',
              'PDF and SBOM report generation',
              'Scan history and comparison',
            ]} />
            <P>The Service is provided for informational and testing purposes only. Scan results do not constitute a guarantee that a scanned target is free from vulnerabilities.</P>
          </Section>

          <Section id="authorization" title="3. Authorized Use — Critical">
            <Warn>
              YOU MAY ONLY USE LAUNCHGUARD TO SCAN WEB APPLICATIONS, DOMAINS, AND SYSTEMS THAT YOU OWN, OPERATE, OR HAVE EXPLICIT WRITTEN PERMISSION FROM THE OWNER TO TEST. UNAUTHORIZED SCANNING OF THIRD-PARTY SYSTEMS MAY VIOLATE THE COMPUTER FRAUD AND ABUSE ACT (CFAA), THE UK COMPUTER MISUSE ACT, THE EU DIRECTIVE ON ATTACKS AGAINST INFORMATION SYSTEMS, AND EQUIVALENT LAWS IN YOUR JURISDICTION.
            </Warn>
            <P>By initiating any scan, you represent and warrant that:</P>
            <Ul items={[
              'You are the owner of the target URL/domain, or',
              'You have obtained explicit, written authorization from the target owner prior to scanning, and',
              'Your use of the Service complies with all applicable local, national, and international laws.',
            ]} />
            <P>LaunchGuard provides a domain ownership verification feature (Verified Targets). You are encouraged — but not required for all scan types — to verify ownership before running product-readiness scans.</P>
            <P>LaunchGuard assumes no liability for unauthorized scanning performed by users. Users who scan systems without authorization do so entirely at their own risk and may be subject to civil and criminal liability.</P>
          </Section>

          <Section id="eligibility" title="4. Eligibility">
            <P>You must be at least 18 years old and capable of forming a legally binding contract to use the Service. By using the Service, you represent that you meet these requirements. The Service is not directed to children under 13, and we do not knowingly collect information from children.</P>
          </Section>

          <Section id="accounts" title="5. Accounts and Security">
            <P>You are responsible for maintaining the confidentiality of your account credentials. You agree to:</P>
            <Ul items={[
              'Provide accurate registration information',
              'Keep your password secure and not share it with third parties',
              'Notify us immediately of any unauthorized use of your account',
              'Accept responsibility for all activity that occurs under your account',
            ]} />
            <P>We reserve the right to suspend or terminate accounts that we reasonably believe are being used in violation of these Terms.</P>
          </Section>

          <Section id="prohibited" title="6. Prohibited Conduct">
            <P>You agree not to:</P>
            <Ul items={[
              'Scan any system without authorization from its owner',
              'Use the Service to facilitate attacks, exploit vulnerabilities for malicious purposes, or cause harm to any system',
              'Attempt to circumvent, disable, or interfere with security features of the Service',
              'Use the Service to conduct denial-of-service attacks',
              'Share, resell, or sublicense the Service without our written consent',
              'Reverse engineer, decompile, or disassemble any part of the Service',
              'Use automated tools to access the Service beyond normal usage (e.g., scraping, mass API abuse)',
              'Impersonate any person or entity or misrepresent your affiliation',
              'Violate any applicable law, regulation, or third-party rights',
            ]} />
          </Section>

          <Section id="ip" title="7. Intellectual Property">
            <P>All content, software, trademarks, and other intellectual property associated with the Service are owned by or licensed to LaunchGuard. Nothing in these Terms grants you any right to use our intellectual property except as expressly permitted.</P>
            <P>You retain ownership of any data you submit to the Service, including target URLs and scan configuration. By using the Service, you grant us a limited license to process that data solely to provide the Service to you.</P>
          </Section>

          <Section id="disclaimers" title="8. Disclaimers">
            <P style={{ textTransform: 'uppercase', fontSize: 13 }}>THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.</P>
            <P>We do not warrant that:</P>
            <Ul items={[
              'The Service will be uninterrupted, error-free, or secure',
              'Scan results are complete, accurate, or up-to-date',
              'Vulnerabilities not detected by a scan do not exist',
              'The Service will meet your specific requirements',
            ]} />
            <P>Security scanning is inherently probabilistic. A clean scan result is not a security certification and does not guarantee the absence of vulnerabilities. Always complement automated scanning with manual security review and professional penetration testing before launch.</P>
          </Section>

          <Section id="liability" title="9. Limitation of Liability">
            <P style={{ textTransform: 'uppercase', fontSize: 13 }}>TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, LAUNCHGUARD AND ITS OFFICERS, DIRECTORS, EMPLOYEES, AND AGENTS SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES — INCLUDING LOST PROFITS, DATA LOSS, OR BUSINESS INTERRUPTION — ARISING FROM YOUR USE OF OR INABILITY TO USE THE SERVICE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.</P>
            <P>Our total cumulative liability to you for any claims arising under these Terms shall not exceed the greater of (a) the amount you paid us in the twelve months preceding the claim, or (b) USD $100.</P>
            <P>Some jurisdictions do not allow limitation of liability for certain types of damages. In such jurisdictions, our liability is limited to the maximum extent permitted by law.</P>
          </Section>

          <Section id="indemnification" title="10. Indemnification">
            <P>You agree to indemnify, defend, and hold harmless LaunchGuard and its officers, directors, employees, agents, and successors from and against any claims, liabilities, damages, losses, and expenses (including reasonable attorneys' fees) arising out of or related to:</P>
            <Ul items={[
              'Your use of the Service',
              'Your violation of these Terms',
              'Your scanning of any system without authorization',
              'Your violation of any applicable law or third-party right',
            ]} />
          </Section>

          <Section id="termination" title="11. Termination">
            <P>We may suspend or terminate your access to the Service at any time, with or without cause or notice, including if we reasonably believe you are violating these Terms. Upon termination, your right to use the Service ceases immediately.</P>
            <P>You may terminate your account at any time by contacting us. Sections 3 (Authorized Use), 7 (IP), 9 (Liability), 10 (Indemnification), and 12 (Governing Law) survive termination.</P>
          </Section>

          <Section id="governing" title="12. Governing Law and Dispute Resolution">
            <P>These Terms are governed by and construed in accordance with applicable law. Any dispute arising from these Terms or your use of the Service shall first be attempted to be resolved through good-faith negotiation. If unresolved, disputes shall be submitted to binding arbitration or the courts of competent jurisdiction in the applicable territory.</P>
          </Section>

          <Section id="changes" title="13. Changes to Terms">
            <P>We reserve the right to modify these Terms at any time. We will provide notice of material changes by updating the "Last Updated" date at the top of this page and, where appropriate, by notifying you via email. Continued use of the Service after changes take effect constitutes your acceptance of the revised Terms.</P>
          </Section>

          <Section id="contact" title="14. Contact">
            <P>If you have questions about these Terms, please contact us at:</P>
            <div style={{ background: T.surface, border: `1px solid ${T.border}`, borderLeft: `2px solid ${T.primary}`, padding: '12px 16px', fontFamily: "'IBM Plex Mono', monospace", fontSize: 12, color: T.muted, lineHeight: 1.8 }}>
              LaunchGuard<br />
              legal@launchguard.app
            </div>
          </Section>

        </main>
      </div>
    </div>
  );
};

export default TermsOfService;
