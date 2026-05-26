import React, { useState, useEffect } from 'react';
import {
  FileText, Shield, ArrowLeft, Download,
  AlertTriangle, CheckCircle, AlertOctagon, Database, Lock,
  Info, RefreshCw, ChevronDown, ChevronUp, ExternalLink, Globe, Trash2, Package,
  Mail, ArrowRightLeft, Link2Off
} from 'lucide-react';
import { useScanReportData } from '../hooks/useScanReportData';
import { apiFetch, apiJson, ApiError } from '../lib/api';
import ConfirmDialog from './ConfirmDialog';

const T = {
  bg:          'var(--color-bg)',
  surface:     'var(--color-surface)',
  card:        'var(--color-card)',
  elev:        'var(--color-elevated)',
  border:      'var(--color-border)',
  borderSubtle:'var(--color-border-subtle)',
  borderBright:'var(--color-border-bright)',
  text:        'var(--color-text)',
  muted:       'var(--color-text-muted)',
  dim:         'var(--color-text-dim)',
  primary:     'var(--color-primary)',
  primaryDim:  'var(--color-primary-dim)',
  secure:      'var(--color-secure)',
  secureDim:   'var(--color-secure-dim)',
  danger:      'var(--color-danger)',
  dangerDim:   'var(--color-danger-dim)',
  warn:        'var(--color-warn)',
  warnDim:     'var(--color-warn-dim)',
  info:        'var(--color-info)',
  infoDim:     'var(--color-info-dim)',
  purple:      '#A78BFA',
  purpleDim:   '#2D1F4E',
};

const fmt = (d) => {
  const dt = new Date(d);
  return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    + ' · ' + dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const obfuscateEmail = (email) => String(email || '').replace('@', ' [at] ');

/* Collapsible section */
const Section = ({ id, label, subLabel, icon: Icon, iconColor, iconBg, expanded, onToggle, children }) => (
  <div className="rounded-xl overflow-hidden" style={{ border: `1px solid ${T.border}` }}>
    <button onClick={() => onToggle(id)}
      className="w-full flex items-center justify-between px-5 py-4 cursor-pointer transition-colors"
      style={{ background: T.surface }} aria-expanded={expanded}>
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: iconBg }}>
          <Icon size={16} style={{ color: iconColor }} />
        </div>
        <div className="text-left">
          <p className="text-sm font-semibold" style={{ color: T.text }}>{label}</p>
          {subLabel && <p className="text-xs mt-0.5" style={{ color: T.muted }}>{subLabel}</p>}
        </div>
      </div>
      {expanded ? <ChevronUp size={15} style={{ color: T.dim }} /> : <ChevronDown size={15} style={{ color: T.dim }} />}
    </button>
    {expanded && (
      <div className="px-5 py-4" style={{ borderTop: `1px solid ${T.borderSubtle}` }}>
        {children}
      </div>
    )}
  </div>
);

/* Finding card */
const FindingCard = ({ color, bg, icon: Icon, title, items = [] }) => (
  <div className="rounded-lg p-4" style={{ background: bg, border: `1px solid ${color}25` }}>
    <div className="flex items-start gap-3">
      <Icon size={14} className="flex-shrink-0 mt-0.5" style={{ color }} />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold" style={{ color }}>{title}</p>
        {items.map((item, i) => (
          <p key={i} className="text-xs mt-1 break-all font-mono" style={{ color: T.muted }}>{item}</p>
        ))}
      </div>
    </div>
  </div>
);

/* Recommendations */
const Recs = ({ items }) => (
  <div className="rounded-lg p-4 mt-3" style={{ background: T.infoDim, border: `1px solid ${T.info}25` }}>
    <p className="text-xs font-semibold mb-2 font-mono uppercase tracking-widest" style={{ color: T.info }}>Recommendations</p>
    <ul className="flex flex-col gap-1.5">
      {items.map((r, i) => (
        <li key={i} className="text-xs flex items-start gap-1.5" style={{ color: T.muted }}>
          <span style={{ color: T.info }}>→</span> {r}
        </li>
      ))}
    </ul>
  </div>
);

/* Clean state */
const CleanState = ({ icon: Icon, title, body }) => (
  <div className="flex flex-col items-center gap-3 py-8 text-center">
    <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: T.secureDim }}>
      <Icon size={22} style={{ color: T.secure }} />
    </div>
    <div>
      <p className="text-sm font-semibold" style={{ color: T.text }}>{title}</p>
      {body && <p className="text-xs mt-1" style={{ color: T.muted }}>{body}</p>}
    </div>
  </div>
);

/* Score ring (SVG) */
const ScoreRing = ({ score, color }) => {
  const r = 36, circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  return (
    <div className="relative w-24 h-24 flex items-center justify-center">
      <svg width="96" height="96" className="-rotate-90">
        <circle cx="48" cy="48" r={r} fill="none" stroke={T.border} strokeWidth="6" />
        <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" style={{ transition: 'stroke-dasharray 0.6s ease' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-bold" style={{ color }}>{score}</span>
        <span className="text-xs" style={{ color: T.dim }}>/100</span>
      </div>
    </div>
  );
};

/* ─────────────────────────────────────────────── */
const ScanReport = ({ scanId, navigateTo }) => {
  const [expanded, setExpanded] = useState({ sql: true, ssl: true, headers: true, wordpress: true, zap: true, malicious: true, xss: true, tech: true, exposure: true, dns: true, redirect: true, takeover: true });
  const { report, loading, error } = useScanReportData(scanId);
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState(null);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);

  useEffect(() => { document.title = 'Scan Report — LaunchGuard'; }, []);

  const toggle = (id) => setExpanded(p => ({ ...p, [id]: !p[id] }));

  const handleDownload = () => {
    const tzOffset = new Date().getTimezoneOffset();
    apiFetch(`/report/${scanId}?format=pdf&tz_offset=${tzOffset}`, { auth: true })
      .then(async (res) => {
        if (!res.ok) throw new ApiError('Download failed', res.status);
        return res.blob();
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = Object.assign(document.createElement('a'), { href: url, download: `scan_${scanId}.pdf` });
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(url);
      })
      .catch(console.error);
  };

  const handleSbomDownload = () => {
    apiJson(`/report/${scanId}?format=sbom`, { auth: true })
      .then(({ data }) => {
        const payload = JSON.stringify(data.sbom || {}, null, 2);
        const blob = new Blob([payload], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = Object.assign(document.createElement('a'), { href: url, download: `scan_${scanId}_sbom.json` });
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(url);
      })
      .catch(console.error);
  };

  const handleDelete = async () => {
    setShowDeleteDialog(false);
    try {
      setIsDeleting(true);
      setDeleteError(null);
      await apiJson(`/scans/${scanId}`, { method: 'DELETE', auth: true });
      navigateTo('dashboard');
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : 'Failed to delete report');
    } finally {
      setIsDeleting(false);
    }
  };

  if (loading) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: T.bg }}>
      <div className="flex flex-col items-center gap-4">
        <div className="w-14 h-14 rounded-2xl flex items-center justify-center" style={{ background: T.primaryDim }}>
          <RefreshCw size={24} className="animate-spin" style={{ color: T.primary }} />
        </div>
        <p className="text-sm" style={{ color: T.muted }}>Loading report…</p>
      </div>
    </div>
  );

  if (error || !report) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: T.bg }}>
      <div className="flex flex-col items-center gap-4">
        <div className="w-14 h-14 rounded-2xl flex items-center justify-center" style={{ background: T.dangerDim }}>
          <AlertTriangle size={24} style={{ color: T.danger }} />
        </div>
        <p className="text-sm font-medium" style={{ color: T.text }}>{error ? 'Error loading report' : 'Report not found'}</p>
        <p className="text-xs" style={{ color: T.muted }}>{error || `Report ${scanId} could not be found.`}</p>
        <button onClick={() => navigateTo('dashboard')}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium cursor-pointer text-white"
          style={{ background: T.primary }}>
          <ArrowLeft size={14} /> Back to Dashboard
        </button>
      </div>
    </div>
  );

  const meta      = report.meta || {};
  const bestPractices = report.best_practices || [];
  const findings  = report.findings || {};
  const sections  = report.sections || findings.sections || {};
  const summary   = report.summary  || findings.summary  || {};

  const hasSql       = findings.sqli && findings.sqli.length > 0;
  const hasSsl       = findings.ssl  && !findings.ssl.valid;
  const hdrIssues    = findings.headers?.issues || [];
  const wpIssues     = findings.wordpress?.issues || [];
  const zapIssues    = findings.zap?.issues || [];
  const isMal        = findings.malicious?.is_malicious;
  const xssIssues    = findings.xss?.issues || [];
  const hasXss       = xssIssues.some(i => i.type === 'Reflected XSS');
  const techIssues   = findings.tech?.issues || [];
  const actionableTechIssues = techIssues.filter(i => i.severity !== 'Info');
  const exposureIssues = findings.exposure?.issues || [];
  const exposureEmails = findings.exposure?.discovered_emails || [];
  const hasExposure  = exposureIssues.some(i => ['Critical','High'].includes(i.severity));
  const dnsIssues    = findings.dns?.issues || [];
  const redirIssues  = findings.redirect?.issues || [];
  const takeIssues   = findings.takeover?.issues || [];

  const totalIssues = summary.total_issues ??
    (
      (hasSql ? findings.sqli.length : 0) +
      hdrIssues.length +
      wpIssues.length +
      zapIssues.length +
      xssIssues.length +
      actionableTechIssues.length +
      exposureIssues.length +
      dnsIssues.length +
      redirIssues.length +
      takeIssues.length +
      (hasSsl ? 1 : 0) +
      (isMal ? 1 : 0)
    );

  const score = meta.security_score ?? (totalIssues === 0 ? 100 : Math.max(0, 100 - totalIssues * 20));
  const risk  = meta.risk_rating || (totalIssues > 5 || isMal ? 'Critical' : totalIssues > 3 ? 'High' : totalIssues > 0 ? 'Medium' : 'Low');
  const url   = meta.target_url || report.url || '';
  const ts    = meta.timestamp  || report.timestamp;

  const riskColor  = risk === 'Critical' ? T.danger : risk === 'High' ? T.warn : risk === 'Medium' ? T.warn : T.secure;
  const riskDim    = risk === 'Critical' ? T.dangerDim : risk === 'High' ? T.warnDim : risk === 'Medium' ? T.warnDim : T.secureDim;
  const scoreColor = score < 50 ? T.danger : score < 80 ? T.warn : T.secure;

  return (
    <div className="min-h-screen" style={{ background: T.bg }}>

      <ConfirmDialog
        open={showDeleteDialog}
        title="Delete Report"
        message="This scan record and its PDF will be permanently removed. This cannot be undone."
        confirmLabel="Delete"
        onConfirm={handleDelete}
        onCancel={() => setShowDeleteDialog(false)}
      />

      {/* Nav bar */}
      <div className="sticky top-0 z-20 px-6 lg:px-10 py-4 flex items-center justify-between"
        style={{ background: `${T.surface}E0`, backdropFilter: 'blur(12px)', borderBottom: `1px solid ${T.border}` }}>
        <button onClick={() => navigateTo('dashboard')}
          className="flex items-center gap-1.5 text-xs font-medium cursor-pointer px-3 py-1.5 rounded-lg"
          style={{ color: T.muted, background: T.card, border: `1px solid ${T.border}` }}>
          <ArrowLeft size={13} /> Dashboard
        </button>
        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 rounded-lg text-xs font-semibold font-mono" style={{ background: riskDim, color: riskColor }}>
            {risk} Risk
          </span>
          <button onClick={handleSbomDownload}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer"
            style={{ background: T.card, color: T.info, border: `1px solid ${T.border}` }}>
            <Package size={12} /> SBOM
          </button>
          <button onClick={() => setShowDeleteDialog(true)} disabled={isDeleting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer disabled:opacity-60"
            style={{ background: T.card, color: T.danger, border: `1px solid ${T.border}` }}>
            <Trash2 size={12} /> {isDeleting ? 'Deleting…' : 'Delete'}
          </button>
          <button onClick={handleDownload}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer"
            style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>
            <Download size={12} /> PDF
          </button>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6">
        {deleteError && (
          <div className="mb-4 rounded-xl px-4 py-3 text-xs flex items-center gap-2" style={{ background: T.dangerDim, color: T.danger, border: `1px solid ${T.danger}25` }}>
            <AlertTriangle size={14} /> {deleteError}
          </div>
        )}
        <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-6 items-start">

          {/* ── Left: sticky summary panel ── */}
          <div className="lg:sticky lg:top-24 flex flex-col gap-4">

            {/* Score card */}
            <div className="rounded-xl p-5 flex flex-col items-center gap-4" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <ScoreRing score={score} color={scoreColor} />
              <div className="text-center">
                <p className="text-xs font-mono uppercase tracking-widest mb-1" style={{ color: T.dim }}>Security Score</p>
                <span className="px-3 py-1 rounded-lg text-xs font-bold" style={{ background: riskDim, color: riskColor }}>
                  {risk} Risk
                </span>
              </div>
              <div className="w-full pt-2" style={{ borderTop: `1px solid ${T.borderSubtle}` }}>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>Issues found</span>
                  <span className="font-mono font-semibold" style={{ color: totalIssues > 0 ? T.danger : T.secure }}>{totalIssues}</span>
                </div>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>SQL Injection</span>
                  <span className="font-mono" style={{ color: hasSql ? T.danger : T.secure }}>{hasSql ? findings.sqli.length : '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>SSL Issues</span>
                  <span className="font-mono" style={{ color: hasSsl ? T.warn : T.secure }}>{hasSsl ? '1' : '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>Header Issues</span>
                  <span className="font-mono" style={{ color: hdrIssues.length > 0 ? T.info : T.secure }}>{hdrIssues.length || '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>WP Issues</span>
                  <span className="font-mono" style={{ color: wpIssues.length > 0 ? T.warn : T.secure }}>{wpIssues.length || '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>ZAP Alerts</span>
                  <span className="font-mono" style={{ color: zapIssues.length > 0 ? T.danger : T.secure }}>{zapIssues.length || '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>XSS Issues</span>
                  <span className="font-mono" style={{ color: xssIssues.length > 0 ? T.purple : T.secure }}>{xssIssues.length || '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>Tech Issues</span>
                  <span className="font-mono" style={{ color: actionableTechIssues.length > 0 ? T.info : T.secure }}>{actionableTechIssues.length || '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>Sensitive Exposure</span>
                  <span className="font-mono" style={{ color: exposureIssues.length > 0 ? T.warn : T.secure }}>{exposureIssues.length || '—'}</span>
                </div>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>Malicious Flags</span>
                  <span className="font-mono" style={{ color: isMal ? T.purple : T.secure }}>{isMal ? '1' : '—'}</span>
                </div>
                {findings.dns && (
                  <div className="flex items-center justify-between text-xs py-1.5">
                    <span style={{ color: T.muted }}>DNS Issues</span>
                    <span className="font-mono" style={{ color: dnsIssues.length > 0 ? T.warn : T.secure }}>{dnsIssues.length || '—'}</span>
                  </div>
                )}
                {findings.redirect && (
                  <div className="flex items-center justify-between text-xs py-1.5">
                    <span style={{ color: T.muted }}>Open Redirects</span>
                    <span className="font-mono" style={{ color: redirIssues.length > 0 ? T.danger : T.secure }}>{redirIssues.length || '—'}</span>
                  </div>
                )}
                {findings.takeover && (
                  <div className="flex items-center justify-between text-xs py-1.5">
                    <span style={{ color: T.muted }}>Subdomain Takeover</span>
                    <span className="font-mono" style={{ color: takeIssues.length > 0 ? T.danger : T.secure }}>{takeIssues.length || '—'}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Metadata card */}
            <div className="rounded-xl p-5" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <p className="text-xs font-mono uppercase tracking-widest mb-3" style={{ color: T.dim }}>Scan Metadata</p>
              <div className="flex flex-col gap-3">
                <div>
                  <p className="text-xs mb-0.5" style={{ color: T.muted }}>Target</p>
                  <a href={url} target="_blank" rel="noopener noreferrer"
                    className="text-xs font-mono flex items-center gap-1 break-all" style={{ color: T.primary }}>
                    <ExternalLink size={10} className="flex-shrink-0" /> {url || '—'}
                  </a>
                </div>
                <div>
                  <p className="text-xs mb-0.5" style={{ color: T.muted }}>Scan ID</p>
                  <p className="text-xs font-mono break-all" style={{ color: T.text }}>{meta.scan_id || report.scan_id}</p>
                </div>
                <div>
                  <p className="text-xs mb-0.5" style={{ color: T.muted }}>Date</p>
                  <p className="text-xs font-mono" style={{ color: T.text }}>{ts ? fmt(ts) : '—'}</p>
                </div>
              </div>
            </div>

            {/* Summary card */}
            <div className="rounded-xl p-5" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <p className="text-xs font-mono uppercase tracking-widest mb-3" style={{ color: T.dim }}>Executive Summary</p>
              <p className="text-xs leading-relaxed" style={{ color: T.muted }}>
                {totalIssues > 0
                  ? `Detected ${totalIssues} security ${totalIssues === 1 ? 'issue' : 'issues'} that should be addressed promptly.`
                  : 'No security issues detected — the site appears well-protected.'}
              </p>
              {totalIssues > 0 && (
                <ul className="mt-3 flex flex-col gap-1.5">
                  {hasSql && <li className="flex items-center gap-2 text-xs" style={{ color: T.danger }}><AlertTriangle size={11} /> {findings.sqli.length} SQL injection</li>}
                  {hasSsl && <li className="flex items-center gap-2 text-xs" style={{ color: T.warn }}><AlertTriangle size={11} /> SSL certificate issue</li>}
                  {hdrIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.info }}><AlertTriangle size={11} /> {hdrIssues.length} header issue{hdrIssues.length > 1 ? 's' : ''}</li>}
                  {wpIssues.length  > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.warn }}><AlertTriangle size={11} /> {wpIssues.length} WordPress issue{wpIssues.length > 1 ? 's' : ''}</li>}
                  {zapIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.danger }}><AlertTriangle size={11} /> {zapIssues.length} ZAP alert{zapIssues.length > 1 ? 's' : ''}</li>}
                  {xssIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.purple }}><AlertTriangle size={11} /> {xssIssues.length} XSS issue{xssIssues.length > 1 ? 's' : ''}</li>}
                  {actionableTechIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.info }}><AlertTriangle size={11} /> {actionableTechIssues.length} technology issue{actionableTechIssues.length > 1 ? 's' : ''}</li>}
                  {exposureIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.warn }}><AlertTriangle size={11} /> {exposureIssues.length} exposed path{exposureIssues.length > 1 ? 's' : ''}</li>}
                  {isMal && <li className="flex items-center gap-2 text-xs" style={{ color: T.purple }}><AlertOctagon size={11} /> Potentially malicious</li>}
                  {dnsIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.warn }}><AlertTriangle size={11} /> {dnsIssues.length} DNS issue{dnsIssues.length > 1 ? 's' : ''}</li>}
                  {redirIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.danger }}><AlertOctagon size={11} /> {redirIssues.length} open redirect{redirIssues.length > 1 ? 's' : ''}</li>}
                  {takeIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.danger }}><AlertOctagon size={11} /> {takeIssues.length} subdomain takeover{takeIssues.length > 1 ? 's' : ''}</li>}
                </ul>
              )}
            </div>
          </div>

          {/* ── Right: findings sections ── */}
          <div className="flex flex-col gap-4">

            {/* SQL */}
            <Section id="sql" label="SQL Injection" subLabel={hasSql ? `${findings.sqli.length} vulnerabilities` : 'No issues'}
              icon={hasSql ? AlertTriangle : Database} iconColor={hasSql ? T.danger : T.secure}
              iconBg={hasSql ? T.dangerDim : T.secureDim}
              expanded={expanded.sql} onToggle={toggle}>
              {hasSql ? (
                <div className="flex flex-col gap-3">
                  <p className="text-xs" style={{ color: T.muted }}>SQL injection lets attackers execute malicious queries to access your database.</p>
                  {findings.sqli.map((v, i) => (
                    <FindingCard key={i} color={T.danger} bg={T.dangerDim} icon={Database}
                      title={`Vulnerability ${i + 1}: ${v.type || 'SQL Injection'}`}
                      items={[
                        v.parameter && `Parameter: ${v.parameter}`,
                        v.severity  && `Severity: ${v.severity}`,
                        v.payload   && `Payload: ${v.payload}`,
                      ].filter(Boolean)} />
                  ))}
                  <Recs items={['Use parameterized queries / prepared statements', 'Validate and sanitize all user input', 'Apply least-privilege to database users', 'Consider a Web Application Firewall (WAF)']} />
                </div>
              ) : <CleanState icon={CheckCircle} title="No SQL Injection Vulnerabilities" body="Protected against SQL injection attacks." />}
            </Section>

            {/* SSL */}
            <Section id="ssl" label="SSL/TLS Certificate" subLabel={hasSsl ? 'Certificate issues' : 'Valid certificate'}
              icon={hasSsl ? AlertTriangle : Lock} iconColor={hasSsl ? T.warn : T.secure}
              iconBg={hasSsl ? T.warnDim : T.secureDim}
              expanded={expanded.ssl} onToggle={toggle}>
              {hasSsl ? (
                <div className="flex flex-col gap-3">
                  <FindingCard color={T.warn} bg={T.warnDim} icon={Lock} title="Certificate Issue"
                    items={[
                      findings.ssl.error && `Error: ${findings.ssl.error}`,
                      findings.ssl.self_signed && 'Self-signed certificate (not browser-trusted)',
                      findings.ssl.expires && `Expires: ${findings.ssl.expires}`,
                    ].filter(Boolean)} />
                  <Recs items={["Get a certificate from a trusted CA (Let's Encrypt is free)", 'Use TLS 1.2+ and strong cipher suites', 'Enable HSTS', 'Monitor expiry — renew before it lapses']} />
                </div>
              ) : (
                <div>
                  <CleanState icon={Lock} title="Valid SSL Certificate" body="Properly configured SSL/TLS." />
                  {findings.ssl && (
                    <div className="mt-2 rounded-lg p-4" style={{ background: T.surface }}>
                      {[['Issuer', findings.ssl.issuer?.organizationName || findings.ssl.issuer?.commonName],
                        ['Subject', findings.ssl.subject?.commonName],
                        ['Expires', findings.ssl.expires],
                        ['Protocol', findings.ssl.protocol],
                      ].filter(([, v]) => v).map(([k, v]) => (
                        <div key={k} className="flex gap-4 text-xs mb-1.5">
                          <span className="w-20 font-medium flex-shrink-0 font-mono" style={{ color: T.muted }}>{k}</span>
                          <span style={{ color: T.text }}>{v}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </Section>

            {/* Headers */}
            <Section id="headers" label="HTTP Header Security" subLabel={hdrIssues.length > 0 ? `${hdrIssues.length} issue${hdrIssues.length > 1 ? 's' : ''}` : 'No issues'}
              icon={hdrIssues.length > 0 ? AlertTriangle : CheckCircle}
              iconColor={hdrIssues.length > 0 ? T.info : T.secure}
              iconBg={hdrIssues.length > 0 ? T.infoDim : T.secureDim}
              expanded={expanded.headers} onToggle={toggle}>
              {hdrIssues.length > 0 ? (
                <div className="flex flex-col gap-3">
                  {hdrIssues.map((h, i) => (
                    <FindingCard key={i} color={T.info} bg={T.infoDim} icon={Shield}
                      title={h.name} items={[`Severity: ${h.severity}`, h.evidence].filter(Boolean)} />
                  ))}
                  {sections.headers?.recommendations?.length > 0 && <Recs items={sections.headers.recommendations} />}
                </div>
              ) : <CleanState icon={CheckCircle} title="No Header Issues" body="No HTTP header or HTTPS misconfigurations found." />}
            </Section>

            {/* WordPress */}
            <Section id="wordpress" label="WordPress Security"
              subLabel={!findings.wordpress?.is_wordpress ? 'Not WordPress' : wpIssues.length > 0 ? `${wpIssues.length} issue${wpIssues.length > 1 ? 's' : ''}` : 'No issues'}
              icon={wpIssues.length > 0 ? AlertTriangle : CheckCircle}
              iconColor={wpIssues.length > 0 ? T.warn : T.secure}
              iconBg={wpIssues.length > 0 ? T.warnDim : T.secureDim}
              expanded={expanded.wordpress} onToggle={toggle}>
              {!findings.wordpress?.is_wordpress ? (
                <div className="flex flex-col items-center gap-3 py-6 text-center">
                  <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: T.infoDim }}>
                    <Info size={20} style={{ color: T.info }} />
                  </div>
                  <p className="text-sm font-semibold" style={{ color: T.text }}>Not a WordPress Site</p>
                  <p className="text-xs" style={{ color: T.muted }}>No WordPress signatures detected.</p>
                </div>
              ) : (
                <div className="flex flex-col gap-3">
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { label: 'Core Version', val: findings.wordpress.version?.detected || 'Not exposed', sub: `Latest: ${findings.wordpress.version?.latest || 'Unknown'}` },
                      { label: 'Plugins',      val: findings.wordpress.plugins?.length || 0, sub: `Outdated: ${(findings.wordpress.plugins || []).filter(p => p.outdated).length}` },
                      { label: 'Themes',       val: `${findings.wordpress.themes?.length || 0}`, sub: (findings.wordpress.detection_methods || []).join(', ') || '—' },
                    ].map((c, i) => (
                      <div key={i} className="p-3 rounded-lg" style={{ background: T.surface }}>
                        <p className="text-xs mb-1" style={{ color: T.muted }}>{c.label}</p>
                        <p className="text-sm font-semibold" style={{ color: T.text }}>{c.val}</p>
                        <p className="text-xs mt-0.5 font-mono" style={{ color: T.dim }}>{c.sub}</p>
                      </div>
                    ))}
                  </div>
                  {wpIssues.length > 0 ? wpIssues.map((issue, i) => (
                    <FindingCard key={i} color={T.warn} bg={T.warnDim} icon={Shield}
                      title={issue.name} items={[`Severity: ${issue.severity}`, issue.evidence].filter(Boolean)} />
                  )) : (
                    <FindingCard color={T.secure} bg={T.secureDim} icon={CheckCircle}
                      title="No obvious WordPress hardening issues"
                      items={['The scanner did not find public exposure issues.']} />
                  )}
                  {(findings.wordpress?.plugins || []).length > 0 && (
                    <div className="rounded-lg p-3" style={{ background: T.surface }}>
                      <p className="text-xs font-semibold mb-2" style={{ color: T.text }}>Detected Plugins</p>
                      {findings.wordpress.plugins.slice(0, 8).map((p, i) => (
                        <div key={i} className="flex items-center justify-between text-xs py-1">
                          <span className="font-mono" style={{ color: T.muted }}>
                            <span style={{ color: T.text }}>{p.name || p.slug}</span>
                            {p.version && ` v${p.version}`}
                          </span>
                          <span className="px-2 py-0.5 rounded-md font-semibold"
                            style={p.outdated ? { background: T.dangerDim, color: T.danger } : { background: T.secureDim, color: T.secure }}>
                            {p.outdated ? 'Outdated' : 'Current'}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                  {sections.wordpress?.recommendations?.length > 0 && <Recs items={sections.wordpress.recommendations} />}
                </div>
              )}
            </Section>

            {/* ZAP */}
            <Section id="zap" label="OWASP ZAP Analysis"
              subLabel={findings.zap?.status === 'disabled' ? 'Not enabled' : zapIssues.length > 0 ? `${zapIssues.length} alerts` : 'No alerts'}
              icon={zapIssues.length > 0 ? AlertOctagon : CheckCircle}
              iconColor={zapIssues.length > 0 ? T.danger : T.secure}
              iconBg={zapIssues.length > 0 ? T.dangerDim : T.secureDim}
              expanded={expanded.zap} onToggle={toggle}>
              {findings.zap?.status === 'disabled' || findings.zap?.status === 'not_run' ? (
                <div className="flex flex-col gap-4 py-4">
                  <div className="flex items-start gap-3 p-4 rounded-xl" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                    <Info size={16} className="flex-shrink-0 mt-0.5" style={{ color: T.info }} />
                    <div className="flex flex-col gap-1.5">
                      <p className="text-sm font-semibold" style={{ color: T.text }}>OWASP ZAP Not Running</p>
                      <p className="text-xs leading-relaxed" style={{ color: T.muted }}>
                        ZAP (Zed Attack Proxy) is an active scanner that must run as a separate process on the same host as the backend.
                        It performs deeper crawling and active probing that passive scanners cannot do.
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-col gap-2">
                    <p className="text-xs font-semibold uppercase tracking-widest font-mono" style={{ color: T.dim }}>To enable ZAP integration:</p>
                    {[
                      'Install OWASP ZAP: brew install zaproxy (macOS) or download from zaproxy.org',
                      'Start ZAP in daemon mode: zap.sh -daemon -port 8080 -config api.key=your-key',
                      'Set ZAP_API_KEY and ZAP_BASE_URL in your backend .env file',
                      'Restart the backend — ZAP alerts will appear automatically in future scans',
                    ].map((step, i) => (
                      <div key={i} className="flex items-start gap-3 px-4 py-3 rounded-lg" style={{ background: T.surface, border: `1px solid ${T.borderSubtle}` }}>
                        <span className="w-5 h-5 rounded flex items-center justify-center text-xs font-bold flex-shrink-0" style={{ background: `${T.primary}20`, color: T.primary }}>{i + 1}</span>
                        <p className="text-xs font-mono leading-relaxed" style={{ color: T.muted }}>{step}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : zapIssues.length > 0 ? (
                <div className="flex flex-col gap-3">
                  {zapIssues.map((z, i) => (
                    <FindingCard key={i} color={T.danger} bg={T.dangerDim} icon={AlertOctagon}
                      title={z.name}
                      items={[`Severity: ${z.severity || z.risk || 'Info'}`, z.evidence, z.description].filter(Boolean)} />
                  ))}
                </div>
              ) : <CleanState icon={CheckCircle} title="No ZAP Alerts" body="OWASP ZAP found no additional issues." />}
            </Section>

            {/* XSS */}
            {findings.xss && (
              <Section id="xss" label="Cross-Site Scripting (XSS)" subLabel={hasXss ? `${xssIssues.filter(i=>i.type==='Reflected XSS').length} reflected vector${xssIssues.filter(i=>i.type==='Reflected XSS').length!==1?'s':''} found` : 'No reflected XSS detected'}
                icon={hasXss ? AlertTriangle : CheckCircle}
                iconColor={hasXss ? T.purple : T.secure}
                iconBg={hasXss ? T.purpleDim : T.secureDim}
                expanded={expanded.xss} onToggle={toggle}>
                {xssIssues.length > 0 ? (
                  <div className="flex flex-col gap-3">
                    <div className="grid grid-cols-2 gap-3">
                      {[
                        { label: 'Reflected XSS', val: xssIssues.filter(i=>i.type==='Reflected XSS').length },
                        { label: 'CSP Present', val: findings.xss?.csp_present ? 'Yes' : 'No' },
                      ].map(({label, val}) => (
                        <div key={label} className="p-3 rounded-lg" style={{ background: T.surface }}>
                          <p className="text-xs mb-1" style={{ color: T.dim }}>{label}</p>
                          <p className="text-sm font-bold font-mono" style={{ color: T.text }}>{val}</p>
                        </div>
                      ))}
                    </div>
                    {xssIssues.filter(i=>i.type==='Reflected XSS').map((issue, i) => (
                      <FindingCard key={i} color={T.purple} bg={T.purpleDim} icon={AlertTriangle}
                        title={issue.type}
                        items={[issue.vector, issue.parameter && `Parameter: ${issue.parameter}`, issue.payload && `Payload: ${issue.payload}`].filter(Boolean)} />
                    ))}
                    {!findings.xss?.csp_present && (
                      <FindingCard color={T.warn} bg={T.warnDim} icon={AlertTriangle}
                        title="No Content-Security-Policy header"
                        items={['Missing CSP makes XSS easier to exploit across all pages.']} />
                    )}
                    <Recs items={findings.xss?.recommendations?.length ? findings.xss.recommendations : [
                      'Encode all user-supplied output using context-aware encoding.',
                      'Implement a strict Content-Security-Policy header.',
                      'Use HttpOnly and Secure flags on session cookies.',
                    ]} />
                  </div>
                ) : <CleanState icon={CheckCircle} title="No XSS Detected" body="No reflected cross-site scripting vectors found in tested parameters." />}
              </Section>
            )}

            {/* Technology */}
            {findings.tech && (
              <Section id="tech" label="Technology Fingerprinting"
                subLabel={actionableTechIssues.length > 0 ? `${actionableTechIssues.length} actionable issue${actionableTechIssues.length !== 1 ? 's' : ''}` : 'No actionable technology issues'}
                icon={actionableTechIssues.length > 0 ? AlertTriangle : CheckCircle}
                iconColor={actionableTechIssues.length > 0 ? T.info : T.secure}
                iconBg={actionableTechIssues.length > 0 ? T.infoDim : T.secureDim}
                expanded={expanded.tech} onToggle={toggle}>
                <div className="flex flex-col gap-3">
                  {(findings.tech?.packages || []).length > 0 && (
                    <div className="rounded-lg overflow-hidden" style={{ border: `1px solid ${T.border}` }}>
                      <div className="px-3 py-2" style={{ background: T.surface, borderBottom: `1px solid ${T.border}` }}>
                        <p className="text-xs font-semibold" style={{ color: T.muted }}>Detected Packages</p>
                      </div>
                      <div>
                        {findings.tech.packages.map((pkg, idx, arr) => (
                          <div key={`${pkg.name}-${pkg.version}`} className="flex items-center justify-between gap-3 px-3 py-2.5"
                            style={{ borderBottom: idx < arr.length - 1 ? `1px solid ${T.border}` : 'none' }}>
                            <div className="min-w-0">
                              <p className="text-xs font-mono" style={{ color: T.text }}>{pkg.name}</p>
                              <p className="text-[11px] break-all" style={{ color: T.dim }}>{pkg.source}</p>
                            </div>
                            <span className="text-xs px-2 py-0.5 rounded font-mono"
                              style={{ background: `${T.primary}15`, color: T.primary, border: `1px solid ${T.primary}25` }}>
                              {pkg.version}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {(findings.tech?.advisories || []).length > 0 && (
                    <div className="flex flex-col gap-3">
                      {findings.tech.advisories.map((advisory, i) => (
                        <FindingCard key={`${advisory.package}-${advisory.id}-${i}`}
                          color={advisory.severity === 'Critical' || advisory.severity === 'High' ? T.danger : T.warn}
                          bg={advisory.severity === 'Critical' || advisory.severity === 'High' ? T.dangerDim : T.warnDim}
                          icon={AlertTriangle}
                          title={`${advisory.package}@${advisory.version}`}
                          items={[
                            (advisory.cves || []).join(', ') || advisory.id,
                            (advisory.cwes || []).join(', ') || 'CWE not published',
                            advisory.summary,
                            advisory.fixed_versions?.length ? `Fixed in: ${advisory.fixed_versions.join(', ')}` : null,
                          ].filter(Boolean)} />
                      ))}
                    </div>
                  )}
                  {Object.keys(findings.tech?.technologies || {}).length > 0 && (
                    <div className="rounded-lg overflow-hidden" style={{ border: `1px solid ${T.border}` }}>
                      <div className="px-3 py-2" style={{ background: T.surface, borderBottom: `1px solid ${T.border}` }}>
                        <p className="text-xs font-semibold" style={{ color: T.muted }}>Detected Stack</p>
                      </div>
                      <div>
                        {Object.entries(findings.tech.technologies).map(([category, techs], idx, arr) => (
                          <div key={category} className="flex items-start gap-3 px-3 py-2.5"
                            style={{ borderBottom: idx < arr.length - 1 ? `1px solid ${T.border}` : 'none' }}>
                            <p className="text-xs w-32 flex-shrink-0 font-medium capitalize" style={{ color: T.dim }}>
                              {category.replace(/-/g, ' ')}
                            </p>
                            <div className="flex flex-wrap gap-1.5">
                              {(Array.isArray(techs) ? techs : [techs]).map((t, i) => {
                                const version = findings.tech?.versions?.[t];
                                return (
                                  <span key={i} className="text-xs px-2 py-0.5 rounded font-mono flex items-center gap-1"
                                    style={{ background: `${T.info}15`, color: T.info, border: `1px solid ${T.info}25` }}>
                                    {t}{version && <span style={{ color: T.dim, fontSize: '10px' }}>v{version}</span>}
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {techIssues.length > 0 ? (
                    <>
                      {techIssues.map((issue, i) => (
                        <FindingCard key={i}
                          color={issue.severity === 'Info' ? T.info : T.warn}
                          bg={issue.severity === 'Info' ? T.infoDim : T.warnDim}
                          icon={issue.severity === 'Info' ? Info : AlertTriangle}
                          title={issue.name}
                          items={[`Severity: ${issue.severity}`, issue.evidence].filter(Boolean)} />
                      ))}
                      {sections.tech?.recommendations?.length > 0 && <Recs items={sections.tech.recommendations} />}
                    </>
                  ) : (
                    <CleanState icon={CheckCircle} title="No Technology Issues" body="No actionable technology exposure or outdated library findings were detected." />
                  )}
                </div>
              </Section>
            )}

            {/* Sensitive File Exposure */}
            {findings.exposure && (
              <Section id="exposure" label="Sensitive File Exposure"
                subLabel={exposureIssues.length > 0 ? `${exposureIssues.length} exposed path${exposureIssues.length!==1?'s':''}` : 'No exposed files detected'}
                icon={hasExposure ? AlertOctagon : exposureIssues.length > 0 ? AlertTriangle : CheckCircle}
                iconColor={hasExposure ? T.danger : exposureIssues.length > 0 ? T.warn : T.secure}
                iconBg={hasExposure ? T.dangerDim : exposureIssues.length > 0 ? T.warnDim : T.secureDim}
                expanded={expanded.exposure} onToggle={toggle}>
                {exposureIssues.length > 0 ? (
                  <div className="flex flex-col gap-3">
                    {exposureEmails.length > 0 && (
                      <FindingCard
                        color={T.info}
                        bg={T.infoDim}
                        icon={Mail}
                        title={`Discovered Email Address${exposureEmails.length !== 1 ? 'es' : ''}`}
                        items={exposureEmails.slice(0, 20).map(obfuscateEmail)}
                      />
                    )}
                    {exposureIssues.map((issue, i) => {
                      const color = issue.severity === 'Critical' ? T.danger : issue.severity === 'High' ? T.warn : issue.severity === 'Medium' ? T.info : T.dim;
                      const bg = issue.severity === 'Critical' ? T.dangerDim : issue.severity === 'High' ? T.warnDim : issue.severity === 'Medium' ? T.infoDim : T.surface;
                      return (
                        <div key={i} className="rounded-lg overflow-hidden" style={{ border: `1px solid ${color}40`, background: bg }}>
                          <div className="flex items-start gap-3 p-4">
                            {issue.severity === 'Critical'
                              ? <AlertOctagon size={14} className="flex-shrink-0 mt-0.5" style={{ color }} />
                              : <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" style={{ color }} />}
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-semibold" style={{ color }}>{issue.name}</p>
                              <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1">
                                <p className="text-xs font-mono break-all" style={{ color: T.info }}>{issue.url || issue.path}</p>
                                {issue.content_length && (
                                  <p className="text-xs" style={{ color: T.dim }}>{issue.content_length.toLocaleString()} bytes</p>
                                )}
                              </div>
                              {(issue.emails || []).length > 0 && (
                                <p className="text-xs mt-1 font-mono break-all" style={{ color: T.muted }}>
                                  Emails: {issue.emails.slice(0, 10).map(obfuscateEmail).join(', ')}
                                </p>
                              )}
                            </div>
                          </div>
                          {issue.content_preview && (
                            <div style={{ borderTop: `1px solid ${color}20` }}>
                              <p className="px-4 pt-2 pb-1 text-xs font-semibold uppercase tracking-wider" style={{ color: T.dim }}>Content Preview</p>
                              <pre className="px-4 pb-4 text-xs overflow-x-auto whitespace-pre-wrap break-all" style={{
                                color: T.info,
                                background: T.elev,
                                fontFamily: 'monospace',
                                lineHeight: '1.5',
                                maxHeight: '320px',
                                overflowY: 'auto',
                              }}>{issue.content_preview}</pre>
                            </div>
                          )}
                        </div>
                      );
                    })}
                    <Recs items={findings.exposure?.recommendations?.length ? findings.exposure.recommendations : [
                      'Block access to sensitive paths via web server rules.',
                      'Remove backup and debug files from the web root.',
                    ]} />
                  </div>
                ) : <CleanState icon={CheckCircle} title="No Sensitive Files Exposed" body="No credentials, backups, or debug pages found at common paths." />}
              </Section>
            )}

            {/* DNS Security */}
            {findings.dns && (() => {
              const dns = findings.dns;
              const dnsIssues = dns.issues || [];
              const dnsHigh = dnsIssues.some(i => ['Critical','High'].includes(i.severity));
              return (
                <Section id="dns" label="DNS Security (SPF / DMARC / DKIM)"
                  subLabel={dnsIssues.length > 0 ? `${dnsIssues.length} issue${dnsIssues.length!==1?'s':''}` : 'Pass'}
                  icon={dnsHigh ? AlertOctagon : dnsIssues.length > 0 ? AlertTriangle : CheckCircle}
                  iconColor={dnsHigh ? T.danger : dnsIssues.length > 0 ? T.warn : T.secure}
                  iconBg={dnsHigh ? T.dangerDim : dnsIssues.length > 0 ? T.warnDim : T.secureDim}
                  expanded={expanded.dns} onToggle={toggle}>
                  {dnsIssues.length > 0 ? (
                    <div className="flex flex-col gap-3">
                      {dnsIssues.map((issue, i) => {
                        const color = issue.severity === 'High' ? T.warn : issue.severity === 'Medium' ? T.info : T.dim;
                        const bg = issue.severity === 'High' ? T.warnDim : issue.severity === 'Medium' ? T.infoDim : T.surface;
                        return (
                          <FindingCard key={i} color={color} bg={bg} icon={AlertTriangle}
                            title={issue.name}
                            items={[issue.evidence].filter(Boolean)} />
                        );
                      })}
                      {dns.spf?.record && <p className="text-xs font-mono break-all mt-1" style={{ color: T.dim }}>SPF: {dns.spf.record}</p>}
                      {dns.dmarc?.record && <p className="text-xs font-mono break-all mt-1" style={{ color: T.dim }}>DMARC: {dns.dmarc.record}</p>}
                      <Recs items={dns.recommendations || []} />
                    </div>
                  ) : (
                    <div className="flex flex-col gap-2">
                      <CleanState icon={CheckCircle} title="Email Security Configured" body="SPF, DMARC, DKIM, and CAA records are properly set up." />
                      {dns.spf?.record && <p className="text-xs font-mono break-all" style={{ color: T.dim }}>SPF: {dns.spf.record}</p>}
                      {dns.dmarc?.record && <p className="text-xs font-mono break-all" style={{ color: T.dim }}>DMARC: {dns.dmarc.record}</p>}
                    </div>
                  )}
                </Section>
              );
            })()}

            {/* Open Redirect */}
            {findings.redirect && (() => {
              const redir = findings.redirect;
              const redirIssues = redir.issues || [];
              return (
                <Section id="redirect" label="Open Redirect"
                  subLabel={redirIssues.length > 0 ? `${redirIssues.length} vulnerable redirect${redirIssues.length!==1?'s':''}` : 'Pass'}
                  icon={redirIssues.length > 0 ? AlertOctagon : CheckCircle}
                  iconColor={redirIssues.length > 0 ? T.danger : T.secure}
                  iconBg={redirIssues.length > 0 ? T.dangerDim : T.secureDim}
                  expanded={expanded.redirect} onToggle={toggle}>
                  {redirIssues.length > 0 ? (
                    <div className="flex flex-col gap-3">
                      {redirIssues.map((issue, i) => (
                        <div key={i} className="rounded-lg p-4" style={{ background: T.dangerDim, border: `1px solid ${T.danger}30` }}>
                          <div className="flex items-start gap-3">
                            <AlertOctagon size={14} className="flex-shrink-0 mt-0.5" style={{ color: T.danger }} />
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-semibold" style={{ color: T.danger }}>{issue.name}</p>
                              <p className="text-xs mt-1 font-mono break-all" style={{ color: T.muted }}>Parameter: {issue.parameter}</p>
                              <p className="text-xs mt-0.5 font-mono break-all" style={{ color: T.muted }}>Redirected to: {issue.location}</p>
                              <p className="text-xs mt-0.5 font-mono break-all" style={{ color: T.dim }}>Payload: {issue.url}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                      <Recs items={redir.recommendations || []} />
                    </div>
                  ) : <CleanState icon={CheckCircle} title="No Open Redirects Detected" body="No URL parameters could be abused to redirect users to external domains." />}
                </Section>
              );
            })()}

            {/* Subdomain Takeover */}
            {findings.takeover && (() => {
              const take = findings.takeover;
              const takeIssues = take.issues || [];
              const subsChecked = take.subdomains_checked || [];
              return (
                <Section id="takeover" label="Subdomain Takeover"
                  subLabel={takeIssues.length > 0 ? `${takeIssues.length} vulnerable subdomain${takeIssues.length!==1?'s':''}` : `Pass — ${subsChecked.length} subdomain${subsChecked.length!==1?'s':''} checked`}
                  icon={takeIssues.length > 0 ? AlertOctagon : CheckCircle}
                  iconColor={takeIssues.length > 0 ? T.danger : T.secure}
                  iconBg={takeIssues.length > 0 ? T.dangerDim : T.secureDim}
                  expanded={expanded.takeover} onToggle={toggle}>
                  {takeIssues.length > 0 ? (
                    <div className="flex flex-col gap-3">
                      {takeIssues.map((issue, i) => (
                        <FindingCard key={i} color={T.danger} bg={T.dangerDim} icon={AlertOctagon}
                          title={issue.name}
                          items={[issue.evidence].filter(Boolean)} />
                      ))}
                      <Recs items={take.recommendations || []} />
                    </div>
                  ) : (
                    <div className="flex flex-col gap-2">
                      <CleanState icon={CheckCircle} title="No Takeover Risk Detected" body="No dangling CNAMEs or unclaimed service deployments found." />
                      {subsChecked.length > 0 && (
                        <p className="text-xs mt-1" style={{ color: T.dim }}>
                          Checked: {subsChecked.join(', ')}
                        </p>
                      )}
                    </div>
                  )}
                </Section>
              );
            })()}

            {/* Malicious */}
            {(() => {
              const mal = findings.malicious || {};
              const score = mal.score ?? 0;
              const dnsblHit = mal.dnsbl?.blacklisted;
              const dnsblCount = mal.dnsbl?.total_detected ?? 0;
              const hasWarnings = dnsblHit || mal.phishing_match || (mal.score_reasons || []).length > 0;
              const scoreColor = score >= 7 ? T.danger : score >= 4 ? T.warn : T.secure;
              const subLabel = isMal ? 'Potentially malicious' : hasWarnings ? 'Warnings detected' : 'No threats detected';
              return (
                <Section id="malicious" label="Malicious Content" subLabel={subLabel}
                  icon={isMal ? AlertOctagon : hasWarnings ? AlertTriangle : CheckCircle}
                  iconColor={isMal ? T.danger : hasWarnings ? T.warn : T.secure}
                  iconBg={isMal ? T.dangerDim : hasWarnings ? T.warnDim : T.secureDim}
                  expanded={expanded.malicious} onToggle={toggle}>
                  <div className="flex flex-col gap-3">
                    {/* Threat score bar — always shown */}
                    {score !== undefined && (
                      <div className="rounded-lg p-3 flex items-center gap-3" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                        <span className="text-xs font-mono w-24 flex-shrink-0" style={{ color: T.muted }}>Threat Score</span>
                        <div className="flex-1 h-2 rounded-full" style={{ background: T.border }}>
                          <div className="h-2 rounded-full transition-all" style={{ width: `${Math.min(score * 10, 100)}%`, background: scoreColor }} />
                        </div>
                        <span className="text-xs font-mono font-semibold w-10 text-right" style={{ color: scoreColor }}>{score}/10</span>
                      </div>
                    )}

                    {/* DNSBL hits */}
                    {dnsblHit && (
                      <FindingCard color={T.warn} bg={T.warnDim} icon={AlertTriangle}
                        title={`Listed in ${dnsblCount} DNS blacklist${dnsblCount !== 1 ? 's' : ''}`}
                        items={Object.keys(mal.dnsbl?.detected || {}).map(bl => `• ${bl}`)} />
                    )}

                    {/* Phishing match */}
                    {mal.phishing_match && (
                      <FindingCard color={T.danger} bg={T.dangerDim} icon={AlertOctagon}
                        title="Domain matches known phishing patterns" items={[]} />
                    )}

                    {/* Score reasons */}
                    {(mal.score_reasons || []).filter(r => !r.includes('blacklist')).length > 0 && (
                      <FindingCard color={isMal ? T.danger : T.warn} bg={isMal ? T.dangerDim : T.warnDim}
                        icon={AlertTriangle} title="Suspicious Indicators"
                        items={(mal.score_reasons || []).filter(r => !r.includes('blacklist'))} />
                    )}

                    {/* Clean */}
                    {!isMal && !hasWarnings && (
                      <CleanState icon={CheckCircle} title="No Malicious Content" body="Site does not appear to contain threats." />
                    )}

                    {/* Recs only if truly malicious */}
                    {isMal && (
                      <Recs items={['Avoid sharing sensitive info on this site', 'Block domain at network level', 'If your site: investigate for compromise or injected content', 'Run a malware scan on the server']} />
                    )}
                  </div>
                </Section>
              );
            })()}

            {/* Conclusion */}
            <div className="rounded-xl p-5" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <p className="text-xs font-mono uppercase tracking-widest mb-3" style={{ color: T.dim }}>Conclusion & Next Steps</p>
              {totalIssues > 0 ? (
                <div>
                  <p className="text-xs mb-3" style={{ color: T.muted }}>
                    {totalIssues} security {totalIssues === 1 ? 'issue was' : 'issues were'} found. Address these to improve your security posture.
                  </p>
                  <ol className="flex flex-col gap-2">
                    {hasSql && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>1. SQL Injection:</span> Use parameterized queries and input validation.</li>}
                    {hasSsl && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>2. SSL:</span> Get a valid cert and configure TLS properly.</li>}
                    {hdrIssues.length > 0 && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>3. Headers:</span> Add missing security headers and strengthen HTTPS policy.</li>}
                    {wpIssues.length  > 0 && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>4. WordPress:</span> Update outdated core/plugins and reduce public exposure.</li>}
                    {zapIssues.length > 0 && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>5. ZAP Alerts:</span> Validate and remediate ZAP findings.</li>}
                    {xssIssues.length > 0 && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>6. XSS:</span> Encode output, validate input, and enforce a strict CSP.</li>}
                    {actionableTechIssues.length > 0 && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>7. Technology:</span> Patch outdated frontend libraries, disable directory indexing, and reduce banner leakage.</li>}
                    {exposureIssues.length > 0 && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>8. Exposure:</span> Remove backups, secrets, and debug files from the web root.</li>}
                    {isMal && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>9. Malicious:</span> Investigate unauthorized changes or phishing content.</li>}
                    {(findings.dns?.issues || []).length > 0 && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>10. DNS Security:</span> Configure SPF, DMARC (p=reject), DKIM, and CAA records.</li>}
                    {(findings.redirect?.issues || []).length > 0 && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>11. Open Redirect:</span> Validate redirect targets against a strict server-side allowlist.</li>}
                    {(findings.takeover?.issues || []).length > 0 && <li className="text-xs" style={{ color: T.muted }}><span className="font-semibold" style={{ color: T.text }}>12. Subdomain Takeover:</span> Remove dangling CNAMEs and claim unclaimed service deployments.</li>}
                  </ol>
                </div>
              ) : (
                <p className="text-xs" style={{ color: T.muted }}>No issues found. Keep scanning regularly and keep software up to date.</p>
              )}
            </div>

            {bestPractices.length > 0 && (
              <div className="rounded-xl p-5" style={{ background: T.card, border: `1px solid ${T.border}` }}>
                <p className="text-xs font-mono uppercase tracking-widest mb-3" style={{ color: T.dim }}>Developer Best Practices</p>
                <Recs items={bestPractices} />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanReport;
