import React, { useState, useEffect } from 'react';
import {
  FileText, Shield, ArrowLeft, Download,
  AlertTriangle, CheckCircle, AlertOctagon, Database, Lock,
  Info, RefreshCw, ChevronDown, ChevronUp, ExternalLink, Globe, Trash2, Package,
  Mail, ArrowRightLeft, Link2Off, Camera, Monitor, Smartphone,
} from 'lucide-react';
import { useScanReportData } from '../hooks/useScanReportData';
import Spinner from './Spinner';
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

const labelForConfidence = (value) => {
  const normalized = String(value || 'heuristic').replace(/_/g, ' ').toLowerCase();
  if (normalized === 'high') return 'High Confidence';
  if (normalized === 'medium') return 'Medium Confidence';
  if (normalized === 'low') return 'Low Confidence';
  if (normalized === 'measured') return 'Measured';
  if (normalized === 'ai assisted') return 'AI-Assisted';
  return 'Heuristic';
};

const labelForEvidenceType = (value) => {
  const normalized = String(value || '').replace(/_/g, ' ').toLowerCase();
  if (normalized === 'confirmed technical issue') return 'Confirmed Technical Issue';
  if (normalized === 'measured ux failure') return 'Measured UX Failure';
  if (normalized === 'heuristic ux risk') return 'Heuristic UX Risk';
  if (normalized === 'ai visual recommendation') return 'AI Visual Recommendation';
  return normalized ? normalized.replace(/\b\w/g, c => c.toUpperCase()) : 'Evidence';
};

const verdictTone = (verdict) => {
  if (verdict === 'blocked') return { color: T.danger, bg: T.dangerDim, icon: AlertOctagon };
  if (verdict === 'fix_before_shipping') return { color: T.warn, bg: T.warnDim, icon: AlertTriangle };
  if (verdict === 'monitor_after_launch') return { color: T.info, bg: T.infoDim, icon: RefreshCw };
  return { color: T.secure, bg: T.secureDim, icon: CheckCircle };
};

const deltaLabel = (value) => {
  if (value === null || value === undefined) return '—';
  if (value === 0) return 'No change';
  return value > 0 ? `+${value}` : `${value}`;
};

/* Collapsible section */
const Section = ({ id, label, subLabel, icon: Icon, iconColor, iconBg, expanded, onToggle, children }) => (
  <div className="card overflow-hidden">
    <button onClick={() => onToggle(id)}
      className="w-full flex items-center justify-between px-5 py-4 cursor-pointer transition-colors"
      style={{ background: 'var(--color-surface)' }} aria-expanded={expanded}>
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
      <div className="px-5 py-4" style={{ borderTop: '1px solid var(--color-border-subtle)' }}>
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
        <circle cx="48" cy="48" r={r} fill="none" stroke="var(--color-border)" strokeWidth="6" />
        <circle cx="48" cy="48" r={r} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" style={{ transition: 'stroke-dasharray 0.6s ease' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-bold" style={{ color }}>{score}</span>
        <span className="text-xs" style={{ color: 'var(--color-text-dim)' }}>/100</span>
      </div>
    </div>
  );
};

/* Authenticated screenshot image — fetches via cookie-auth and converts to blob URL */
const AuthImage = ({ src, alt, className, style }) => {
  const [blobUrl, setBlobUrl] = useState(null);
  useEffect(() => {
    if (!src) return;
    let revoke;
    apiFetch(src, { auth: true })
      .then(r => r.ok ? r.blob() : null)
      .then(blob => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        revoke = url;
        setBlobUrl(url);
      })
      .catch(() => {});
    return () => { if (revoke) URL.revokeObjectURL(revoke); };
  }, [src]);
  if (!blobUrl) return (
    <div className="flex items-center justify-center py-12" style={{ color: 'var(--color-text-dim)' }}>
      <RefreshCw size={16} className="animate-spin" />
    </div>
  );
  return <img src={blobUrl} alt={alt} className={className} style={style} />;
};

/* Site screenshot panel */
const ScreenshotPanel = ({ screenshots }) => {
  const [active, setActive] = useState('desktop');
  const [lightbox, setLightbox] = useState(null);

  const shots = screenshots?.screenshots || {};
  const hasDesktop = !!shots.desktop;
  const hasMobile  = !!shots.mobile;
  if (!hasDesktop && !hasMobile) return null;

  const tabs = [
    hasDesktop && { key: 'desktop', label: 'Desktop', icon: Monitor },
    hasMobile  && { key: 'mobile',  label: 'Mobile',  icon: Smartphone },
  ].filter(Boolean);

  const currentRel = shots[active] || shots.desktop || shots.mobile;

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4"
        style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)' }}>
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: T.primaryDim }}>
            <Camera size={16} style={{ color: T.primary }} />
          </div>
          <div>
            <p className="text-sm font-semibold" style={{ color: T.text }}>Site Screenshots</p>
            <p className="text-xs mt-0.5" style={{ color: T.muted }}>Captured at scan time</p>
          </div>
        </div>
        {tabs.length > 1 && (
          <div className="flex items-center gap-1 rounded-lg p-1" style={{ background: 'var(--color-elevated)' }}>
            {tabs.map(({ key, label, icon: Icon }) => (
              <button key={key} onClick={() => setActive(key)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-150 cursor-pointer"
                style={active === key
                  ? { background: 'var(--color-card)', color: T.primary, boxShadow: '0 1px 4px rgba(0,0,0,0.3)' }
                  : { color: T.muted }}>
                <Icon size={12} /> {label}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="p-4">
        <div className="relative rounded-xl overflow-hidden cursor-zoom-in group"
          style={{ border: '1px solid var(--color-border)', background: 'var(--color-bg)' }}
          onClick={() => setLightbox(currentRel)}>
          <AuthImage
            src={currentRel}
            alt={`${active} screenshot`}
            className="w-full h-auto block"
            style={{ maxHeight: active === 'mobile' ? '500px' : '420px', objectFit: 'contain', objectPosition: 'top' }}
          />
          <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity duration-200"
            style={{ background: 'rgba(0,0,0,0.4)' }}>
            <span className="text-white text-xs font-semibold px-3 py-1.5 rounded-lg"
              style={{ background: 'rgba(0,0,0,0.6)' }}>Click to enlarge</span>
          </div>
        </div>
      </div>

      {lightbox && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6"
          style={{ background: 'rgba(0,0,0,0.9)', backdropFilter: 'blur(10px)' }}
          onClick={() => setLightbox(null)}>
          <AuthImage src={lightbox} alt="enlarged"
            className="max-w-full max-h-full rounded-xl shadow-2xl"
            style={{ border: '1px solid rgba(255,255,255,0.1)' }} />
          <button onClick={() => setLightbox(null)}
            className="absolute top-5 right-5 w-9 h-9 rounded-full flex items-center justify-center text-white cursor-pointer text-lg font-bold"
            style={{ background: 'rgba(255,255,255,0.15)' }}>✕</button>
        </div>
      )}
    </div>
  );
};

/* ─────────────────────────────────────────────── */
const ScanReport = ({ scanId, navigateTo }) => {
  const [expanded, setExpanded] = useState({ sql: true, ssl: true, headers: true, wordpress: true, zap: true, malicious: true, xss: true, tech: true, exposure: true, secrets: true, dns: true, redirect: true, takeover: true, accessibility: true, responsive_ux: true, performance_ux: true, form_usability: true, seo: true, broken_links: true, app_controls: true, exposed_services: true, abuse_controls: true, visual_ai: true, comparison: true });
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
    <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--color-bg)' }}>
      <Spinner size="lg" label="Loading report…" />
    </div>
  );

  if (error || !report) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--color-bg)' }}>
      <div className="flex flex-col items-center gap-4">
        <div className="w-14 h-14 rounded-2xl flex items-center justify-center" style={{ background: 'var(--color-danger-dim)' }}>
          <AlertTriangle size={24} style={{ color: 'var(--color-danger)' }} />
        </div>
        <p className="text-sm font-medium" style={{ color: T.text }}>{error ? 'Error loading report' : 'Report not found'}</p>
        <p className="text-xs" style={{ color: T.muted }}>{error || `Report ${scanId} could not be found.`}</p>
        <button onClick={() => navigateTo('dashboard')} className="btn-primary">
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
  const launchVerdict = findings.launch_verdict || {};
  const verdictInfo = verdictTone(launchVerdict.verdict);
  const VerdictIcon = verdictInfo.icon;
  const scanProfile = findings.scan_profile || 'full_scan';
  const isSecurityScan = scanProfile === 'full_scan' || scanProfile === 'full_launch_audit' || scanProfile === 'security_only';
  const isUxScan = scanProfile === 'product_readiness' || scanProfile === 'full_launch_audit';
  const comparison = report.comparison || null;

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
  const secretsIssues = findings.secrets?.issues || [];
  const hasSecrets   = secretsIssues.some(i => ['Critical','High'].includes(i.severity));
  const dnsIssues    = findings.dns?.issues || [];
  const redirIssues  = findings.redirect?.issues || [];
  const takeIssues   = findings.takeover?.issues || [];
  const accessibilityIssues = findings.accessibility?.issues || [];
  const responsiveIssues = findings.responsive_ux?.issues || [];
  const performanceIssues = findings.performance_ux?.issues || [];
  const formIssues = findings.form_usability?.issues || [];
  const seoIssues = findings.seo?.issues || [];
  const brokenLinkIssues = findings.broken_links?.issues || [];
  const appControlIssues = findings.app_controls?.issues || [];
  const exposedServiceIssues = findings.exposed_services?.issues || [];
  const abuseIssues = [
    ...(findings.abuse_controls?.issues || []),
    ...((findings.abuse_controls?.discovery || {}).issues || []),
  ];
  const visualAiIssues = findings.visual_ai?.issues || [];
  const launchReadiness = findings.launch_readiness || {};
  const topLaunchActions = [
    ...(launchVerdict.top_blockers || []),
    ...(launchVerdict.important_issues || []),
    ...(launchVerdict.monitoring_items || []),
  ].slice(0, 5);

  const totalIssues = summary.total_issues ??
    (
      (hasSql ? findings.sqli.length : 0) +
      hdrIssues.length +
      wpIssues.length +
      zapIssues.length +
      xssIssues.length +
      actionableTechIssues.length +
      exposureIssues.length +
      secretsIssues.length +
      dnsIssues.length +
      redirIssues.length +
      takeIssues.length +
      seoIssues.length +
      (hasSsl ? 1 : 0) +
      (isMal ? 1 : 0)
    );

  const score = meta.security_score ?? (totalIssues === 0 ? 100 : Math.max(0, 100 - totalIssues * 5));
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
      <div className="page-header px-6 lg:px-10 py-4 flex items-center justify-between">
        <button onClick={() => navigateTo('dashboard')} className="btn-secondary flex items-center gap-1.5 text-xs">
          <ArrowLeft size={13} /> Dashboard
        </button>
        <div className="flex items-center gap-2">
          <span className="badge" style={{ background: riskDim, color: riskColor }}>
            {risk} Risk
          </span>
          <button onClick={handleSbomDownload} className="btn-secondary text-xs"
            style={{ color: 'var(--color-info)' }}>
            <Package size={12} /> SBOM
          </button>
          <button onClick={() => setShowDeleteDialog(true)} disabled={isDeleting}
            className="btn-secondary text-xs disabled:opacity-60"
            style={{ color: 'var(--color-danger)', borderColor: 'rgba(239,68,68,0.2)', background: 'var(--color-danger-dim)' }}>
            <Trash2 size={12} /> {isDeleting ? 'Deleting…' : 'Delete'}
          </button>
          <button onClick={handleDownload} className="btn-secondary text-xs">
            <Download size={12} /> PDF
          </button>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6">
        {deleteError && (
          <div className="mb-4 rounded-xl px-4 py-3 text-xs flex items-center gap-2"
            style={{ background: 'var(--color-danger-dim)', color: 'var(--color-danger)', border: '1px solid rgba(239,68,68,0.2)' }}>
            <AlertTriangle size={14} /> {deleteError}
          </div>
        )}
        <div className="card p-5 mb-6" style={{ borderColor: verdictInfo.color }}>
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-5">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0" style={{ background: verdictInfo.bg }}>
                <VerdictIcon size={22} style={{ color: verdictInfo.color }} />
              </div>
              <div>
                <p className="section-label mb-1">Launch Verdict</p>
                <h1 className="text-2xl font-bold" style={{ color: verdictInfo.color }}>
                  {launchVerdict.label || 'Launch Verdict Pending'}
                </h1>
                <p className="text-sm mt-2 max-w-3xl" style={{ color: T.muted }}>
                  {launchVerdict.summary || 'This report was generated before the verdict engine was available.'}
                </p>
                {launchVerdict.next_action && (
                  <p className="text-sm mt-2" style={{ color: T.text }}>
                    <span className="font-semibold">Next action:</span> {launchVerdict.next_action}
                  </p>
                )}
                {launchVerdict.scan_profile && (
                  <p className="text-xs mt-3" style={{ color: T.dim }}>
                    Scan profile: <span style={{ color: T.text }}>{launchVerdict.scan_profile.label}</span>
                    {launchVerdict.scan_profile.description ? ` · ${launchVerdict.scan_profile.description}` : ''}
                  </p>
                )}
              </div>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 min-w-[280px]">
              {[
                { label: 'Blockers', value: launchVerdict.counts?.blockers ?? 0, color: T.danger },
                { label: 'Fix First', value: launchVerdict.counts?.fix_before_ship ?? 0, color: T.warn },
                { label: 'Monitor', value: launchVerdict.counts?.monitor_after_ship ?? 0, color: T.info },
                { label: 'Advisory', value: launchVerdict.counts?.recommendations ?? 0, color: T.muted },
              ].map(item => (
                <div key={item.label} className="rounded-lg p-3" style={{ background: T.surface, border: `1px solid ${T.borderSubtle}` }}>
                  <p className="text-[10px] uppercase tracking-wide" style={{ color: T.dim }}>{item.label}</p>
                  <p className="text-lg font-bold font-mono" style={{ color: item.color }}>{item.value}</p>
                </div>
              ))}
            </div>
          </div>
          {topLaunchActions.length > 0 && (
            <div className="mt-5 pt-4" style={{ borderTop: `1px solid ${T.borderSubtle}` }}>
              <p className="section-label mb-3">Top Launch Actions</p>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                {topLaunchActions.map((item, index) => (
                  <div key={item.finding_id || index} className="rounded-lg p-3" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded" style={{ background: T.elev, color: verdictTone(item.launch_impact === 'blocked' ? 'blocked' : item.launch_impact === 'monitor_after_ship' ? 'monitor_after_launch' : 'fix_before_shipping').color }}>
                        {String(item.launch_impact || '').replace(/_/g, ' ')}
                      </span>
                      <span className="text-[10px]" style={{ color: T.dim }}>{labelForEvidenceType(item.evidence_type)}</span>
                    </div>
                    <p className="text-sm font-semibold" style={{ color: T.text }}>{item.title}</p>
                    {item.recommended_fix && <p className="text-xs mt-1" style={{ color: T.muted }}>{item.recommended_fix}</p>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-6 items-start">

          {/* ── Left: sticky summary panel ── */}
          <div className="lg:sticky lg:top-24 flex flex-col gap-4">

            {/* Score card */}
            <div className="card p-5 flex flex-col items-center gap-4">
              <ScoreRing score={score} color={scoreColor} />
              <div className="text-center">
                <p className="section-label mb-1">LaunchGuard Score</p>
                <span className="badge" style={{ background: riskDim, color: riskColor }}>
                  {risk} Risk
                </span>
              </div>
              <div className="w-full pt-2" style={{ borderTop: '1px solid var(--color-border-subtle)' }}>
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>Issues found</span>
                  <span className="font-mono font-semibold" style={{ color: totalIssues > 0 ? T.danger : T.secure }}>{totalIssues}</span>
                </div>
                {isSecurityScan && (<>
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
                {findings.secrets && (
                  <div className="flex items-center justify-between text-xs py-1.5">
                    <span style={{ color: T.muted }}>Public Secrets</span>
                    <span className="font-mono" style={{ color: secretsIssues.length > 0 ? T.danger : T.secure }}>{secretsIssues.length || '—'}</span>
                  </div>
                )}
                <div className="flex items-center justify-between text-xs py-1.5">
                  <span style={{ color: T.muted }}>Malicious Flags</span>
                  <span className="font-mono" style={{ color: isMal ? T.purple : T.secure }}>{isMal ? '1' : '—'}</span>
                </div>
                </>)}
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
                {findings.accessibility && (
                  <div className="flex items-center justify-between text-xs py-1.5">
                    <span style={{ color: T.muted }}>Accessibility</span>
                    <span className="font-mono" style={{ color: accessibilityIssues.length > 0 ? T.info : T.secure }}>{accessibilityIssues.length || '—'}</span>
                  </div>
                )}
                {findings.responsive_ux && (
                  <div className="flex items-center justify-between text-xs py-1.5">
                    <span style={{ color: T.muted }}>Responsive UX</span>
                    <span className="font-mono" style={{ color: responsiveIssues.length > 0 ? T.warn : T.secure }}>{responsiveIssues.length || '—'}</span>
                  </div>
                )}
                {findings.performance_ux && (
                  <div className="flex items-center justify-between text-xs py-1.5">
                    <span style={{ color: T.muted }}>Performance UX</span>
                    <span className="font-mono" style={{ color: performanceIssues.length > 0 ? T.warn : T.secure }}>{performanceIssues.length || '—'}</span>
                  </div>
                )}
                {findings.form_usability && (
                  <div className="flex items-center justify-between text-xs py-1.5">
                    <span style={{ color: T.muted }}>Form Usability</span>
                    <span className="font-mono" style={{ color: formIssues.length > 0 ? T.warn : T.secure }}>{formIssues.length || '—'}</span>
                  </div>
                )}
                {findings.seo && (
                  <div className="flex items-center justify-between text-xs py-1.5">
                    <span style={{ color: T.muted }}>SEO Readiness</span>
                    <span className="font-mono" style={{ color: seoIssues.length > 0 ? T.info : T.secure }}>{seoIssues.length || '—'}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Metadata card */}
            <div className="card p-5">
              <p className="section-label mb-3">Scan Metadata</p>
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
            <div className="card p-5">
              <p className="section-label mb-3">Executive Summary</p>
              <p className="text-xs leading-relaxed" style={{ color: T.muted }}>
                {launchVerdict.summary || (totalIssues > 0
                  ? `Detected ${totalIssues} issue${totalIssues === 1 ? '' : 's'} that should be addressed promptly.`
                  : 'No configured launch-blocking issues were detected.')}
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
                  {secretsIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.danger }}><AlertOctagon size={11} /> {secretsIssues.length} publicly exposed secret{secretsIssues.length > 1 ? 's' : ''} detected</li>}
                  {isMal && <li className="flex items-center gap-2 text-xs" style={{ color: T.purple }}><AlertOctagon size={11} /> Potentially malicious</li>}
                  {dnsIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.warn }}><AlertTriangle size={11} /> {dnsIssues.length} DNS issue{dnsIssues.length > 1 ? 's' : ''}</li>}
                  {redirIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.danger }}><AlertOctagon size={11} /> {redirIssues.length} open redirect{redirIssues.length > 1 ? 's' : ''}</li>}
                  {takeIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.danger }}><AlertOctagon size={11} /> {takeIssues.length} subdomain takeover{takeIssues.length > 1 ? 's' : ''}</li>}
                  {accessibilityIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.info }}><AlertTriangle size={11} /> {accessibilityIssues.length} accessibility finding{accessibilityIssues.length > 1 ? 's' : ''}</li>}
                  {responsiveIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.warn }}><AlertTriangle size={11} /> {responsiveIssues.length} responsive/mobile finding{responsiveIssues.length > 1 ? 's' : ''}</li>}
                  {performanceIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.warn }}><AlertTriangle size={11} /> {performanceIssues.length} performance UX issue{performanceIssues.length > 1 ? 's' : ''}</li>}
                  {formIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.warn }}><AlertTriangle size={11} /> {formIssues.length} form usability issue{formIssues.length > 1 ? 's' : ''}</li>}
                  {seoIssues.length > 0 && <li className="flex items-center gap-2 text-xs" style={{ color: T.info }}><AlertTriangle size={11} /> {seoIssues.length} SEO readiness issue{seoIssues.length > 1 ? 's' : ''}</li>}
                </ul>
              )}
            </div>

            {comparison && (
              <div className="card p-5">
                <p className="section-label mb-3">Re-scan Comparison</p>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: 'Fixed', value: comparison.fixed_count, color: T.secure },
                    { label: 'New', value: comparison.new_count, color: T.danger },
                    { label: 'Unresolved', value: comparison.unresolved_count, color: T.warn },
                  ].map((item) => (
                    <div key={item.label} className="rounded-lg p-3" style={{ background: T.surface, border: `1px solid ${T.borderSubtle}` }}>
                      <p className="text-xs mb-1" style={{ color: T.muted }}>{item.label}</p>
                      <p className="text-sm font-bold font-mono" style={{ color: item.color }}>{item.value}</p>
                    </div>
                  ))}
                </div>
                <div className="mt-3 flex flex-col gap-1.5 text-xs" style={{ color: T.muted }}>
                  <p>Previous scan: <span style={{ color: T.text }}>{comparison.previous_scan_id || '—'}</span></p>
                  <p>Issue count delta: <span style={{ color: T.text }}>{deltaLabel(comparison.summary_delta?.issue_count)}</span></p>
                  <p>Launch readiness delta: <span style={{ color: T.text }}>{deltaLabel(comparison.summary_delta?.launch_readiness_score)}</span></p>
                </div>
              </div>
            )}

            {launchVerdict.limitations?.length > 0 && (
              <div className="card p-5">
                <p className="section-label mb-3">Report Limitations</p>
                <div className="flex flex-col gap-2">
                  {launchVerdict.limitations.map((item, index) => (
                    <p key={index} className="text-xs leading-relaxed" style={{ color: T.dim }}>{item}</p>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ── Right: findings sections ── */}
          <div className="flex flex-col gap-4">

            {/* Screenshots */}
            <ScreenshotPanel screenshots={findings.screenshots} scanId={scanId} />

            {/* SQL */}
            {isSecurityScan && <Section id="sql" label="SQL Injection" subLabel={hasSql ? `${findings.sqli.length} vulnerabilities` : 'No issues'}
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
            </Section>}

            {/* SSL */}
            {isSecurityScan && <Section id="ssl" label="SSL/TLS Certificate" subLabel={hasSsl ? 'Certificate issues' : 'Valid certificate'}
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
            </Section>}

            {/* Headers */}
            {isSecurityScan && <Section id="headers" label="HTTP Header Security" subLabel={hdrIssues.length > 0 ? `${hdrIssues.length} issue${hdrIssues.length > 1 ? 's' : ''}` : 'No issues'}
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
            </Section>}

            {/* WordPress */}
            {isSecurityScan && <Section id="wordpress" label="WordPress Security"
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
            </Section>}

            {/* ZAP */}
            {isSecurityScan && <Section id="zap" label="OWASP ZAP Analysis"
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
            </Section>}

            {/* XSS */}
            {isSecurityScan && findings.xss && (
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
            {isSecurityScan && findings.tech && (
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
            {isSecurityScan && findings.exposure && (
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

            {/* Hardcoded Secrets & API Keys */}
            {isSecurityScan && findings.secrets && (
              <Section id="secrets" label="Hardcoded Secrets & API Keys"
                subLabel={secretsIssues.length > 0 ? `${secretsIssues.length} secret${secretsIssues.length!==1?'s':''} detected` : 'No secrets detected'}
                icon={hasSecrets ? AlertOctagon : secretsIssues.length > 0 ? AlertTriangle : CheckCircle}
                iconColor={hasSecrets ? T.danger : secretsIssues.length > 0 ? T.warn : T.secure}
                iconBg={hasSecrets ? T.dangerDim : secretsIssues.length > 0 ? T.warnDim : T.secureDim}
                expanded={expanded.secrets} onToggle={toggle}>
                {secretsIssues.length > 0 ? (
                  <div className="flex flex-col gap-3">
                    {secretsIssues.map((issue, i) => {
                      const color = issue.severity === 'Critical' ? T.danger : issue.severity === 'High' ? T.warn : issue.severity === 'Medium' ? T.info : T.dim;
                      const bg = issue.severity === 'Critical' ? T.dangerDim : issue.severity === 'High' ? T.warnDim : issue.severity === 'Medium' ? T.infoDim : T.surface;
                      return (
                        <div key={i} className="rounded-lg overflow-hidden" style={{ border: `1px solid ${color}40`, background: bg }}>
                          <div className="flex items-start gap-3 p-4">
                            {issue.severity === 'Critical'
                              ? <AlertOctagon size={14} className="flex-shrink-0 mt-0.5" style={{ color }} />
                              : <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" style={{ color }} />}
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <p className="text-sm font-semibold" style={{ color }}>{issue.name}</p>
                                <span className="text-xs px-2 py-0.5 rounded-full font-medium uppercase tracking-wider" style={{ background: `${color}20`, color }}>
                                  {issue.severity}
                                </span>
                              </div>
                              <p className="text-xs font-mono break-all mt-1" style={{ color: T.info }}>{issue.source}</p>
                              <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1">
                                <span className="text-xs" style={{ color: T.muted }}>
                                  Value: <code className="font-mono" style={{ color: T.warn }}>{issue.match_redacted}</code>
                                </span>
                                {issue.line && (
                                  <span className="text-xs" style={{ color: T.dim }}>Line {issue.line}</span>
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    <Recs items={findings.secrets?.recommendations?.length ? findings.secrets.recommendations : [
                      'Remove hardcoded API keys and secrets from client-side code.',
                      'Rotate any exposed credentials immediately — treat them as compromised.',
                      'Use environment variables or a secrets manager.',
                      'Add pre-commit hooks (git-secrets, truffleHog) to prevent future leaks.',
                    ]} />
                  </div>
                ) : <CleanState icon={CheckCircle} title="No Hardcoded Secrets Detected" body="No API keys, tokens, or credentials were found in the page source or JavaScript files." />}
              </Section>
            )}

            {/* DNS Security */}
            {isSecurityScan && findings.dns && (() => {
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
            {isSecurityScan && findings.redirect && (() => {
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
            {isSecurityScan && findings.takeover && (() => {
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
            {isSecurityScan && (() => {
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

            {[
              { id: 'accessibility', label: 'Accessibility', issues: accessibilityIssues, iconColor: T.info, iconBg: T.infoDim, recommendations: findings.accessibility?.recommendations || [] },
              { id: 'responsive_ux', label: 'Mobile and Responsive UX', issues: responsiveIssues, iconColor: T.warn, iconBg: T.warnDim, recommendations: findings.responsive_ux?.recommendations || [] },
              { id: 'performance_ux', label: 'Performance UX', issues: performanceIssues, iconColor: T.info, iconBg: T.infoDim, recommendations: findings.performance_ux?.recommendations || [], rawMetrics: findings.performance_ux?.raw_metrics },
              { id: 'form_usability', label: 'Form and Interaction Usability', issues: formIssues, iconColor: T.warn, iconBg: T.warnDim, recommendations: findings.form_usability?.recommendations || [] },
              { id: 'seo', label: 'SEO Readiness', issues: seoIssues, iconColor: T.info, iconBg: T.infoDim, recommendations: findings.seo?.recommendations || [] },
              { id: 'broken_links', label: 'Broken Links', issues: brokenLinkIssues, iconColor: T.warn, iconBg: T.warnDim, recommendations: findings.broken_links?.recommendations || [] },
              { id: 'app_controls', label: 'Application Controls', issues: appControlIssues, iconColor: T.warn, iconBg: T.warnDim, recommendations: findings.app_controls?.recommendations || [], endpoints: findings.app_controls?.discovered_endpoints || [], forms: findings.app_controls?.form_matrix || [] },
              { id: 'exposed_services', label: 'Exposed Services', issues: exposedServiceIssues, iconColor: T.danger, iconBg: T.dangerDim, recommendations: findings.exposed_services?.recommendations || [], services: findings.exposed_services?.open_services || [], ports: findings.exposed_services?.ports_checked || [] },
              { id: 'abuse_controls', label: 'Abuse Controls and Exposed Routes', issues: abuseIssues, iconColor: T.danger, iconBg: T.dangerDim, recommendations: findings.abuse_controls?.recommendations || [], routes: findings.abuse_controls?.discovery?.routes || [] },
              { id: 'visual_ai', label: 'Visual UX Recommendations', issues: visualAiIssues, iconColor: T.purple, iconBg: T.purpleDim, recommendations: findings.visual_ai?.recommendations || [] },
            ].filter((item) => findings[item.id]).map((item) => (
              <Section
                key={item.id}
                id={item.id}
                label={item.label}
                subLabel={item.issues.length > 0 ? `${item.issues.length} finding${item.issues.length !== 1 ? 's' : ''}` : 'No issues'}
                icon={item.issues.length > 0 ? AlertTriangle : CheckCircle}
                iconColor={item.issues.length > 0 ? item.iconColor : T.secure}
                iconBg={item.issues.length > 0 ? item.iconBg : T.secureDim}
                expanded={expanded[item.id]}
                onToggle={toggle}
              >
                {(() => {
                  const rawMetrics = item.rawMetrics;
                  const metricRows = rawMetrics ? Object.entries(rawMetrics).flatMap(([pageUrl, m]) => {
                    if (!m || typeof m !== 'object') return [];
                    const labels = {
                      load_time_ms:              { label: 'Load Time',        unit: 'ms',  good: 3000, warn: 5000 },
                      dom_content_loaded_ms:     { label: 'DOM Ready',        unit: 'ms',  good: 1500, warn: 3000 },
                      first_contentful_paint_ms: { label: 'FCP',              unit: 'ms',  good: 1800, warn: 3000 },
                      ttfb_ms:                   { label: 'TTFB',             unit: 'ms',  good: 200,  warn: 600  },
                      tti_ms:                    { label: 'TTI',              unit: 'ms',  good: 2500, warn: 3800 },
                      total_transfer_kb:         { label: 'Transfer Size',    unit: 'KB',  good: 500,  warn: 2000 },
                      js_transfer_kb:            { label: 'JS Size',          unit: 'KB',  good: 200,  warn: 500  },
                      css_transfer_kb:           { label: 'CSS Size',         unit: 'KB',  good: 50,   warn: 150  },
                      image_transfer_kb:         { label: 'Images Size',      unit: 'KB',  good: 200,  warn: 1000 },
                      resource_count:            { label: 'Requests',         unit: '',    good: 50,   warn: 100  },
                    };
                    return Object.entries(labels)
                      .filter(([k]) => m[k] != null && m[k] > 0)
                      .map(([k, meta]) => {
                        const v = m[k];
                        const color = v <= meta.good ? T.secure : v <= meta.warn ? T.warn : T.danger;
                        return { pageUrl, key: k, label: meta.label, value: v, unit: meta.unit, color };
                      });
                  }) : [];
                  return (
                    <div className="flex flex-col gap-3">
                      {metricRows.length > 0 && (
                        <div className="rounded-lg p-4" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                          <p className="text-xs font-semibold mb-3" style={{ color: T.muted }}>RAW PERFORMANCE METRICS</p>
                          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                            {metricRows.map(({ key, label, value, unit, color }) => (
                              <div key={key} className="flex flex-col gap-1 p-3 rounded" style={{ background: T.elev, border: `1px solid ${T.borderSubtle}` }}>
                                <span className="text-[10px] uppercase tracking-wide" style={{ color: T.dim }}>{label}</span>
                                <span className="text-lg font-bold font-mono" style={{ color }}>{value.toLocaleString()}<span className="text-xs ml-0.5" style={{ color: T.muted }}>{unit}</span></span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {item.routes?.length > 0 && (
                        <div className="rounded-lg p-4" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                          <p className="text-xs font-semibold mb-3" style={{ color: T.muted }}>DISCOVERED AUTH AND ADMIN ROUTES</p>
                          <div className="flex flex-col gap-2">
                            {item.routes.map((route, index) => (
                              <div key={`${route.path}-${index}`} className="flex items-center justify-between gap-3 p-3 rounded" style={{ background: T.elev, border: `1px solid ${T.borderSubtle}` }}>
                                <div className="min-w-0">
                                  <p className="text-xs font-mono truncate" style={{ color: T.text }}>{route.path}</p>
                                  <p className="text-[11px]" style={{ color: T.dim }}>{route.kind} · HTTP {route.status_code}</p>
                                </div>
                                <span className="text-[11px] font-semibold" style={{ color: route.kind === 'sensitive' ? T.warn : T.info }}>{route.kind}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {item.endpoints?.length > 0 && (
                        <div className="rounded-lg p-4" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                          <p className="text-xs font-semibold mb-3" style={{ color: T.muted }}>DISCOVERED API ENDPOINTS</p>
                          <div className="flex flex-col gap-2 max-h-64 overflow-auto">
                            {item.endpoints.slice(0, 30).map((endpoint, index) => (
                              <p key={`${endpoint}-${index}`} className="text-xs font-mono break-all p-2 rounded" style={{ background: T.elev, color: T.text }}>{endpoint}</p>
                            ))}
                          </div>
                        </div>
                      )}
                      {item.forms?.length > 0 && (
                        <div className="rounded-lg p-4" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                          <p className="text-xs font-semibold mb-3" style={{ color: T.muted }}>FORM SAFETY MATRIX</p>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {item.forms.map((form, index) => (
                              <div key={`${form.selector}-${index}`} className="p-3 rounded" style={{ background: T.elev, border: `1px solid ${T.borderSubtle}` }}>
                                <p className="text-xs font-mono truncate" style={{ color: T.text }}>{form.selector}</p>
                                <p className="text-[11px]" style={{ color: T.dim }}>{form.classification} · {form.method} · {form.safe_to_submit ? 'bounded-testable' : 'manual-review'}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {item.services?.length > 0 && (
                        <div className="rounded-lg p-4" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                          <p className="text-xs font-semibold mb-3" style={{ color: T.muted }}>OPEN SERVICES</p>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {item.services.map((service, index) => (
                              <div key={`${service.port}-${index}`} className="p-3 rounded" style={{ background: T.elev, border: `1px solid ${T.borderSubtle}` }}>
                                <p className="text-xs font-mono" style={{ color: T.text }}>{service.host}:{service.port}</p>
                                <p className="text-[11px]" style={{ color: T.dim }}>{service.protocol} · {service.risk} · {service.http?.server || service.http?.status_code || 'tcp open'}</p>
                              </div>
                            ))}
                          </div>
                          {item.ports?.length > 0 && (
                            <p className="text-[11px] mt-3 font-mono break-all" style={{ color: T.dim }}>Checked: {item.ports.join(', ')}</p>
                          )}
                        </div>
                      )}
                      {item.issues.length > 0 ? (
                        <>
                          {item.issues.map((issue, index) => (
                            <div key={issue.id || index} className="rounded-lg p-4" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                              <div className="flex items-start justify-between gap-3">
                                <div>
                                  <p className="text-sm font-semibold" style={{ color: T.text }}>{issue.title || issue.name}</p>
                                  <div className="mt-2 flex items-center gap-2 flex-wrap">
                                    <span className="px-2 py-0.5 rounded text-[11px] font-semibold" style={{ background: T.elev, color: item.iconColor, border: `1px solid ${T.border}` }}>
                                      {labelForConfidence(issue.confidence)}
                                    </span>
                                    {issue.evidence_type && (
                                      <span className="px-2 py-0.5 rounded text-[11px] font-semibold" style={{ background: T.elev, color: T.muted, border: `1px solid ${T.border}` }}>
                                        {labelForEvidenceType(issue.evidence_type)}
                                      </span>
                                    )}
                                    <span className="text-xs" style={{ color: T.dim }}>{issue.viewport || 'all viewports'}</span>
                                    {issue.evidence?.metric && (
                                      <span className="text-xs font-mono" style={{ color: T.dim }}>
                                        {issue.evidence.metric}: {issue.evidence.value} / threshold: {issue.evidence.threshold}
                                      </span>
                                    )}
                                  </div>
                                  {issue.user_impact && <p className="text-xs mt-2" style={{ color: T.muted }}>{issue.user_impact}</p>}
                                  {issue.technical_remediation && <p className="text-xs mt-2" style={{ color: T.text }}>{issue.technical_remediation}</p>}
                                  {issue.builder_prompt && (
                                    <pre className="mt-2 text-xs whitespace-pre-wrap break-words" style={{ color: T.info, background: T.elev, padding: '10px', borderRadius: '8px' }}>
                                      {issue.builder_prompt}
                                    </pre>
                                  )}
                                  {issue.evidence?.screenshot_url && (
                                    <img
                                      src={issue.evidence.screenshot_url}
                                      alt={issue.title || issue.name || 'Issue evidence'}
                                      className="mt-3 rounded-lg border max-w-full"
                                      style={{ borderColor: T.border, maxHeight: '280px' }}
                                    />
                                  )}
                                </div>
                                <span className="px-2 py-1 rounded text-xs font-semibold" style={{ background: item.iconBg, color: item.iconColor }}>
                                  {issue.severity}
                                </span>
                              </div>
                            </div>
                          ))}
                          {item.recommendations.length > 0 && <Recs items={item.recommendations} />}
                        </>
                      ) : metricRows.length === 0 ? (
                        <CleanState icon={CheckCircle} title={`No ${item.label} Issues`} body="No findings detected in this category." />
                      ) : (
                        <CleanState icon={CheckCircle} title="No Performance Issues" body="All measured metrics are within acceptable thresholds." />
                      )}
                    </div>
                  );
                })()}
              </Section>
            ))}

            {comparison && (
              <Section
                id="comparison"
                label="Re-scan Improvements"
                subLabel={`${comparison.fixed_count} fixed · ${comparison.new_count} new · ${comparison.unresolved_count} unresolved`}
                icon={ArrowRightLeft}
                iconColor={T.info}
                iconBg={T.infoDim}
                expanded={expanded.comparison ?? true}
                onToggle={toggle}
              >
                <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                  {[
                    { key: 'fixed', title: 'Fixed Findings', color: T.secure, icon: CheckCircle },
                    { key: 'new', title: 'New Findings', color: T.danger, icon: AlertTriangle },
                    { key: 'unresolved', title: 'Unresolved Findings', color: T.warn, icon: Link2Off },
                  ].map((bucket) => (
                    <div key={bucket.key} className="rounded-lg p-4" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                      <p className="text-sm font-semibold mb-3" style={{ color: bucket.color }}>{bucket.title}</p>
                      <div className="flex flex-col gap-3">
                        {(comparison[bucket.key] || []).length > 0 ? (comparison[bucket.key] || []).map((issue) => (
                          <div key={`${bucket.key}-${issue.id}`} className="rounded-lg p-3" style={{ background: T.elev, border: `1px solid ${T.borderSubtle}` }}>
                            <div className="flex items-start gap-2">
                              <bucket.icon size={13} className="mt-0.5 flex-shrink-0" style={{ color: bucket.color }} />
                              <div>
                                <p className="text-xs font-semibold" style={{ color: T.text }}>{issue.title}</p>
                                <p className="text-[11px] mt-1" style={{ color: T.dim }}>{issue.scanner} · {issue.viewport || 'all viewports'}</p>
                                {issue.page_url && <p className="text-[11px] mt-1 break-all" style={{ color: T.muted }}>{issue.page_url}</p>}
                              </div>
                            </div>
                          </div>
                        )) : (
                          <p className="text-xs" style={{ color: T.muted }}>No items.</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </Section>
            )}

            {/* Conclusion */}
            <div className="card p-5">
              <p className="section-label mb-3">Conclusion & Next Steps</p>
              {launchReadiness.summary && (
                <p className="text-xs mb-3" style={{ color: T.info }}>
                  Launch readiness: {launchReadiness.summary}
                </p>
              )}
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
              <div className="card p-5">
                <p className="section-label mb-3">Developer Best Practices</p>
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
