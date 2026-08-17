import React, { useState, useEffect, useMemo } from 'react';
import {
  AlertTriangle, Lock, Database,
  RefreshCw, CheckCircle, Search,
  Globe, ArrowRight, Zap, ChevronRight,
  Code2, Layers, FolderSearch
} from 'lucide-react';
import { useScansData } from '../hooks/useScansData';
import { useVerifiedTargetsData } from '../hooks/useVerifiedTargetsData';
import { apiDateMs, formatApiDateTime, formatApiTime } from '../lib/time';
import Spinner from './Spinner';

const V = {
  primary: 'var(--color-primary)',
  secure:  'var(--color-secure)',
  warn:    'var(--color-warn)',
  danger:  'var(--color-danger)',
  info:    'var(--color-info)',
  purple:  'var(--color-info)',
};

/* Keep T as alias for backwards compat with scan result panels */
const T = {
  bg:          'var(--color-bg)',
  surface:     'var(--color-surface)',
  card:        'var(--color-card)',
  elev:        'var(--color-elevated)',
  border:      'var(--color-border)',
  borderBright:'var(--color-border-bright)',
  text:        'var(--color-text)',
  muted:       'var(--color-text-muted)',
  dim:         'var(--color-text-dim)',
  ...V,
};

const SCANNERS = [
  {
    id: 'full',
    icon: Zap,
    color: V.primary,
    title: 'Full Async Scan',
    subtitle: 'All checks · Async',
    desc: 'Runs SQLi, SSL/TLS, HTTP headers, malicious URL analysis, and optional ZAP alerts in a background job.',
    badge: 'Recommended',
  },
  {
    id: 'sql',
    icon: Database,
    color: V.danger,
    title: 'SQL Injection',
    subtitle: 'Sync · Form params',
    desc: 'Tests URL parameters and form inputs for SQL injection vulnerabilities using multiple payload types.',
  },
  {
    id: 'ssl',
    icon: Lock,
    color: V.secure,
    title: 'SSL / TLS',
    subtitle: 'Sync · Certificate',
    desc: 'Checks certificate validity, expiry, issuer trust, self-signing, and protocol version.',
  },
  {
    id: 'wordpress',
    icon: Globe,
    color: V.warn,
    title: 'WordPress',
    subtitle: 'Sync · CMS hardening',
    desc: 'Detects core version, exposed plugins, XML-RPC, REST user enumeration, and hardening issues.',
  },
  {
    id: 'xss',
    icon: Code2,
    color: V.purple,
    title: 'XSS Scanner',
    subtitle: 'Sync · Reflection & forms',
    desc: 'Tests URL parameters and HTML forms against 36 PortSwigger payloads including SVG, animation events, and WAF bypass vectors.',
    badge: 'New',
  },
  {
    id: 'tech',
    icon: Layers,
    color: V.info,
    title: 'Tech Fingerprint',
    subtitle: 'Sync · Stack detection',
    desc: 'Identifies the full technology stack — CMS, frameworks, servers, CDNs — and flags exposed version banners.',
    badge: 'New',
  },
  {
    id: 'exposure',
    icon: FolderSearch,
    color: '#F97316',
    title: 'File Exposure',
    subtitle: 'Sync · Sensitive paths',
    desc: 'Probes ~100 sensitive paths across all stacks — .env files, Git repos, SQL dumps, Spring Boot actuators, AWS credentials, CI configs, and more.',
    badge: 'New',
  },
  {
    id: 'malware',
    icon: AlertTriangle,
    color: '#DC2626',
    title: 'Malware Analysis',
    subtitle: 'Sync · Downloads',
    desc: 'Discovers same-origin downloadable artifacts and analyzes them with local malware tooling such as ClamAV, YARA, PE metadata, and Office macro inspection.',
    badge: 'New',
  },
];

const VulnBadge = ({ vulnerable, label }) => (
  <span className="badge"
    style={vulnerable
      ? { background: 'var(--color-danger-dim)', color: 'var(--color-danger)', border: '1px solid rgba(239,68,68,0.2)' }
      : { background: 'var(--color-secure-dim)', color: 'var(--color-secure)', border: '1px solid rgba(34,197,94,0.2)' }}
  >
    {vulnerable ? <AlertTriangle size={10} /> : <CheckCircle size={10} />}
    {label}
  </span>
);

const FindingItem = ({ color, title, meta }) => (
  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', borderLeft: `2px solid ${color}`, background: 'var(--color-surface)' }}>
    <div style={{ minWidth: 0, flex: 1 }}>
      <p style={{ fontSize: 11, fontWeight: 600, color, fontFamily: "var(--font-mono)" }}>{title}</p>
      {meta && <p style={{ fontSize: 10, marginTop: 2, color: T.muted, fontFamily: "var(--font-mono)" }}>{meta}</p>}
    </div>
  </div>
);

const Recs = ({ items }) => (
  <div style={{ borderLeft: '2px solid var(--color-info)', paddingLeft: 12, paddingTop: 4, paddingBottom: 4 }}>
    <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-info)', fontFamily: "var(--font-mono)", marginBottom: 6 }}>Recommendations</p>
    <ul style={{ display: 'flex', flexDirection: 'column', gap: 4, margin: 0, padding: 0, listStyle: 'none' }}>
      {items.map((r, i) => (
        <li key={i} style={{ fontSize: 11, color: 'var(--color-text-muted)', display: 'flex', gap: 6, alignItems: 'flex-start' }}>
          <span style={{ color: 'var(--color-info)', flexShrink: 0 }}>›</span> {r}
        </li>
      ))}
    </ul>
  </div>
);

const ProgressBar = ({ value, color }) => (
  <div
    style={{ width: '100%', height: 2, background: 'var(--color-border)' }}
  >
    <div
      style={{ width: `${Math.max(0, Math.min(value ?? 0, 100))}%`, height: '100%', background: color, transition: 'width 500ms ease' }}
    />
  </div>
);

const normalizeHost = (value = '') => {
  try {
    const url = new URL(value.startsWith('http') ? value : `https://${value}`);
    return url.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
};

/* Scan URL input + button */
const ScanInput = ({ url, setUrl, onScan, isScanning }) => (
  <div className="flex gap-2">
    <div className="relative flex-1">
      <input type="url" value={url}
        onChange={(e) => setUrl(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && !isScanning && onScan()}
        placeholder="https://target.example.com"
        className="input font-mono" style={{ fontSize: '13px' }} />
    </div>
    <button onClick={onScan} disabled={isScanning}
      className="btn-primary whitespace-nowrap" style={{ opacity: isScanning ? 0.75 : 1 }}>
      {isScanning ? <><Spinner size="sm" /> Scanning…</> : <><Search size={13} /> Scan</>}
    </button>
  </div>
);

/* Full scan job status */
const FullScanStatus = ({ job, navigateTo }) => {
  if (!job) return null;

  const statusColor = job.status === 'completed' ? T.secure : job.status === 'failed' ? T.danger : T.warn;
  const fmt = (d) => formatApiDateTime(d, { dateStyle: 'short', timeStyle: 'short' });
  const progress = job.progress || null;
  const isStale = Boolean(progress?.stale) && ['queued', 'running'].includes(job.status);
  const progressPercent = progress?.percent ?? (job.status === 'completed' ? 100 : 0);
  const queuedForMs = job.created_at ? Date.now() - apiDateMs(job.created_at) : 0;
  const queueName = job.scan_type === 'product_readiness' || job.scan_type === 'full_launch_audit'
    ? 'ux_scans'
    : 'security_scans';
  const queueWarning = job.status === 'queued' && queuedForMs > 15000;
  const progressMessage =
    (isStale ? 'The worker has not reported progress recently.' : progress?.message)
    || (job.status === 'queued' ? 'Waiting for worker to pick up the job' : null);
  const logs = Array.isArray(progress?.logs) ? progress.logs.slice(-6).reverse() : [];
  const statusLabel = isStale ? 'stalled' : job.status;
  const shownStatusColor = isStale ? T.danger : statusColor;

  return (
    <div className="rounded-xl overflow-hidden mt-4" style={{ border: '1px solid var(--color-border)' }}>
      <div className="flex items-center justify-between px-4 py-3" style={{ background: 'var(--color-surface)' }}>
        <p className="section-label">Job Status</p>
        <span className="badge" style={{ background: `${shownStatusColor}15`, color: shownStatusColor }}>
          {['queued','running'].includes(job.status) && !isStale && <Spinner size="sm" style={{ width: 10, height: 10 }} />}
          {statusLabel}
        </span>
      </div>
      <div className="p-4 flex flex-col gap-2">
        <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{job.url}</p>
        <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>{job.created_at ? fmt(job.created_at) : 'Pending…'}</p>
        {!['failed'].includes(job.status) && (
          <>
            <div className="mt-1 flex items-center justify-between gap-3">
              <p className="text-xs font-medium" style={{ color: 'var(--color-text)' }}>
                {progressMessage || 'Preparing status…'}
              </p>
              <span className="text-xs font-mono" style={{ color: shownStatusColor }}>
                {progressPercent}%
              </span>
            </div>
            <ProgressBar value={progressPercent} color={shownStatusColor} />
            {progress?.current_step_label && (
              <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>
                Current step: {progress.current_step_label}
                {progress?.step_index && progress?.total_steps
                  ? ` (${progress.step_index}/${progress.total_steps})`
                  : ''}
              </p>
            )}
          </>
        )}
        {job.status === 'failed' && <p className="text-xs mt-1" style={{ color: 'var(--color-danger)' }}>{job.error_message || 'Scan failed'}</p>}
        {isStale && (
          <div className="mt-2 rounded-lg p-3" style={{ background: 'var(--color-danger-dim)', border: '1px solid rgba(239,68,68,0.2)' }}>
            <p className="text-xs font-semibold" style={{ color: 'var(--color-danger)' }}>
              This scan stopped updating.
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
              The worker may have restarted while the scan was running. If this does not recover shortly, start a new scan.
            </p>
          </div>
        )}
        {queueWarning && (
          <div className="mt-2 rounded-lg p-3" style={{ background: 'var(--color-warn-dim)', border: '1px solid rgba(245,158,11,0.2)' }}>
            <p className="text-xs font-semibold" style={{ color: 'var(--color-warn)' }}>
              This job is still queued.
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
              The <span className="font-mono" style={{ color: 'var(--color-text)' }}>{queueName}</span> queue may be busy, rate-limited, or reconnecting. Check worker logs if it does not start shortly.
            </p>
          </div>
        )}
        {logs.length > 0 && (
          <div className="mt-2 rounded-lg p-3 flex flex-col gap-2"
            style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}>
            <p className="section-label">Activity</p>
            {logs.map((entry, index) => (
              <div key={`${entry.timestamp || index}-${entry.message || index}`} className="flex items-start gap-2">
                <span className="mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: shownStatusColor }} />
                <div className="min-w-0">
                  <p className="text-xs" style={{ color: 'var(--color-text)' }}>{entry.message}</p>
                  {entry.timestamp && (
                    <p className="text-xs font-mono" style={{ color: 'var(--color-text-dim)' }}>
                      {formatApiTime(entry.timestamp, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
        {job.status === 'completed' && job.result_id ? (
          <button onClick={() => navigateTo('report', job.result_id)}
            className="btn-primary mt-1 justify-center">
            View Report <ArrowRight size={13} />
          </button>
        ) : !['completed','failed'].includes(job.status) && (
          <p className="text-xs mt-1" style={{ color: 'var(--color-text-dim)' }}>
            {isStale ? 'Waiting for the backend to mark the interrupted job or recover it.' : 'Processing in background — auto-refreshing every 3s'}
          </p>
        )}
      </div>
    </div>
  );
};

/* ════════════════════════════════════════════════ */
const Scanners = ({ navigateTo }) => {
  const [activeId, setActiveId] = useState('full');

  const {
    fullScanUrl, setFullScanUrl, fullScanProfile, setFullScanProfile,
    fullScanPagePaths, setFullScanPagePaths, fullScanVerifiedTargetId, setFullScanVerifiedTargetId,
    fullScanEnableAiReview, setFullScanEnableAiReview,
    fullScanEnableActiveChecks, setFullScanEnableActiveChecks,
    fullScanActiveCheckPaths, setFullScanActiveCheckPaths,
    fullScanActiveCheckBudget, setFullScanActiveCheckBudget,
    fullScanAuthAccounts, setFullScanAuthAccounts,
    fullScanProtectedPaths, setFullScanProtectedPaths,
    fullScanIdorPaths, setFullScanIdorPaths,
    sqlScanUrl, setSqlScanUrl,
    sslScanUrl, setSslScanUrl, wordpressScanUrl, setWordpressScanUrl,
    xssScanUrl, setXssScanUrl, techScanUrl, setTechScanUrl,
    exposureScanUrl, setExposureScanUrl, malwareScanUrl, setMalwareScanUrl,
    isFullScanSubmitting, isSqlScanning, isSslScanning, isWordpressScanning,
    isXssScanning, isTechScanning, isExposureScanning, isMalwareScanning,
    fullScanJob, sqlScanResult, sslScanResult, wordpressScanResult,
    xssScanResult, techScanResult, exposureScanResult, malwareScanResult,
    fullScanError, sqlError, sslError, wordpressError, xssError, techError, exposureError, malwareError,
    handleFullScan, handleSqlScan, handleSslScan, handleWordpressScan,
    handleXssScan, handleTechScan, handleExposureScan, handleMalwareScan,
  } = useScansData();
  const {
    targets,
    loading: targetsLoading,
  } = useVerifiedTargetsData();

  useEffect(() => { document.title = 'Scanners — LaunchGuard'; }, []);

  const fmt = (d) => formatApiDateTime(d, { dateStyle: 'short', timeStyle: 'short' });

  const active = SCANNERS.find(s => s.id === activeId);
  const activeScanUrl = {
    full: fullScanUrl,
    sql: sqlScanUrl,
    wordpress: wordpressScanUrl,
    exposure: exposureScanUrl,
  }[activeId] || fullScanUrl;
  const verifiedTargets = useMemo(
    () => (targets || []).filter((target) => target.verification_status === 'verified'),
    [targets]
  );
  const scanUrlHost = normalizeHost(activeScanUrl);
  const selectedVerifiedTarget = verifiedTargets.find((target) => String(target.id) === String(fullScanVerifiedTargetId)) || null;
  const selectedTargetHost = normalizeHost(selectedVerifiedTarget?.normalized_domain || '');
  const selectedTargetMatchesUrl = Boolean(selectedVerifiedTarget && (!scanUrlHost || selectedTargetHost === scanUrlHost));
  const matchingVerifiedTarget = verifiedTargets.find((target) => normalizeHost(target.normalized_domain || '') === scanUrlHost) || null;

  const handleVerifiedTargetChange = (targetId) => {
    setFullScanVerifiedTargetId(targetId);
    if (!targetId) {
      setFullScanEnableActiveChecks(false);
    }
  };

  // Auto-select a verified target when the scan URL matches one the user already owns
  useEffect(() => {
    if (!scanUrlHost || !matchingVerifiedTarget || selectedTargetMatchesUrl) {
      return;
    }
    setFullScanVerifiedTargetId(matchingVerifiedTarget.id);
  }, [matchingVerifiedTarget, scanUrlHost, selectedTargetMatchesUrl, setFullScanVerifiedTargetId]);

  useEffect(() => {
    if (!targetsLoading && fullScanEnableActiveChecks && !selectedTargetMatchesUrl) {
      setFullScanEnableActiveChecks(false);
    }
  }, [fullScanEnableActiveChecks, selectedTargetMatchesUrl, setFullScanEnableActiveChecks, targetsLoading]);

  const renderActiveChecksControl = (label) => (
    <div className="mt-3 rounded-xl p-4" style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border-subtle)' }}>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <label className="flex flex-col gap-1.5">
          <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Verified Target</span>
          <select
            value={fullScanVerifiedTargetId}
            onChange={(e) => handleVerifiedTargetChange(e.target.value)}
            className="input text-sm cursor-pointer"
            disabled={targetsLoading}
          >
            <option value="">{targetsLoading ? 'Loading verified targets...' : 'No verified target selected'}</option>
            {verifiedTargets.map((target) => (
              <option key={target.id} value={target.id}>
                {target.normalized_domain}
              </option>
            ))}
          </select>
        </label>
        <label
          className="flex items-start gap-2 text-xs cursor-pointer rounded-lg px-3 py-2"
          style={{
            color: selectedTargetMatchesUrl ? 'var(--color-text-muted)' : 'var(--color-text-dim)',
            cursor: selectedTargetMatchesUrl ? 'pointer' : 'not-allowed',
            border: '1px solid var(--color-border-subtle)',
            background: 'var(--color-card)',
          }}
        >
          <input
            type="checkbox"
            checked={Boolean(fullScanEnableActiveChecks && selectedTargetMatchesUrl)}
            disabled={!selectedTargetMatchesUrl}
            onChange={(e) => setFullScanEnableActiveChecks(e.target.checked)}
            style={{ marginTop: 2 }}
          />
          <span>
            {label}
            {selectedTargetMatchesUrl ? (
              <span className="block mt-1 font-mono" style={{ color: 'var(--color-secure)' }}>
                Authorized for {selectedVerifiedTarget.normalized_domain}
              </span>
            ) : (
              <span className="block mt-1" style={{ color: 'var(--color-text-dim)' }}>
                Select the verified target that matches this URL before enabling active checks.
              </span>
            )}
          </span>
        </label>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen" style={{ background: 'var(--color-bg)' }}>

      {/* Page header */}
      <div className="page-header px-6 lg:px-10 py-4">
        <h1 className="text-base font-bold" style={{ color: 'var(--color-text)', letterSpacing: '-0.025em' }}>Security Scanners</h1>
        <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>Run targeted vulnerability checks on any URL</p>
      </div>

      <div className="px-6 lg:px-10 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-6 items-start">

          {/* Left: scanner picker */}
          <div className="lg:sticky lg:top-20 overflow-hidden"
            style={{ border: '1px solid var(--color-border)', background: 'var(--color-card)' }}>
            {SCANNERS.map((s, i) => {
              const isActive = s.id === activeId;
              return (
                <button key={s.id} onClick={() => setActiveId(s.id)}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    width: '100%', textAlign: 'left', cursor: 'pointer',
                    padding: '10px 14px',
                    borderTop: 'none', borderRight: 'none', borderBottom: i < SCANNERS.length - 1 ? '1px solid var(--color-border)' : 'none',
                    borderLeft: `2px solid ${isActive ? s.color : 'transparent'}`,
                    background: isActive ? 'var(--color-elevated)' : 'transparent',
                    transition: 'background 100ms ease, border-color 100ms ease',
                  }}
                  onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = 'var(--color-surface)'; }}
                  onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent'; }}
                >
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                      <span style={{
                        fontSize: 11, fontWeight: isActive ? 600 : 500,
                        color: isActive ? 'var(--color-text)' : 'var(--color-text-muted)',
                        fontFamily: "var(--font-mono)",
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }}>{s.title}</span>
                      {s.badge && (
                        <span style={{
                          fontSize: 9, padding: '1px 5px', fontWeight: 700, letterSpacing: '0.06em',
                          textTransform: 'uppercase', fontFamily: "var(--font-mono)", flexShrink: 0,
                          background: isActive ? `${s.color}18` : 'var(--color-primary-dim)',
                          color: isActive ? s.color : 'var(--color-primary)',
                        }}>
                          {s.badge}
                        </span>
                      )}
                    </div>
                    <p style={{ fontSize: 10, marginTop: 2, color: 'var(--color-text-dim)', fontFamily: "var(--font-mono)" }}>{s.subtitle}</p>
                  </div>
                  <ChevronRight size={10} style={{ color: isActive ? s.color : 'var(--color-text-dim)', flexShrink: 0, marginLeft: 8 }} />
                </button>
              );
            })}
          </div>

          {/* ── Right: active scanner panel ── */}
          <div className="flex flex-col gap-5">

            {/* Scanner description header */}
            <div style={{ borderLeft: `3px solid ${active.color}`, paddingLeft: 16, paddingTop: 4, paddingBottom: 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <h2 style={{ fontSize: 15, fontWeight: 700, color: 'var(--color-text)', fontFamily: "var(--font-display)", letterSpacing: '-0.02em', margin: 0 }}>{active.title}</h2>
                {active.badge && (
                  <span style={{
                    fontSize: 9, padding: '2px 6px', fontWeight: 700, letterSpacing: '0.08em',
                    textTransform: 'uppercase', fontFamily: "var(--font-mono)",
                    background: `${active.color}18`, color: active.color,
                  }}>
                    {active.badge}
                  </span>
                )}
              </div>
              <p style={{ fontSize: 12, marginTop: 4, color: 'var(--color-text-muted)', lineHeight: 1.6 }}>{active.desc}</p>
            </div>

            {/* ── FULL SCAN ── */}
            {activeId === 'full' && (
              <div className="card overflow-hidden">
                <div className="px-5 py-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="section-label mb-3">Target URL</p>
                  <ScanInput url={fullScanUrl} setUrl={setFullScanUrl} onScan={handleFullScan} isScanning={isFullScanSubmitting} />
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
                    <label className="flex flex-col gap-1.5">
                      <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Scan Profile</span>
                      <select value={fullScanProfile} onChange={(e) => setFullScanProfile(e.target.value)} className="input text-sm cursor-pointer">
                        <option value="security_only">Security Scan</option>
                        <option value="product_readiness">Product Readiness Scan</option>
                        <option value="full_launch_audit">Full Launch Audit</option>
                      </select>
                    </label>
                  </div>
                  {renderActiveChecksControl('Enable active ZAP, Nikto, SQLMap, SSRF, and ownership-gated probes')}
                  {fullScanProfile !== 'security_only' && (
                    <div className="mt-3 flex flex-col gap-3">
                      <label className="flex flex-col gap-1.5">
                        <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Page Paths</span>
                        <textarea value={fullScanPagePaths} onChange={(e) => setFullScanPagePaths(e.target.value)}
                          rows={4} placeholder={"/\n/signup\n/pricing"}
                          className="input text-sm font-mono" style={{ resize: 'vertical' }} />
                      </label>
                      <label className="flex items-center gap-2 text-xs cursor-pointer" style={{ color: 'var(--color-text-muted)' }}>
                        <input type="checkbox" checked={fullScanEnableAiReview} onChange={(e) => setFullScanEnableAiReview(e.target.checked)} />
                        Enable AI visual review when configured
                      </label>
                      <div className="rounded-xl p-4" style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border-subtle)' }}>
                        <p className="text-xs font-semibold" style={{ color: 'var(--color-text)' }}>Pre-production auth and abuse-control inputs</p>
                        {fullScanEnableActiveChecks && selectedTargetMatchesUrl ? (
                          <div className="grid grid-cols-1 md:grid-cols-[1fr_140px] gap-3 mt-3">
                            <label className="flex flex-col gap-1.5">
                              <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Auth/API Paths</span>
                              <textarea value={fullScanActiveCheckPaths} onChange={(e) => setFullScanActiveCheckPaths(e.target.value)}
                                rows={4} placeholder={"POST /login\nPOST /signup\nPOST /forgot-password\nGET /admin"}
                                className="input text-sm font-mono" style={{ resize: 'vertical' }} />
                              <span className="text-[11px]" style={{ color: 'var(--color-text-dim)' }}>
                                Leave blank to discover common auth and admin routes automatically.
                              </span>
                            </label>
                            <label className="flex flex-col gap-1.5">
                              <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Request Budget</span>
                              <input type="number" min="3" max="20" value={fullScanActiveCheckBudget}
                                onChange={(e) => setFullScanActiveCheckBudget(e.target.value)}
                                className="input text-sm font-mono" />
                            </label>
                            <label className="flex flex-col gap-1.5 md:col-span-2">
                              <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Staging Test Accounts</span>
                              <textarea value={fullScanAuthAccounts} onChange={(e) => setFullScanAuthAccounts(e.target.value)}
                                rows={3} placeholder={"user1@example.com|Password123!|user\nadmin@example.com|Password123!|admin"}
                                className="input text-sm font-mono" style={{ resize: 'vertical' }} />
                            </label>
                            <label className="flex flex-col gap-1.5">
                              <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Protected Paths</span>
                              <textarea value={fullScanProtectedPaths} onChange={(e) => setFullScanProtectedPaths(e.target.value)}
                                rows={3} placeholder={"/dashboard\n/account\n/admin"}
                                className="input text-sm font-mono" style={{ resize: 'vertical' }} />
                            </label>
                            <label className="flex flex-col gap-1.5">
                              <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>IDOR Path Templates</span>
                              <textarea value={fullScanIdorPaths} onChange={(e) => setFullScanIdorPaths(e.target.value)}
                                rows={3} placeholder={"/api/users/123\n/api/projects/abc"}
                                className="input text-sm font-mono" style={{ resize: 'vertical' }} />
                            </label>
                          </div>
                        ) : (
                          <p className="text-xs mt-2" style={{ color: 'var(--color-text-dim)' }}>
                            Enable active checks above to include auth and abuse-control probes.
                          </p>
                        )}
                      </div>
                    </div>
                  )}
                  {fullScanError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: 'var(--color-danger)' }}>
                      <AlertTriangle size={11} /> {fullScanError}
                    </p>
                  )}
                </div>
                <div className="px-5 py-4">
                  {fullScanJob ? (
                    <FullScanStatus job={fullScanJob} navigateTo={navigateTo} />
                  ) : (
                    <p className="text-xs text-center py-6" style={{ color: 'var(--color-text-dim)' }}>
                      Submit a URL above to queue a security scan, product-readiness scan, or full launch audit
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* ── SQL SCAN ── */}
            {activeId === 'sql' && (
              <div className="card overflow-hidden">
                <div className="px-5 py-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="section-label mb-3">Target URL</p>
                  <ScanInput url={sqlScanUrl} setUrl={setSqlScanUrl} onScan={handleSqlScan} isScanning={isSqlScanning} />
                  {renderActiveChecksControl('Enable SQLMap active SQL injection probes')}
                  {sqlError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: 'var(--color-danger)' }}>
                      <AlertTriangle size={11} /> {sqlError}
                    </p>
                  )}
                </div>
                {sqlScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{sqlScanResult.url}</p>
                      <VulnBadge vulnerable={sqlScanResult.vulnerable} label={sqlScanResult.vulnerable ? 'Vulnerable' : 'Secure'} />
                    </div>
                    {sqlScanResult.vulnerable ? (
                      <>
                        <p className="text-xs font-semibold" style={{ color: 'var(--color-danger)' }}>
                          {sqlScanResult.findings.length} injection {sqlScanResult.findings.length === 1 ? 'vector' : 'vectors'} found
                        </p>
                        <div className="flex flex-col gap-2">
                          {sqlScanResult.findings.map((f, i) => (
                            <FindingItem key={i} color={T.danger} bg="#F43F5E08" icon={AlertTriangle}
                              title={f.type} meta={`Parameter: ${f.parameter} · Severity: ${f.severity}`} />
                          ))}
                        </div>
                        <Recs items={sqlScanResult.recommendations} />
                      </>
                    ) : (
                      <div className="flex items-center gap-3 px-4 py-4 rounded-lg"
                        style={{ background: 'var(--color-secure-dim)', border: '1px solid rgba(34,197,94,0.2)' }}>
                        <CheckCircle size={18} style={{ color: 'var(--color-secure)' }} />
                        <p className="text-sm font-medium" style={{ color: 'var(--color-secure)' }}>No SQL injection vulnerabilities detected</p>
                      </div>
                    )}
                    <div className="flex justify-end">
                      <button onClick={() => sqlScanResult?.scan_id && navigateTo('report', sqlScanResult.scan_id)}
                        className="btn-secondary text-xs">
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isSqlScanning && (
                  <p className="text-xs text-center py-6" style={{ color: 'var(--color-text-dim)' }}>Enter a URL and scan to check for SQL injection</p>
                )}
                {isSqlScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <Spinner size="sm" color={T.danger} />
                    <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Testing injection vectors…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── SSL SCAN ── */}
            {activeId === 'ssl' && (
              <div className="card overflow-hidden">
                <div className="px-5 py-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="section-label mb-3">Target URL</p>
                  <ScanInput url={sslScanUrl} setUrl={setSslScanUrl} onScan={handleSslScan} isScanning={isSslScanning} />
                  {sslError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: 'var(--color-danger)' }}>
                      <AlertTriangle size={11} /> {sslError}
                    </p>
                  )}
                </div>
                {sslScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{sslScanResult.url}</p>
                      <VulnBadge vulnerable={!sslScanResult.findings?.valid} label={sslScanResult.findings?.valid ? 'Valid Certificate' : 'Invalid Certificate'} />
                    </div>
                    {sslScanResult.findings?.valid ? (
                      <>
                        {sslScanResult.findings.expires && (
                          <div className="grid grid-cols-2 gap-3">
                            {[
                              { label: 'Expires', val: fmt(sslScanResult.findings.expires) },
                              { label: 'Protocol', val: sslScanResult.findings.protocol },
                            ].map(({ label, val }) => (
                              <div key={label} className="p-3 rounded-lg" style={{ background: 'var(--color-surface)' }}>
                                <p className="text-xs mb-1" style={{ color: 'var(--color-text-dim)' }}>{label}</p>
                                <p className="text-xs font-semibold font-mono" style={{ color: 'var(--color-text)' }}>{val}</p>
                              </div>
                            ))}
                          </div>
                        )}
                        <FindingItem color={T.secure} bg="#10B98108" icon={CheckCircle}
                          title="Secure Connection" meta={`Self-signed: ${sslScanResult.findings.self_signed ? 'Yes' : 'No'}`} />
                      </>
                    ) : (
                      <>
                        <FindingItem color={T.warn} bg="#F59E0B08" icon={AlertTriangle}
                          title="Certificate Issue" meta={sslScanResult.findings?.error} />
                        {sslScanResult.recommendations?.length > 0 && <Recs items={sslScanResult.recommendations} />}
                      </>
                    )}
                    <div className="flex justify-end">
                      <button onClick={() => sslScanResult?.scan_id && navigateTo('report', sslScanResult.scan_id)}
                        className="btn-secondary text-xs">
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isSslScanning && (
                  <p className="text-xs text-center py-6" style={{ color: 'var(--color-text-dim)' }}>Enter a URL and scan to check SSL/TLS configuration</p>
                )}
                {isSslScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <Spinner size="sm" color={T.secure} />
                    <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Verifying certificate chain…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── WORDPRESS SCAN ── */}
            {activeId === 'wordpress' && (
              <div className="card overflow-hidden">
                <div className="px-5 py-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="section-label mb-3">Target URL</p>
                  <ScanInput url={wordpressScanUrl} setUrl={setWordpressScanUrl} onScan={handleWordpressScan} isScanning={isWordpressScanning} />
                  {renderActiveChecksControl('Enable WPScan active WordPress probes')}
                  {wordpressError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: 'var(--color-danger)' }}>
                      <AlertTriangle size={11} /> {wordpressError}
                    </p>
                  )}
                </div>
                {wordpressScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{wordpressScanResult.url}</p>
                      <VulnBadge
                        vulnerable={(wordpressScanResult.summary?.wordpress_issue_count || 0) > 0}
                        label={(wordpressScanResult.summary?.wordpress_issue_count || 0) > 0 ? 'Issues Found' : 'No Issues'} />
                    </div>
                    {!wordpressScanResult.findings?.is_wordpress ? (
                      <div className="flex items-center gap-3 px-4 py-4 rounded-lg"
                        style={{ background: 'var(--color-info-dim)', border: '1px solid rgba(56,189,248,0.2)' }}>
                        <Globe size={16} style={{ color: 'var(--color-info)' }} />
                        <p className="text-sm" style={{ color: 'var(--color-info)' }}>Not a WordPress site — no CMS signatures detected.</p>
                      </div>
                    ) : (
                      <>
                        <div className="grid grid-cols-3 gap-3">
                          {[
                            { label: 'Core', val: wordpressScanResult.findings.version?.detected || 'Hidden', sub: `Latest: ${wordpressScanResult.findings.version?.latest || '?'}` },
                            { label: 'Plugins', val: wordpressScanResult.findings.plugins?.length || 0, sub: `${(wordpressScanResult.findings.plugins || []).filter(p => p.outdated).length} outdated` },
                            { label: 'Themes', val: wordpressScanResult.findings.themes?.length || 0, sub: 'detected' },
                          ].map((item, i) => (
                            <div key={i} className="p-3 rounded-lg" style={{ background: 'var(--color-surface)' }}>
                              <p className="text-xs mb-1" style={{ color: 'var(--color-text-dim)' }}>{item.label}</p>
                              <p className="text-sm font-bold font-mono" style={{ color: 'var(--color-text)' }}>{item.val}</p>
                              <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>{item.sub}</p>
                            </div>
                          ))}
                        </div>
                        {(wordpressScanResult.findings.issues || []).length > 0 ? (
                          <div className="flex flex-col gap-2">
                            {wordpressScanResult.findings.issues.map((issue, i) => (
                              <FindingItem key={i} color={T.warn} bg="#F59E0B08" icon={AlertTriangle}
                                title={issue.name} meta={`Severity: ${issue.severity} · ${issue.evidence}`} />
                            ))}
                          </div>
                        ) : (
                          <FindingItem color={T.secure} bg="#10B98108" icon={CheckCircle}
                            title="No WordPress hardening issues detected" />
                        )}
                        {(wordpressScanResult.findings.plugins || []).length > 0 && (
                          <div className="rounded-lg p-3" style={{ background: 'var(--color-surface)' }}>
                            <p className="text-xs font-semibold mb-2" style={{ color: 'var(--color-text-muted)' }}>Detected Plugins</p>
                            <div className="flex flex-col gap-1.5">
                              {wordpressScanResult.findings.plugins.slice(0, 8).map((p, i) => (
                                <div key={i} className="flex items-center justify-between text-xs">
                                  <span className="font-mono" style={{ color: 'var(--color-text)' }}>
                                    {p.name || p.slug}{p.version && ` v${p.version}`}
                                  </span>
                                  <span className="badge"
                                    style={p.outdated
                                      ? { background: 'var(--color-danger-dim)', color: 'var(--color-danger)' }
                                      : { background: 'var(--color-secure-dim)', color: 'var(--color-secure)' }}>
                                    {p.outdated ? 'Outdated' : 'OK'}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                        {wordpressScanResult.recommendations?.length > 0 && <Recs items={wordpressScanResult.recommendations} />}
                      </>
                    )}
                    <div className="flex justify-end">
                      <button onClick={() => wordpressScanResult?.scan_id && navigateTo('report', wordpressScanResult.scan_id)}
                        className="btn-secondary text-xs">
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isWordpressScanning && (
                  <p className="text-xs text-center py-6" style={{ color: 'var(--color-text-dim)' }}>Enter a WordPress site URL to start CMS security analysis</p>
                )}
                {isWordpressScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <Spinner size="sm" color={T.warn} />
                    <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Probing WordPress installation…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── XSS SCAN ── */}
            {activeId === 'xss' && (
              <div className="card overflow-hidden">
                <div className="px-5 py-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="section-label mb-3">Target URL</p>
                  <ScanInput url={xssScanUrl} setUrl={setXssScanUrl} onScan={handleXssScan} isScanning={isXssScanning} />
                  {xssError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: 'var(--color-danger)' }}>
                      <AlertTriangle size={11} /> {xssError}
                    </p>
                  )}
                </div>
                {xssScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{xssScanResult.url}</p>
                      <VulnBadge vulnerable={xssScanResult.vulnerable} label={xssScanResult.vulnerable ? 'Vulnerable' : 'Secure'} />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      {[
                        { label: 'Reflected XSS', val: xssScanResult.findings.reflected_xss_count ?? 0 },
                        { label: 'CSP Present', val: xssScanResult.findings.csp_present ? 'Yes' : 'No' },
                      ].map(({ label, val }) => (
                        <div key={label} className="p-3 rounded-lg" style={{ background: 'var(--color-surface)' }}>
                          <p className="text-xs mb-1" style={{ color: 'var(--color-text-dim)' }}>{label}</p>
                          <p className="text-sm font-bold font-mono" style={{ color: 'var(--color-text)' }}>{val}</p>
                        </div>
                      ))}
                    </div>
                    {(xssScanResult.findings.issues || []).length > 0 ? (
                      <div className="flex flex-col gap-2">
                        {xssScanResult.findings.issues.map((issue, i) => (
                          <FindingItem key={i}
                            color={issue.severity === 'High' ? T.danger : issue.severity === 'Medium' ? T.warn : T.info}
                            bg={issue.severity === 'High' ? '#F43F5E08' : issue.severity === 'Medium' ? '#F59E0B08' : `${T.info}08`}
                            icon={AlertTriangle}
                            title={issue.type || issue.name}
                            meta={[issue.vector, issue.parameter && `Param: ${issue.parameter}`, issue.severity && `Severity: ${issue.severity}`].filter(Boolean).join(' · ')}
                          />
                        ))}
                      </div>
                    ) : (
                      <div className="flex items-center gap-3 px-4 py-4 rounded-lg"
                        style={{ background: 'var(--color-secure-dim)', border: '1px solid rgba(34,197,94,0.2)' }}>
                        <CheckCircle size={18} style={{ color: 'var(--color-secure)' }} />
                        <p className="text-sm font-medium" style={{ color: 'var(--color-secure)' }}>No reflected XSS found in tested parameters</p>
                      </div>
                    )}
                    {xssScanResult.recommendations?.length > 0 && <Recs items={xssScanResult.recommendations} />}
                    <div className="flex justify-end">
                      <button onClick={() => xssScanResult?.scan_id && navigateTo('report', xssScanResult.scan_id)}
                        className="btn-secondary text-xs">
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isXssScanning && (
                  <p className="text-xs text-center py-6" style={{ color: 'var(--color-text-dim)' }}>Enter a URL to test for cross-site scripting vulnerabilities</p>
                )}
                {isXssScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <Spinner size="sm" color={T.purple} />
                    <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Injecting XSS payloads into parameters and forms…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── TECH FINGERPRINT ── */}
            {activeId === 'tech' && (
              <div className="card overflow-hidden">
                <div className="px-5 py-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="section-label mb-3">Target URL</p>
                  <ScanInput url={techScanUrl} setUrl={setTechScanUrl} onScan={handleTechScan} isScanning={isTechScanning} />
                  {techError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: 'var(--color-danger)' }}>
                      <AlertTriangle size={11} /> {techError}
                    </p>
                  )}
                </div>
                {techScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{techScanResult.url}</p>
                      <VulnBadge
                        vulnerable={(techScanResult.findings.issues || []).some(i => i.severity !== 'Info')}
                        label={(techScanResult.findings.issues || []).some(i => i.severity !== 'Info') ? 'Issues Found' : 'Clean'} />
                    </div>
                    {Object.keys(techScanResult.technologies || {}).length > 0 ? (
                      <div className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--color-border)' }}>
                        <div className="px-3 py-2" style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)' }}>
                          <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)' }}>Detected Stack</p>
                        </div>
                        <div>
                          {Object.entries(techScanResult.technologies).map(([category, techs], idx, arr) => (
                            <div key={category} className="flex items-start gap-3 px-3 py-2.5"
                              style={{ borderBottom: idx < arr.length - 1 ? '1px solid var(--color-border)' : 'none' }}>
                              <p className="text-xs w-32 flex-shrink-0 font-medium capitalize" style={{ color: 'var(--color-text-dim)' }}>
                                {category.replace(/-/g, ' ')}
                              </p>
                              <div className="flex flex-wrap gap-1.5">
                                {(Array.isArray(techs) ? techs : [techs]).map((t, i) => {
                                  const version = techScanResult.versions?.[t];
                                  return (
                                    <span key={i} className="badge"
                                      style={{ background: 'var(--color-info-dim)', color: 'var(--color-info)' }}>
                                      {t}{version && <span style={{ color: 'var(--color-text-dim)', fontSize: '10px' }}>v{version}</span>}
                                    </span>
                                  );
                                })}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <p className="text-xs text-center py-3" style={{ color: 'var(--color-text-dim)' }}>No technology signatures detected</p>
                    )}
                    {(techScanResult.findings.packages || []).length > 0 && (
                      <div className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--color-border)' }}>
                        <div className="px-3 py-2" style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)' }}>
                          <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)' }}>Detected Packages</p>
                        </div>
                        <div>
                          {(techScanResult.findings.packages || []).map((pkg, idx, arr) => (
                            <div key={`${pkg.name}-${pkg.version}`} className="flex items-center justify-between gap-3 px-3 py-2.5"
                              style={{ borderBottom: idx < arr.length - 1 ? '1px solid var(--color-border)' : 'none' }}>
                              <div className="min-w-0">
                                <p className="text-xs font-mono" style={{ color: 'var(--color-text)' }}>{pkg.name}</p>
                                <p className="text-[11px]" style={{ color: 'var(--color-text-dim)' }}>{pkg.source}</p>
                              </div>
                              <span className="badge" style={{ background: 'var(--color-primary-dim)', color: 'var(--color-primary)' }}>
                                {pkg.version}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {(techScanResult.findings.advisories || []).length > 0 && (
                      <div className="flex flex-col gap-2">
                        <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)' }}>Known CVEs / CWEs</p>
                        {techScanResult.findings.advisories.map((advisory, i) => (
                          <FindingItem key={`${advisory.package}-${advisory.id}-${i}`}
                            color={advisory.severity === 'Critical' || advisory.severity === 'High' ? T.danger : T.warn}
                            bg={advisory.severity === 'Critical' || advisory.severity === 'High' ? '#F43F5E08' : '#F59E0B08'}
                            icon={AlertTriangle}
                            title={`${advisory.package}@${advisory.version}`}
                            meta={[
                              (advisory.cves || []).join(', ') || advisory.id,
                              (advisory.cwes || []).join(', ') || 'CWE not published',
                              advisory.summary,
                              advisory.fixed_versions?.length ? `Fixed in ${advisory.fixed_versions.join(', ')}` : null,
                            ].filter(Boolean).join(' • ')}
                          />
                        ))}
                      </div>
                    )}
                    {(techScanResult.findings.issues || []).length > 0 && (
                      <div className="flex flex-col gap-2">
                        {techScanResult.findings.issues.map((issue, i) => (
                          <FindingItem key={i}
                            color={issue.severity === 'Low' ? T.warn : T.info}
                            bg={issue.severity === 'Low' ? '#F59E0B08' : `${T.info}08`}
                            icon={issue.severity === 'Info' ? Layers : AlertTriangle}
                            title={issue.name}
                            meta={issue.evidence}
                          />
                        ))}
                      </div>
                    )}
                    {techScanResult.recommendations?.length > 0 && <Recs items={techScanResult.recommendations} />}
                    <div className="flex justify-end">
                      <button onClick={() => techScanResult?.scan_id && navigateTo('report', techScanResult.scan_id)}
                        className="btn-secondary text-xs">
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isTechScanning && (
                  <p className="text-xs text-center py-6" style={{ color: 'var(--color-text-dim)' }}>Enter a URL to fingerprint the technology stack</p>
                )}
                {isTechScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <Spinner size="sm" color={T.info} />
                    <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Fingerprinting technology stack…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── EXPOSURE SCAN ── */}
            {activeId === 'exposure' && (
              <div className="card overflow-hidden">
                <div className="px-5 py-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="section-label mb-3">Target URL</p>
                  <ScanInput url={exposureScanUrl} setUrl={setExposureScanUrl} onScan={handleExposureScan} isScanning={isExposureScanning} />
                  {renderActiveChecksControl('Enable ffuf active file and directory discovery')}
                  {exposureError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: 'var(--color-warn)' }}>
                      <AlertTriangle size={11} /> {exposureError}
                    </p>
                  )}
                </div>
                {exposureScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{exposureScanResult.url}</p>
                      <VulnBadge vulnerable={exposureScanResult.vulnerable} label={exposureScanResult.vulnerable ? 'Exposed' : 'Clean'} />
                    </div>
                    {(() => {
                      const issues = exposureScanResult.findings.issues || [];
                      const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
                      issues.forEach(i => { if (counts[i.severity] !== undefined) counts[i.severity]++; });
                      return (
                        <div className="grid grid-cols-4 gap-2">
                          {[
                            { label: 'Critical', count: counts.Critical, color: T.danger },
                            { label: 'High',     count: counts.High,     color: T.warn },
                            { label: 'Medium',   count: counts.Medium,   color: T.info },
                            { label: 'Low',      count: counts.Low,      color: T.muted },
                          ].map(({ label, count, color }) => (
                            <div key={label} className="p-2 rounded-lg text-center" style={{ background: 'var(--color-surface)' }}>
                              <p className="text-lg font-bold font-mono" style={{ color: count > 0 ? color : 'var(--color-text-dim)' }}>{count}</p>
                              <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>{label}</p>
                            </div>
                          ))}
                        </div>
                      );
                    })()}
                    {(exposureScanResult.findings.issues || []).length > 0 ? (
                      <div className="flex flex-col gap-2">
                        {exposureScanResult.findings.issues.map((issue, i) => {
                          const color = issue.severity === 'Critical' ? T.danger : issue.severity === 'High' ? T.warn : issue.severity === 'Medium' ? T.info : T.muted;
                          const bg = issue.severity === 'Critical' ? '#F43F5E08' : issue.severity === 'High' ? '#F59E0B08' : `${T.info}08`;
                          return (
                            <FindingItem key={i} color={color} bg={bg}
                              icon={issue.severity === 'Critical' ? AlertTriangle : FolderSearch}
                              title={issue.name}
                              meta={`${issue.path} · ${issue.severity}${issue.stack && issue.stack !== 'universal' ? ` · ${issue.stack}` : ''}`}
                            />
                          );
                        })}
                      </div>
                    ) : (
                      <div className="flex items-center gap-3 px-4 py-4 rounded-lg"
                        style={{ background: 'var(--color-secure-dim)', border: '1px solid rgba(34,197,94,0.2)' }}>
                        <CheckCircle size={18} style={{ color: 'var(--color-secure)' }} />
                        <p className="text-sm font-medium" style={{ color: 'var(--color-secure)' }}>No sensitive files exposed at common paths</p>
                      </div>
                    )}
                    {exposureScanResult.recommendations?.length > 0 && <Recs items={exposureScanResult.recommendations} />}
                    <div className="flex justify-end">
                      <button onClick={() => exposureScanResult?.scan_id && navigateTo('report', exposureScanResult.scan_id)}
                        className="btn-secondary text-xs">
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isExposureScanning && (
                  <p className="text-xs text-center py-6" style={{ color: 'var(--color-text-dim)' }}>Enter a URL to probe for exposed sensitive files</p>
                )}
                {isExposureScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <Spinner size="sm" color={T.warn} />
                    <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Probing sensitive file paths across all stacks…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── MALWARE ANALYSIS ── */}
            {activeId === 'malware' && (
              <div className="card overflow-hidden">
                <div className="px-5 py-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
                  <p className="section-label mb-3">Target URL</p>
                  <ScanInput url={malwareScanUrl} setUrl={setMalwareScanUrl} onScan={handleMalwareScan} isScanning={isMalwareScanning} />
                  {malwareError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: 'var(--color-danger)' }}>
                      <AlertTriangle size={11} /> {malwareError}
                    </p>
                  )}
                </div>
                {malwareScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{malwareScanResult.url}</p>
                      <VulnBadge vulnerable={malwareScanResult.vulnerable} label={malwareScanResult.vulnerable ? 'Risk Detected' : 'No Indicators'} />
                    </div>
                    {(malwareScanResult.findings.artifacts || []).length > 0 && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {(malwareScanResult.findings.artifacts || []).slice(0, 4).map((artifact, index) => (
                          <div key={`${artifact.sha256 || index}-${index}`} className="p-3 rounded-lg"
                            style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}>
                            <p className="text-xs font-semibold truncate" style={{ color: 'var(--color-text)' }}>{artifact.artifact_type || 'artifact'}</p>
                            <p className="text-xs mt-1 truncate font-mono" style={{ color: 'var(--color-text-dim)' }}>{artifact.artifact_url}</p>
                            {artifact.sha256 && <p className="text-xs mt-1 truncate font-mono" style={{ color: 'var(--color-text-dim)' }}>{artifact.sha256}</p>}
                          </div>
                        ))}
                      </div>
                    )}
                    {(malwareScanResult.findings.issues || []).length > 0 ? (
                      <div className="flex flex-col gap-2">
                        {(malwareScanResult.findings.issues || []).map((issue, i) => (
                          <FindingItem key={i}
                            color={issue.severity === 'Critical' ? T.danger : T.warn}
                            bg={issue.severity === 'Critical' ? '#F43F5E08' : '#F59E0B08'}
                            icon={AlertTriangle}
                            title={issue.name || issue.title}
                            meta={`${issue.artifact_type || 'artifact'}${issue.artifact_url ? ` · ${issue.artifact_url}` : ''}`}
                          />
                        ))}
                      </div>
                    ) : (
                      <div className="flex items-center gap-3 px-4 py-4 rounded-lg"
                        style={{ background: 'var(--color-secure-dim)', border: '1px solid rgba(34,197,94,0.2)' }}>
                        <CheckCircle size={18} style={{ color: 'var(--color-secure)' }} />
                        <p className="text-sm font-medium" style={{ color: 'var(--color-secure)' }}>No malware indicators detected in discovered same-origin downloads</p>
                      </div>
                    )}
                    {malwareScanResult.recommendations?.length > 0 && <Recs items={malwareScanResult.recommendations} />}
                    <div className="flex justify-end">
                      <button onClick={() => malwareScanResult?.scan_id && navigateTo('report', malwareScanResult.scan_id)}
                        className="btn-secondary text-xs">
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isMalwareScanning && (
                  <p className="text-xs text-center py-6" style={{ color: 'var(--color-text-dim)' }}>Enter a URL to inspect same-origin downloadable artifacts for malware indicators</p>
                )}
                {isMalwareScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <Spinner size="sm" color={T.danger} />
                    <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Discovering and analyzing downloadable artifacts…</p>
                  </div>
                )}
              </div>
            )}

          </div>
        </div>
      </div>
    </div>
  );
};

export default Scanners;
