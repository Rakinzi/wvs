import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  AlertTriangle, Lock, Database,
  RefreshCw, CheckCircle, Search,
  Globe, ArrowRight, Zap, ChevronRight,
  Code2, Layers, FolderSearch
} from 'lucide-react';
import { useScansData } from '../hooks/useScansData';
import { apiJson } from '../lib/api';

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
  primary:     'var(--color-primary)',
  secure:      'var(--color-secure)',
  warn:        'var(--color-warn)',
  danger:      'var(--color-danger)',
  info:        'var(--color-info)',
  purple:      '#A78BFA',
};

const SCANNERS = [
  {
    id: 'full',
    icon: Zap,
    color: T.primary,
    title: 'Full Async Scan',
    subtitle: 'All checks · Async',
    desc: 'Runs SQLi, SSL/TLS, HTTP headers, malicious URL analysis, and optional ZAP alerts in a background job.',
    badge: 'Recommended',
  },
  {
    id: 'sql',
    icon: Database,
    color: T.danger,
    title: 'SQL Injection',
    subtitle: 'Sync · Form params',
    desc: 'Tests URL parameters and form inputs for SQL injection vulnerabilities using multiple payload types.',
  },
  {
    id: 'ssl',
    icon: Lock,
    color: T.secure,
    title: 'SSL / TLS',
    subtitle: 'Sync · Certificate',
    desc: 'Checks certificate validity, expiry, issuer trust, self-signing, and protocol version.',
  },
  {
    id: 'wordpress',
    icon: Globe,
    color: T.warn,
    title: 'WordPress',
    subtitle: 'Sync · CMS hardening',
    desc: 'Detects core version, exposed plugins, XML-RPC, REST user enumeration, and hardening issues.',
  },
  {
    id: 'xss',
    icon: Code2,
    color: T.purple,
    title: 'XSS Scanner',
    subtitle: 'Sync · Reflection & forms',
    desc: 'Tests URL parameters and HTML forms against 36 PortSwigger payloads including SVG, animation events, and WAF bypass vectors.',
    badge: 'New',
  },
  {
    id: 'tech',
    icon: Layers,
    color: T.info,
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
];

const VulnBadge = ({ vulnerable, label }) => (
  <span
    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold"
    style={vulnerable
      ? { background: '#F43F5E15', color: T.danger, border: `1px solid #F43F5E30` }
      : { background: '#10B98115', color: T.secure, border: `1px solid #10B98130` }}
  >
    {vulnerable ? <AlertTriangle size={10} /> : <CheckCircle size={10} />}
    {label}
  </span>
);

const FindingItem = ({ color, bg, icon, title, meta }) => (
  <div className="flex items-start gap-3 p-3 rounded-lg" style={{ background: bg, border: `1px solid ${color}25` }}>
    {React.createElement(icon, { size: 13, className: 'flex-shrink-0 mt-0.5', style: { color } })}
    <div>
      <p className="text-xs font-semibold" style={{ color }}>{title}</p>
      {meta && <p className="text-xs mt-0.5" style={{ color: T.muted }}>{meta}</p>}
    </div>
  </div>
);

const Recs = ({ items }) => (
  <div className="rounded-lg p-3" style={{ background: `${T.info}08`, border: `1px solid ${T.info}20` }}>
    <p className="text-xs font-semibold mb-2" style={{ color: T.info }}>Recommendations</p>
    <ul className="flex flex-col gap-1">
      {items.map((r, i) => (
        <li key={i} className="text-xs flex items-start gap-1.5" style={{ color: T.muted }}>
          <span style={{ color: T.info }}>›</span> {r}
        </li>
      ))}
    </ul>
  </div>
);

const ProgressBar = ({ value, color }) => (
  <div
    className="w-full h-2 rounded-full overflow-hidden"
    style={{ background: `${color}18`, border: `1px solid ${color}20` }}
  >
    <div
      className="h-full transition-all duration-500"
      style={{ width: `${Math.max(0, Math.min(value ?? 0, 100))}%`, background: color }}
    />
  </div>
);

/* Scan URL input + button */
const ScanInput = ({ accentColor, url, setUrl, onScan, isScanning }) => (
  <div className="flex gap-2">
    <div className="relative flex-1">
      <div
        className="absolute left-3 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full"
        style={{ background: isScanning ? T.warn : accentColor }}
      />
      <input
        type="url"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && !isScanning && onScan()}
        placeholder="https://target.example.com"
        className="w-full pl-7 pr-4 py-2.5 rounded-lg text-sm outline-none transition-all duration-150"
        style={{
          background: T.surface,
          border: `1px solid ${T.border}`,
          color: T.text,
          fontFamily: 'IBM Plex Mono, monospace',
          fontSize: '12px',
        }}
      />
    </div>
    <button
      onClick={onScan}
      disabled={isScanning}
      className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold transition-all duration-150 cursor-pointer whitespace-nowrap"
      style={{
        background: isScanning ? T.dim : accentColor,
        color: '#fff',
        opacity: isScanning ? 0.7 : 1,
      }}
    >
      {isScanning ? <><RefreshCw size={13} className="animate-spin" /> Scanning…</> : <><Search size={13} /> Scan</>}
    </button>
  </div>
);

/* Full scan job status */
const FullScanStatus = ({ job, navigateTo, onPoll }) => {
  const timerRef = useRef(null);
  const activeRef = useRef(false);

  useEffect(() => {
    const shouldPoll = job && ['queued', 'running'].includes(job.status);
    if (shouldPoll && !activeRef.current) {
      activeRef.current = true;
      timerRef.current = setInterval(onPoll, 3000);
    } else if (!shouldPoll && activeRef.current) {
      activeRef.current = false;
      clearInterval(timerRef.current);
    }
    return () => {
      activeRef.current = false;
      clearInterval(timerRef.current);
    };
  }, [job?.status, onPoll]);

  if (!job) return null;

  const statusColor = job.status === 'completed' ? T.secure : job.status === 'failed' ? T.danger : T.warn;
  const fmt = (d) => new Date(d).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
  const progress = job.progress || null;
  const progressPercent = progress?.percent ?? (job.status === 'completed' ? 100 : 0);
  const progressMessage =
    progress?.message
    || (job.status === 'queued' ? 'Waiting for worker to pick up the job' : null);
  const logs = Array.isArray(progress?.logs) ? progress.logs.slice(-6).reverse() : [];

  return (
    <div className="rounded-xl overflow-hidden mt-4" style={{ border: `1px solid ${T.border}` }}>
      <div className="flex items-center justify-between px-4 py-3" style={{ background: T.surface }}>
        <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>Job Status</p>
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold"
          style={{ background: `${statusColor}15`, color: statusColor }}>
          {['queued','running'].includes(job.status) && <RefreshCw size={10} className="animate-spin" />}
          {job.status}
        </span>
      </div>
      <div className="p-4 flex flex-col gap-2">
        <p className="text-xs" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>{job.url}</p>
        <p className="text-xs" style={{ color: T.dim }}>{job.created_at ? fmt(job.created_at) : 'Pending…'}</p>
        {!['failed'].includes(job.status) && (
          <>
            <div className="mt-1 flex items-center justify-between gap-3">
              <p className="text-xs font-medium" style={{ color: T.text }}>
                {progressMessage || 'Preparing status…'}
              </p>
              <span className="text-xs" style={{ color: statusColor, fontFamily: 'IBM Plex Mono, monospace' }}>
                {progressPercent}%
              </span>
            </div>
            <ProgressBar value={progressPercent} color={statusColor} />
            {progress?.current_step_label && (
              <p className="text-xs" style={{ color: T.dim }}>
                Current step: {progress.current_step_label}
                {progress?.step_index && progress?.total_steps
                  ? ` (${progress.step_index}/${progress.total_steps})`
                  : ''}
              </p>
            )}
          </>
        )}
        {job.status === 'failed' && <p className="text-xs mt-1" style={{ color: T.danger }}>{job.error_message || 'Scan failed'}</p>}
        {logs.length > 0 && (
          <div className="mt-2 rounded-lg p-3 flex flex-col gap-2" style={{ background: T.surface, border: `1px solid ${T.border}` }}>
            <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>
              Activity
            </p>
            {logs.map((entry, index) => (
              <div key={`${entry.timestamp || index}-${entry.message || index}`} className="flex items-start gap-2">
                <span className="mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: statusColor }} />
                <div className="min-w-0">
                  <p className="text-xs" style={{ color: T.text }}>{entry.message}</p>
                  {entry.timestamp && (
                    <p className="text-xs" style={{ color: T.dim, fontFamily: 'IBM Plex Mono, monospace' }}>
                      {new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
        {job.status === 'completed' && job.result_id ? (
          <button
            onClick={() => navigateTo('report', job.result_id)}
            className="mt-1 flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold cursor-pointer"
            style={{ background: T.primary, color: '#fff' }}
          >
            View Report <ArrowRight size={13} />
          </button>
        ) : !['completed','failed'].includes(job.status) && (
          <p className="text-xs mt-1" style={{ color: T.dim }}>Processing in background — auto-refreshing every 3s</p>
        )}
      </div>
    </div>
  );
};

/* ════════════════════════════════════════════════ */
const Scanners = ({ navigateTo }) => {
  const [activeId, setActiveId] = useState('full');

  const {
    fullScanUrl, setFullScanUrl, sqlScanUrl, setSqlScanUrl,
    sslScanUrl, setSslScanUrl, wordpressScanUrl, setWordpressScanUrl,
    xssScanUrl, setXssScanUrl, techScanUrl, setTechScanUrl,
    exposureScanUrl, setExposureScanUrl,
    isFullScanSubmitting, isSqlScanning, isSslScanning, isWordpressScanning,
    isXssScanning, isTechScanning, isExposureScanning,
    fullScanJob, setFullScanJob, sqlScanResult, sslScanResult, wordpressScanResult,
    xssScanResult, techScanResult, exposureScanResult,
    fullScanError, sqlError, sslError, wordpressError, xssError, techError, exposureError,
    handleFullScan, handleSqlScan, handleSslScan, handleWordpressScan,
    handleXssScan, handleTechScan, handleExposureScan,
  } = useScansData();

  useEffect(() => { document.title = 'Scanners — WebVulnScanner'; }, []);

  const fmt = (d) => new Date(d).toLocaleDateString() + ' ' +
    new Date(d).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const pollFullScanJob = useCallback(async () => {
    if (!fullScanJob) return;
    try {
      const { data } = await apiJson(`/scan/jobs/${fullScanJob.id}`, { auth: true });
      if (data.status === 'success') setFullScanJob(data.job);
    } catch { /* ignore */ }
  }, [fullScanJob, setFullScanJob]);

  const active = SCANNERS.find(s => s.id === activeId);

  return (
    <div className="min-h-screen" style={{ background: T.bg }}>

      {/* ── Page header ── */}
      <div
        className="sticky top-0 z-10 px-6 lg:px-10 py-4"
        style={{ background: `${T.surface}E8`, borderBottom: `1px solid ${T.border}`, backdropFilter: 'blur(12px)' }}
      >
        <h1 className="text-lg font-semibold tracking-tight" style={{ color: T.text }}>Security Scanners</h1>
        <p className="text-xs mt-0.5" style={{ color: T.dim }}>Run targeted vulnerability checks on any URL</p>
      </div>

      <div className="px-6 lg:px-10 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-6 items-start">

          {/* ── Left: scanner picker ── */}
          <div className="lg:sticky lg:top-24 flex flex-col gap-2">
            {SCANNERS.map((s) => {
              const Icon = s.icon;
              const active = s.id === activeId;
              return (
                <button
                  key={s.id}
                  onClick={() => setActiveId(s.id)}
                  className="flex items-center gap-3 p-4 rounded-xl text-left transition-all duration-150 cursor-pointer w-full"
                  style={{
                    background: active ? T.elev : T.card,
                    border: `1px solid ${active ? s.color + '50' : T.border}`,
                  }}
                >
                  <div
                    className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{ background: active ? `${s.color}20` : `${s.color}10` }}
                  >
                    <Icon size={16} style={{ color: s.color }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold truncate" style={{ color: active ? T.text : T.muted }}>{s.title}</p>
                      {s.badge && (
                        <span className="text-xs px-1.5 py-0.5 rounded font-medium flex-shrink-0"
                          style={{ background: `${T.primary}20`, color: T.primary }}>
                          {s.badge}
                        </span>
                      )}
                    </div>
                    <p className="text-xs mt-0.5" style={{ color: T.dim, fontFamily: 'IBM Plex Mono, monospace' }}>{s.subtitle}</p>
                  </div>
                  <ChevronRight size={14} style={{ color: active ? s.color : T.dim, flexShrink: 0 }} />
                </button>
              );
            })}
          </div>

          {/* ── Right: active scanner panel ── */}
          <div className="flex flex-col gap-5">

            {/* Scanner description header */}
            <div
              className="rounded-xl p-5 flex items-start gap-4"
              style={{ background: T.card, border: `1px solid ${T.border}` }}
            >
              <div
                className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
                style={{ background: `${active.color}18`, border: `1px solid ${active.color}30` }}
              >
                <active.icon size={22} style={{ color: active.color }} />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-base font-bold" style={{ color: T.text }}>{active.title}</h2>
                  {active.badge && (
                    <span className="text-xs px-2 py-0.5 rounded font-medium"
                      style={{ background: `${T.primary}20`, color: T.primary }}>
                      {active.badge}
                    </span>
                  )}
                </div>
                <p className="text-xs mt-1 leading-relaxed" style={{ color: T.muted }}>{active.desc}</p>
              </div>
            </div>

            {/* ── FULL SCAN ── */}
            {activeId === 'full' && (
              <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
                <div className="px-5 py-4" style={{ borderBottom: `1px solid ${T.border}` }}>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>Target URL</p>
                  <ScanInput accentColor={T.primary} url={fullScanUrl} setUrl={setFullScanUrl} onScan={handleFullScan} isScanning={isFullScanSubmitting} />
                  {fullScanError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: T.danger }}>
                      <AlertTriangle size={11} /> {fullScanError}
                    </p>
                  )}
                </div>
                <div className="px-5 py-4">
                  {fullScanJob ? (
                    <FullScanStatus job={fullScanJob} navigateTo={navigateTo} onPoll={pollFullScanJob} />
                  ) : (
                    <p className="text-xs text-center py-6" style={{ color: T.dim }}>
                      Submit a URL above to queue a full async scan
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* ── SQL SCAN ── */}
            {activeId === 'sql' && (
              <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
                <div className="px-5 py-4" style={{ borderBottom: `1px solid ${T.border}` }}>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>Target URL</p>
                  <ScanInput accentColor={T.danger} url={sqlScanUrl} setUrl={setSqlScanUrl} onScan={handleSqlScan} isScanning={isSqlScanning} />
                  {sqlError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: T.danger }}>
                      <AlertTriangle size={11} /> {sqlError}
                    </p>
                  )}
                </div>
                {sqlScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>{sqlScanResult.url}</p>
                      <VulnBadge vulnerable={sqlScanResult.vulnerable} label={sqlScanResult.vulnerable ? 'Vulnerable' : 'Secure'} />
                    </div>
                    {sqlScanResult.vulnerable ? (
                      <>
                        <p className="text-xs font-semibold" style={{ color: T.danger }}>
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
                      <div className="flex items-center gap-3 px-4 py-4 rounded-lg" style={{ background: '#10B98108', border: '1px solid #10B98120' }}>
                        <CheckCircle size={18} style={{ color: T.secure }} />
                        <p className="text-sm font-medium" style={{ color: T.secure }}>No SQL injection vulnerabilities detected</p>
                      </div>
                    )}
                    <div className="flex justify-end">
                      <button onClick={() => sqlScanResult?.scan_id && navigateTo('report', sqlScanResult.scan_id)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer"
                        style={{ background: T.surface, color: T.primary, border: `1px solid ${T.border}` }}>
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isSqlScanning && (
                  <p className="text-xs text-center py-6" style={{ color: T.dim }}>Enter a URL and scan to check for SQL injection</p>
                )}
                {isSqlScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <div className="w-4 h-4 border-2 rounded-full animate-spin" style={{ borderColor: `${T.danger}30`, borderTopColor: T.danger }} />
                    <p className="text-sm" style={{ color: T.muted }}>Testing injection vectors…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── SSL SCAN ── */}
            {activeId === 'ssl' && (
              <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
                <div className="px-5 py-4" style={{ borderBottom: `1px solid ${T.border}` }}>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>Target URL</p>
                  <ScanInput accentColor={T.secure} url={sslScanUrl} setUrl={setSslScanUrl} onScan={handleSslScan} isScanning={isSslScanning} />
                  {sslError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: T.danger }}>
                      <AlertTriangle size={11} /> {sslError}
                    </p>
                  )}
                </div>
                {sslScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>{sslScanResult.url}</p>
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
                              <div key={label} className="p-3 rounded-lg" style={{ background: T.surface }}>
                                <p className="text-xs mb-1" style={{ color: T.dim }}>{label}</p>
                                <p className="text-xs font-semibold" style={{ color: T.text, fontFamily: 'IBM Plex Mono, monospace' }}>{val}</p>
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
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer"
                        style={{ background: T.surface, color: T.primary, border: `1px solid ${T.border}` }}>
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isSslScanning && (
                  <p className="text-xs text-center py-6" style={{ color: T.dim }}>Enter a URL and scan to check SSL/TLS configuration</p>
                )}
                {isSslScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <div className="w-4 h-4 border-2 rounded-full animate-spin" style={{ borderColor: `${T.secure}30`, borderTopColor: T.secure }} />
                    <p className="text-sm" style={{ color: T.muted }}>Verifying certificate chain…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── WORDPRESS SCAN ── */}
            {activeId === 'wordpress' && (
              <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
                <div className="px-5 py-4" style={{ borderBottom: `1px solid ${T.border}` }}>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>Target URL</p>
                  <ScanInput accentColor={T.warn} url={wordpressScanUrl} setUrl={setWordpressScanUrl} onScan={handleWordpressScan} isScanning={isWordpressScanning} />
                  {wordpressError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: T.danger }}>
                      <AlertTriangle size={11} /> {wordpressError}
                    </p>
                  )}
                </div>
                {wordpressScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>{wordpressScanResult.url}</p>
                      <VulnBadge
                        vulnerable={(wordpressScanResult.summary?.wordpress_issue_count || 0) > 0}
                        label={(wordpressScanResult.summary?.wordpress_issue_count || 0) > 0 ? 'Issues Found' : 'No Issues'} />
                    </div>
                    {!wordpressScanResult.findings?.is_wordpress ? (
                      <div className="flex items-center gap-3 px-4 py-4 rounded-lg" style={{ background: `${T.info}08`, border: `1px solid ${T.info}20` }}>
                        <Globe size={16} style={{ color: T.info }} />
                        <p className="text-sm" style={{ color: T.info }}>Not a WordPress site — no CMS signatures detected.</p>
                      </div>
                    ) : (
                      <>
                        <div className="grid grid-cols-3 gap-3">
                          {[
                            { label: 'Core', val: wordpressScanResult.findings.version?.detected || 'Hidden', sub: `Latest: ${wordpressScanResult.findings.version?.latest || '?'}` },
                            { label: 'Plugins', val: wordpressScanResult.findings.plugins?.length || 0, sub: `${(wordpressScanResult.findings.plugins || []).filter(p => p.outdated).length} outdated` },
                            { label: 'Themes', val: wordpressScanResult.findings.themes?.length || 0, sub: 'detected' },
                          ].map((item, i) => (
                            <div key={i} className="p-3 rounded-lg" style={{ background: T.surface }}>
                              <p className="text-xs mb-1" style={{ color: T.dim }}>{item.label}</p>
                              <p className="text-sm font-bold" style={{ color: T.text, fontFamily: 'IBM Plex Mono, monospace' }}>{item.val}</p>
                              <p className="text-xs mt-0.5" style={{ color: T.dim }}>{item.sub}</p>
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
                          <div className="rounded-lg p-3" style={{ background: T.surface }}>
                            <p className="text-xs font-semibold mb-2" style={{ color: T.muted }}>Detected Plugins</p>
                            <div className="flex flex-col gap-1.5">
                              {wordpressScanResult.findings.plugins.slice(0, 8).map((p, i) => (
                                <div key={i} className="flex items-center justify-between text-xs">
                                  <span style={{ color: T.text, fontFamily: 'IBM Plex Mono, monospace' }}>
                                    {p.name || p.slug}{p.version && ` v${p.version}`}
                                  </span>
                                  <span className="px-2 py-0.5 rounded font-semibold"
                                    style={p.outdated ? { background: '#F43F5E15', color: T.danger } : { background: '#10B98115', color: T.secure }}>
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
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer"
                        style={{ background: T.surface, color: T.primary, border: `1px solid ${T.border}` }}>
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isWordpressScanning && (
                  <p className="text-xs text-center py-6" style={{ color: T.dim }}>Enter a WordPress site URL to start CMS security analysis</p>
                )}
                {isWordpressScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <div className="w-4 h-4 border-2 rounded-full animate-spin" style={{ borderColor: `${T.warn}30`, borderTopColor: T.warn }} />
                    <p className="text-sm" style={{ color: T.muted }}>Probing WordPress installation…</p>
                  </div>
                )}
              </div>
            )}
            {/* ── XSS SCAN ── */}
            {activeId === 'xss' && (
              <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
                <div className="px-5 py-4" style={{ borderBottom: `1px solid ${T.border}` }}>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>Target URL</p>
                  <ScanInput accentColor={T.purple} url={xssScanUrl} setUrl={setXssScanUrl} onScan={handleXssScan} isScanning={isXssScanning} />
                  {xssError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: T.danger }}>
                      <AlertTriangle size={11} /> {xssError}
                    </p>
                  )}
                </div>
                {xssScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>{xssScanResult.url}</p>
                      <VulnBadge vulnerable={xssScanResult.vulnerable} label={xssScanResult.vulnerable ? 'Vulnerable' : 'Secure'} />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      {[
                        { label: 'Reflected XSS', val: xssScanResult.findings.reflected_xss_count ?? 0 },
                        { label: 'CSP Present', val: xssScanResult.findings.csp_present ? 'Yes' : 'No' },
                      ].map(({ label, val }) => (
                        <div key={label} className="p-3 rounded-lg" style={{ background: T.surface }}>
                          <p className="text-xs mb-1" style={{ color: T.dim }}>{label}</p>
                          <p className="text-sm font-bold" style={{ color: T.text, fontFamily: 'IBM Plex Mono, monospace' }}>{val}</p>
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
                      <div className="flex items-center gap-3 px-4 py-4 rounded-lg" style={{ background: '#10B98108', border: '1px solid #10B98120' }}>
                        <CheckCircle size={18} style={{ color: T.secure }} />
                        <p className="text-sm font-medium" style={{ color: T.secure }}>No reflected XSS found in tested parameters</p>
                      </div>
                    )}
                    {xssScanResult.recommendations?.length > 0 && <Recs items={xssScanResult.recommendations} />}
                    <div className="flex justify-end">
                      <button onClick={() => xssScanResult?.scan_id && navigateTo('report', xssScanResult.scan_id)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer"
                        style={{ background: T.surface, color: T.primary, border: `1px solid ${T.border}` }}>
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isXssScanning && (
                  <p className="text-xs text-center py-6" style={{ color: T.dim }}>Enter a URL to test for cross-site scripting vulnerabilities</p>
                )}
                {isXssScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <div className="w-4 h-4 border-2 rounded-full animate-spin" style={{ borderColor: `${T.purple}30`, borderTopColor: T.purple }} />
                    <p className="text-sm" style={{ color: T.muted }}>Injecting XSS payloads into parameters and forms…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── TECH FINGERPRINT ── */}
            {activeId === 'tech' && (
              <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
                <div className="px-5 py-4" style={{ borderBottom: `1px solid ${T.border}` }}>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>Target URL</p>
                  <ScanInput accentColor={T.info} url={techScanUrl} setUrl={setTechScanUrl} onScan={handleTechScan} isScanning={isTechScanning} />
                  {techError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: T.danger }}>
                      <AlertTriangle size={11} /> {techError}
                    </p>
                  )}
                </div>
                {techScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>{techScanResult.url}</p>
                      <VulnBadge
                        vulnerable={(techScanResult.findings.issues || []).some(i => i.severity !== 'Info')}
                        label={(techScanResult.findings.issues || []).some(i => i.severity !== 'Info') ? 'Issues Found' : 'Clean'} />
                    </div>
                    {Object.keys(techScanResult.technologies || {}).length > 0 ? (
                      <div className="rounded-lg overflow-hidden" style={{ border: `1px solid ${T.border}` }}>
                        <div className="px-3 py-2" style={{ background: T.surface, borderBottom: `1px solid ${T.border}` }}>
                          <p className="text-xs font-semibold" style={{ color: T.muted }}>Detected Stack</p>
                        </div>
                        <div>
                          {Object.entries(techScanResult.technologies).map(([category, techs], idx, arr) => (
                            <div key={category} className="flex items-start gap-3 px-3 py-2.5"
                              style={{ borderBottom: idx < arr.length - 1 ? `1px solid ${T.border}` : 'none' }}>
                              <p className="text-xs w-32 flex-shrink-0 font-medium capitalize" style={{ color: T.dim }}>
                                {category.replace(/-/g, ' ')}
                              </p>
                              <div className="flex flex-wrap gap-1.5">
                                {(Array.isArray(techs) ? techs : [techs]).map((t, i) => {
                                  const version = techScanResult.versions?.[t];
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
                    ) : (
                      <p className="text-xs text-center py-3" style={{ color: T.dim }}>No technology signatures detected</p>
                    )}
                    {(techScanResult.findings.packages || []).length > 0 && (
                      <div className="rounded-lg overflow-hidden" style={{ border: `1px solid ${T.border}` }}>
                        <div className="px-3 py-2" style={{ background: T.surface, borderBottom: `1px solid ${T.border}` }}>
                          <p className="text-xs font-semibold" style={{ color: T.muted }}>Detected Packages</p>
                        </div>
                        <div>
                          {(techScanResult.findings.packages || []).map((pkg, idx, arr) => (
                            <div key={`${pkg.name}-${pkg.version}`} className="flex items-center justify-between gap-3 px-3 py-2.5"
                              style={{ borderBottom: idx < arr.length - 1 ? `1px solid ${T.border}` : 'none' }}>
                              <div className="min-w-0">
                                <p className="text-xs font-mono" style={{ color: T.text }}>{pkg.name}</p>
                                <p className="text-[11px]" style={{ color: T.dim }}>{pkg.source}</p>
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
                    {(techScanResult.findings.advisories || []).length > 0 && (
                      <div className="flex flex-col gap-2">
                        <p className="text-xs font-semibold" style={{ color: T.muted }}>Known CVEs / CWEs</p>
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
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer"
                        style={{ background: T.surface, color: T.primary, border: `1px solid ${T.border}` }}>
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isTechScanning && (
                  <p className="text-xs text-center py-6" style={{ color: T.dim }}>Enter a URL to fingerprint the technology stack</p>
                )}
                {isTechScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <div className="w-4 h-4 border-2 rounded-full animate-spin" style={{ borderColor: `${T.info}30`, borderTopColor: T.info }} />
                    <p className="text-sm" style={{ color: T.muted }}>Fingerprinting technology stack…</p>
                  </div>
                )}
              </div>
            )}

            {/* ── EXPOSURE SCAN ── */}
            {activeId === 'exposure' && (
              <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
                <div className="px-5 py-4" style={{ borderBottom: `1px solid ${T.border}` }}>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>Target URL</p>
                  <ScanInput accentColor="#F97316" url={exposureScanUrl} setUrl={setExposureScanUrl} onScan={handleExposureScan} isScanning={isExposureScanning} />
                  {exposureError && (
                    <p className="mt-2 text-xs flex items-center gap-1.5" style={{ color: '#F97316' }}>
                      <AlertTriangle size={11} /> {exposureError}
                    </p>
                  )}
                </div>
                {exposureScanResult ? (
                  <div className="px-5 py-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <p className="text-xs" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>{exposureScanResult.url}</p>
                      <VulnBadge vulnerable={exposureScanResult.vulnerable} label={exposureScanResult.vulnerable ? 'Exposed' : 'Clean'} />
                    </div>
                    {/* Stats bar */}
                    {(() => {
                      const issues = exposureScanResult.findings.issues || [];
                      const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
                      issues.forEach(i => { if (counts[i.severity] !== undefined) counts[i.severity]++; });
                      return (
                        <div className="grid grid-cols-4 gap-2">
                          {[
                            { label: 'Critical', count: counts.Critical, color: '#F43F5E' },
                            { label: 'High',     count: counts.High,     color: '#F59E0B' },
                            { label: 'Medium',   count: counts.Medium,   color: T.info },
                            { label: 'Low',      count: counts.Low,      color: T.muted },
                          ].map(({ label, count, color }) => (
                            <div key={label} className="p-2 rounded-lg text-center" style={{ background: T.surface }}>
                              <p className="text-lg font-bold font-mono" style={{ color: count > 0 ? color : T.dim }}>{count}</p>
                              <p className="text-xs" style={{ color: T.dim }}>{label}</p>
                            </div>
                          ))}
                        </div>
                      );
                    })()}
                    {(exposureScanResult.findings.issues || []).length > 0 ? (
                      <div className="flex flex-col gap-2">
                        {exposureScanResult.findings.issues.map((issue, i) => {
                          const color = issue.severity === 'Critical' ? '#F43F5E' : issue.severity === 'High' ? '#F59E0B' : issue.severity === 'Medium' ? T.info : T.muted;
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
                      <div className="flex items-center gap-3 px-4 py-4 rounded-lg" style={{ background: '#10B98108', border: '1px solid #10B98120' }}>
                        <CheckCircle size={18} style={{ color: T.secure }} />
                        <p className="text-sm font-medium" style={{ color: T.secure }}>No sensitive files exposed at common paths</p>
                      </div>
                    )}
                    {exposureScanResult.recommendations?.length > 0 && <Recs items={exposureScanResult.recommendations} />}
                    <div className="flex justify-end">
                      <button onClick={() => exposureScanResult?.scan_id && navigateTo('report', exposureScanResult.scan_id)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer"
                        style={{ background: T.surface, color: T.primary, border: `1px solid ${T.border}` }}>
                        View Report <ArrowRight size={11} />
                      </button>
                    </div>
                  </div>
                ) : !isExposureScanning && (
                  <p className="text-xs text-center py-6" style={{ color: T.dim }}>Enter a URL to probe for exposed sensitive files</p>
                )}
                {isExposureScanning && (
                  <div className="flex items-center gap-3 px-5 py-4">
                    <div className="w-4 h-4 border-2 rounded-full animate-spin" style={{ borderColor: '#F9731630', borderTopColor: '#F97316' }} />
                    <p className="text-sm" style={{ color: T.muted }}>Probing sensitive file paths across all stacks…</p>
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
