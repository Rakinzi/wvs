import React, { useEffect, useRef, useState } from 'react';
import {
  Shield, AlertTriangle, Lock, Database,
  RefreshCw, CheckCircle, Search,
  Clock, Activity, PieChart,
  BarChart as BarChartIcon, Globe,
  ArrowRight, Zap, TrendingUp, Flame,
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
  PieChart as RechartsPieChart, Pie, Cell,
  AreaChart, Area,
} from 'recharts';
import { useDashboardData } from '../hooks/useDashboardData';
import { parseApiDate } from '../lib/time';

/* Recharts can't read CSS vars — literals only */
const C = {
  border:  '#1e1e28',
  dim:     '#44445a',
  muted:   '#6b6b80',
  text:    '#eeeef0',
  primary: '#00d4aa',
  secure:  '#00d4aa',
  warn:    '#f0a040',
  danger:  '#ff4f4f',
  info:    '#5b9fff',
};

const VULN_COLORS = {
  'SQL Injection':     '#ff4f4f',
  'SSL Issues':        '#f0a040',
  'Malicious Content': '#5b9fff',
  'Header Issues':     '#00d4aa',
  'WordPress Issues':  '#f0a040',
  'ZAP Alerts':        '#ff7a7a',
  'Dependency CVEs':   '#ff4f4f',
  'Malware Artifacts': '#dc2626',
};
const PIE_FALLBACK = ['#00d4aa', '#00b894', '#5b9fff', '#f0a040', '#22c55e'];

const tooltipStyle = {
  background: 'var(--color-card)',
  border: '1px solid var(--color-border)',
  borderRadius: '6px',
  color: 'var(--color-text)',
  fontSize: '11px',
  fontFamily: "var(--font-mono)",
  boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
  padding: '8px 12px',
};

/* ── Animated count-up ── */
const useCountUp = (target, duration = 800) => {
  const [display, setDisplay] = useState(null);
  const prev = useRef(null);
  useEffect(() => {
    if (target == null) { setDisplay(null); return; }
    const n = Number(target);
    if (isNaN(n)) { setDisplay(target); return; }
    const start = prev.current ?? 0;
    prev.current = n;
    if (start === n) { setDisplay(n); return; }
    const startTime = performance.now();
    const tick = (now) => {
      const p = Math.min((now - startTime) / duration, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      setDisplay(Math.round(start + (n - start) * ease));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [target, duration]);
  return display;
};

/* ── Stat card — ruled terminal style ── */
const StatCard = ({ icon: Icon, label, value, sub, danger, warn, secure }) => {
  const accent = danger ? C.danger : warn ? C.warn : secure ? C.secure : C.primary;
  const count = useCountUp(value);
  const [hov, setHov] = React.useState(false);
  return (
    <div
      style={{
        background: hov ? 'var(--color-surface)' : 'var(--color-bg)',
        borderTop: `2px solid ${hov ? accent : 'transparent'}`,
        padding: '16px 18px 14px',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        transition: 'background 120ms ease, border-color 120ms ease',
        cursor: 'default',
      }}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <Icon size={11} style={{ color: accent, opacity: 0.6, marginTop: 2 }} />
        <span
          className="stat-value"
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: 24,
            fontWeight: 700,
            color: accent,
            letterSpacing: '-0.04em',
            lineHeight: 1,
          }}
        >
          {count ?? '—'}
        </span>
      </div>
      <div>
        <p style={{ fontSize: 10, fontWeight: 700, color: C.muted, letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: "var(--font-mono)" }}>{label}</p>
        {sub && <p style={{ fontSize: 10, color: C.dim, marginTop: 3 }}>{sub}</p>}
      </div>
    </div>
  );
};

/* ── Activity row ── */
const ActivityRow = ({ icon: Icon, iconBg, iconColor, primary, badge, badgeColor, meta, onAction }) => (
  <div
    className="flex items-center gap-3 px-4 py-2.5 transition-colors duration-100 group"
    style={{
      borderBottom: '1px solid var(--color-border)',
      borderLeft: `2px solid ${iconColor || 'transparent'}`,
    }}
    onMouseEnter={e => { e.currentTarget.style.background = '#0f0f15'; }}
    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
  >
    <div className="flex-1 min-w-0">
      <p
        className="text-xs truncate"
        style={{ color: 'var(--color-text)', fontFamily: "var(--font-mono)", fontWeight: 400 }}
      >
        {primary}
      </p>
      {badge && (
        <span className="text-xs font-semibold mt-0.5 block" style={{ color: badgeColor, fontFamily: "var(--font-mono)", fontSize: 10, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
          {badge}
        </span>
      )}
    </div>
    <div className="flex items-center gap-2 flex-shrink-0">
      {meta && (
        <span
          style={{ color: 'var(--color-text-dim)', fontFamily: "var(--font-mono)", fontSize: 10 }}
        >
          {meta}
        </span>
      )}
      {onAction && (
        <button
          onClick={onAction}
          className="text-xs font-medium cursor-pointer opacity-0 group-hover:opacity-100 transition-opacity duration-150 px-2 py-0.5"
          style={{ color: 'var(--color-primary)', fontFamily: "var(--font-mono)", fontSize: 10, border: '1px solid rgba(0,212,170,0.25)', background: 'rgba(0,212,170,0.06)' }}
        >
          view →
        </button>
      )}
    </div>
  </div>
);

/* ── Section header ── */
const SectionHead = ({ icon: Icon, accent, title, action }) => (
  <div
    className="flex items-center justify-between px-4 py-2.5"
    style={{ borderBottom: '1px solid var(--color-border)', borderLeft: `2px solid ${accent || 'var(--color-border-bright)'}` }}
  >
    <span className="section-label" style={{ color: 'var(--color-text-muted)' }}>{title}</span>
    {action && (
      <button
        onClick={action.onClick}
        className="flex items-center gap-1 cursor-pointer"
        style={{ color: 'var(--color-primary)', fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 600, letterSpacing: '0.04em', background: 'none', border: 'none' }}
      >
        {action.label} <ArrowRight size={9} />
      </button>
    )}
  </div>
);

/* ── Empty state ── */
const Empty = ({ icon: Icon, label, cta, onCta }) => (
  <div className="flex flex-col items-center gap-2 py-8">
    <Icon size={14} style={{ color: 'var(--color-text-dim)' }} />
    <p style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: "var(--font-mono)" }}>{label}</p>
    {cta && (
      <button
        onClick={onCta}
        className="cursor-pointer"
        style={{ color: 'var(--color-primary)', fontSize: 11, fontFamily: "var(--font-mono)", background: 'none', border: 'none', fontWeight: 600 }}
      >
        {cta}
      </button>
    )}
  </div>
);

/* ════════════════════════════════════════════════ */
const Dashboard = ({ navigateTo }) => {
  const {
    dashboardStats, fetchDashboardStats,
    isLoadingStats, statsError,
    recentScanJobs,
  } = useDashboardData();

  useEffect(() => { document.title = 'Dashboard — LaunchGuard'; }, []);

  const rel = (d) => {
    const date = parseApiDate(d);
    if (!date) return '';
    const diff = Math.floor((Date.now() - date.getTime()) / 60000);
    if (diff < 1) return 'just now';
    if (diff < 60) return `${diff}m ago`;
    const h = Math.floor(diff / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  };

  return (
    <div className="min-h-screen" style={{ background: 'var(--color-bg)' }}>

      {/* ── Page header ── */}
      <div className="page-header px-6 lg:px-10 py-4 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2.5">
            <h1
              className="text-base font-bold"
              style={{ color: 'var(--color-text)', letterSpacing: '-0.025em' }}
            >
              Dashboard
            </h1>
            <span
              className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold"
              style={{ background: '#22c55e18', color: C.secure, border: '1px solid rgba(34,197,94,0.25)' }}
            >
              <span className="live-ping w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: C.secure, color: C.secure }} />
              Live
            </span>
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>
            Security intelligence overview
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchDashboardStats}
            className="btn-secondary w-8 h-8 p-0 justify-center"
            aria-label="Refresh"
          >
            <RefreshCw size={13} />
          </button>
          <button onClick={() => navigateTo('scanners')} className="btn-primary glow-pulse">
            <Zap size={13} /> New Scan
          </button>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6 flex flex-col gap-6">

        {/* ── Stats strip ── */}
        {isLoadingStats ? (
          <div className="grid grid-cols-2 xl:grid-cols-5 gap-3">
            {[0,1,2,3,4].map(i => (
              <div key={i} className="skeleton h-28 rounded-xl" />
            ))}
          </div>
        ) : statsError ? (
          <div className="card p-8 flex flex-col items-center gap-4 text-center">
            <AlertTriangle size={18} style={{ color: 'var(--color-danger)' }} />
            <div>
              <p className="text-sm font-semibold font-mono" style={{ color: 'var(--color-text)' }}>Failed to load statistics</p>
              <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>{statsError}</p>
            </div>
            <button onClick={fetchDashboardStats} className="btn-primary">
              <RefreshCw size={12} /> Retry
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-2 xl:grid-cols-5 gap-px stagger" style={{ background: 'var(--color-border)' }}>
            <StatCard icon={Search}        label="Total Scans"      value={dashboardStats.totalScans}           sub={`${dashboardStats.today.scans} today`} />
            <StatCard icon={Flame}         label="Vulnerable"       value={dashboardStats.vulnerableScans}      sub={`${dashboardStats.today.vulnerabilities} new today`} danger />
            <StatCard icon={Database}      label="Dependency CVEs"  value={dashboardStats.dependencyAdvisories} sub="Across saved scans" warn />
            <StatCard icon={Shield}        label="Blocked Sites"    value={dashboardStats.blockedSites}         sub={`${dashboardStats.today.blockedAttempts} blocked today`} />
            <div className="col-span-2 xl:col-span-1">
              <StatCard icon={Activity}    label="Uptime Monitors"  value={dashboardStats.uptimeMonitors}       sub={dashboardStats.averageUptimePercent != null ? `${dashboardStats.averageUptimePercent}% avg 24h` : 'No checks yet'} secure />
            </div>
          </div>
        )}

        {/* ── Main grid ── */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">

          {/* Left 2 cols */}
          <div className="xl:col-span-2 flex flex-col gap-4">

            {/* Recent Scans */}
            <div className="card overflow-hidden">
              <SectionHead icon={Clock} accent={C.primary} title="Recent Scans"
                action={{ label: 'View all', onClick: () => navigateTo('history') }} />
              {dashboardStats?.recentScans?.length ? (
                dashboardStats.recentScans.slice(0, 6).map((scan, index) => (
                  <ActivityRow
                    key={`${scan.id || 'scan'}-${index}`}
                    icon={scan.hasVulnerabilities ? AlertTriangle : CheckCircle}
                    iconBg={scan.hasVulnerabilities ? '#ef444420' : '#22c55e20'}
                    iconColor={scan.hasVulnerabilities ? C.danger : C.secure}
                    primary={scan.url}
                    badge={scan.hasVulnerabilities ? 'Vulnerable' : 'Secure'}
                    badgeColor={scan.hasVulnerabilities ? C.danger : C.secure}
                    meta={rel(scan.timestamp)}
                    onAction={() => navigateTo('report', scan.id)}
                  />
                ))
              ) : !isLoadingStats && (
                <Empty icon={Search} label="No scans yet" cta="Run your first scan →" onCta={() => navigateTo('scanners')} />
              )}
            </div>

            {/* Uptime Overview */}
            <div className="card overflow-hidden">
              <SectionHead icon={Globe} accent={C.secure} title="Uptime Overview"
                action={{ label: 'Manage', onClick: () => navigateTo('uptime') }} />
              {dashboardStats?.recentMonitors?.length ? (
                dashboardStats.recentMonitors.map((m, index) => (
                  <ActivityRow
                    key={`${m.id || 'monitor'}-${index}`}
                    icon={m.status === 'up' ? CheckCircle : m.status === 'down' ? AlertTriangle : Clock}
                    iconBg={m.status === 'up' ? '#22c55e20' : m.status === 'down' ? '#ff4f4f20' : '#00d4aa14'}
                    iconColor={m.status === 'up' ? C.secure : m.status === 'down' ? C.danger : C.primary}
                    primary={m.name}
                    badge={typeof m.uptime_percent_24h === 'number' ? `${m.uptime_percent_24h}% uptime` : m.status}
                    badgeColor={m.status === 'up' ? C.secure : m.status === 'down' ? C.danger : C.muted}
                    meta={m.last_checked_at ? rel(m.last_checked_at) : 'pending'}
                  />
                ))
              ) : (
                <Empty icon={Activity} label="No uptime monitors configured" cta="Add monitor →" onCta={() => navigateTo('uptime')} />
              )}
            </div>

            {/* Async Jobs */}
            <div className="card overflow-hidden">
              <SectionHead icon={RefreshCw} accent={C.info} title="Recent Scan Jobs" />
              {recentScanJobs.length === 0 ? (
                <Empty icon={Zap} label="No active jobs" />
              ) : (
                recentScanJobs.map((job, index) => (
                  <ActivityRow
                    key={`${job.id || 'job'}-${index}`}
                    icon={job.status === 'completed' ? CheckCircle : job.status === 'failed' ? AlertTriangle : RefreshCw}
                    iconBg={job.status === 'completed' ? '#22c55e20' : job.status === 'failed' ? '#ef444420' : '#f59e0b20'}
                    iconColor={job.status === 'completed' ? C.secure : job.status === 'failed' ? C.danger : C.warn}
                    primary={job.url}
                    badge={job.status}
                    badgeColor={job.status === 'completed' ? C.secure : job.status === 'failed' ? C.danger : C.warn}
                    meta={job.created_at ? rel(job.created_at) : ''}
                    onAction={job.result_id ? () => navigateTo('report', job.result_id) : undefined}
                  />
                ))
              )}
            </div>
          </div>

          {/* Right col */}
          <div className="flex flex-col gap-4">

            {/* Blocked Attempts */}
            {!isLoadingStats && !statsError && (
              <div className="card overflow-hidden">
                <SectionHead icon={Globe} accent={C.danger} title="Blocked Attempts"
                  action={{ label: 'View all', onClick: () => navigateTo('blockedAccess') }} />
                {dashboardStats?.recentBlockedAttempts?.length > 0 ? (
                  dashboardStats.recentBlockedAttempts.slice(0, 5).map((a) => (
                    <div
                      key={a.id}
                      className="flex items-center gap-3 px-4 py-2.5"
                      style={{ borderBottom: '1px solid var(--color-border)', borderLeft: `2px solid ${C.danger}` }}
                    >
                      <div className="flex-1 min-w-0">
                        <p
                          className="text-xs truncate"
                          style={{ color: 'var(--color-text)', fontFamily: "var(--font-mono)" }}
                        >
                          {a.url}
                        </p>
                        <p style={{ fontSize: 10, marginTop: 2, color: 'var(--color-text-dim)', fontFamily: "var(--font-mono)" }}>{a.ip_address}</p>
                      </div>
                    </div>
                  ))
                ) : (
                  <Empty icon={Shield} label="No blocked attempts" />
                )}
              </div>
            )}

            {/* Capabilities */}
            <div className="card overflow-hidden">
              <SectionHead icon={Shield} accent={C.info} title="Capabilities" />
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {[
                  { color: C.danger,  title: 'SQL Injection',     desc: 'Forms and URL parameters.' },
                  { color: C.secure,  title: 'SSL / TLS',         desc: 'Certificate and cipher checks.' },
                  { color: C.info,    title: 'Malicious Sites',   desc: 'Phishing and malware domains.' },
                  { color: C.primary, title: 'Access Monitoring', desc: 'Proxy-level blocked attempts.', nav: 'blockedAccess' },
                ].map(({ color, title, desc, nav }, i, arr) => (
                  <button
                    key={title}
                    onClick={nav ? () => navigateTo(nav) : undefined}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 12,
                      padding: '10px 16px',
                      borderTop: 'none',
                      borderRight: 'none',
                      borderBottom: i < arr.length - 1 ? '1px solid var(--color-border)' : 'none',
                      borderLeft: `2px solid ${color}`,
                      background: 'none', textAlign: 'left', width: '100%',
                      cursor: nav ? 'pointer' : 'default',
                      transition: 'background 100ms ease',
                    }}
                    onMouseEnter={e => { if (nav) e.currentTarget.style.background = '#0f0f15'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
                  >
                    <div className="min-w-0 flex-1">
                      <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--color-text)', fontFamily: "var(--font-mono)" }}>{title}</p>
                      <p style={{ fontSize: 10, color: 'var(--color-text-dim)', marginTop: 2 }}>{desc}</p>
                    </div>
                    {nav && <ArrowRight size={10} style={{ color: 'var(--color-text-dim)', flexShrink: 0 }} />}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Charts ── */}
        {!isLoadingStats && !statsError && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

            {/* Bar chart */}
            <div className="lg:col-span-2 card overflow-hidden">
              <SectionHead icon={BarChartIcon} accent={C.primary} title="Scan Activity — Last 7 Days" />
              <div className="p-5" style={{ height: 230 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={dashboardStats.scansByDay} barGap={4} barCategoryGap="35%">
                    <CartesianGrid strokeDasharray="2 4" stroke={C.border} vertical={false} />
                    <XAxis dataKey="date" tick={{ fill: C.dim, fontSize: 11, fontFamily: 'var(--font-mono)' }}
                      tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                      axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: C.dim, fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
                    <Tooltip contentStyle={tooltipStyle}
                      labelFormatter={(v) => new Date(v).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })} />
                    <Legend wrapperStyle={{ color: C.muted, fontSize: '11px' }} />
                    <Bar dataKey="scans" name="Scans" fill={C.primary} radius={[3,3,0,0]} />
                    <Bar dataKey="vulnerabilities" name="Vulnerabilities" fill={C.danger} radius={[3,3,0,0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Donut */}
            <div className="card overflow-hidden">
              <SectionHead icon={PieChart} accent={C.info} title="Vuln. Breakdown" />
              <div className="p-5">
                <div style={{ height: 130 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <RechartsPieChart>
                      <Pie data={dashboardStats.vulnerabilityTypes} cx="50%" cy="50%"
                        outerRadius={55} innerRadius={28} dataKey="value" labelLine={false} paddingAngle={2}>
                        {dashboardStats.vulnerabilityTypes.map((e, i) => (
                          <Cell key={i} fill={VULN_COLORS[e.name] || PIE_FALLBACK[i % PIE_FALLBACK.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={tooltipStyle} />
                    </RechartsPieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-col gap-1.5 mt-4">
                  {dashboardStats.vulnerabilityTypes.slice(0, 5).map((t, i) => (
                    <div key={i} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <div
                          className="w-2 h-2 rounded-sm flex-shrink-0"
                          style={{ background: VULN_COLORS[t.name] || PIE_FALLBACK[i % PIE_FALLBACK.length] }}
                        />
                        <span className="text-xs" style={{ color: C.muted }}>{t.name}</span>
                      </div>
                      <span
                        className="text-xs font-semibold tabular-nums"
                        style={{ color: C.text, fontFamily: 'var(--font-mono)' }}
                      >
                        {t.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Area chart */}
            <div className="lg:col-span-3 card overflow-hidden">
              <SectionHead icon={Shield} accent={C.info} title="Blocked Access Attempts — Last 7 Days" />
              <div className="p-5" style={{ height: 190 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={dashboardStats.blockedAttemptsByDay}>
                    <defs>
                      <linearGradient id="blockGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={C.danger} stopOpacity={0.18} />
                        <stop offset="95%" stopColor={C.danger} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="2 4" stroke={C.border} vertical={false} />
                    <XAxis dataKey="date" tick={{ fill: C.dim, fontSize: 11, fontFamily: 'var(--font-mono)' }}
                      tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                      axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: C.dim, fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Area type="monotone" dataKey="count" name="Blocked"
                      stroke={C.danger} fill="url(#blockGrad)" strokeWidth={1.5} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;
