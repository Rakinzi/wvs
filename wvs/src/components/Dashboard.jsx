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

/* Recharts can't read CSS vars — literals only */
const C = {
  border:  '#27272a',
  dim:     '#52525b',
  muted:   '#71717a',
  text:    '#fafafa',
  primary: '#6366f1',
  secure:  '#22c55e',
  warn:    '#f59e0b',
  danger:  '#ef4444',
  info:    '#38bdf8',
  purple:  '#a78bfa',
};

const VULN_COLORS = {
  'SQL Injection':     '#ef4444',
  'SSL Issues':        '#f59e0b',
  'Malicious Content': '#a78bfa',
  'Header Issues':     '#38bdf8',
  'WordPress Issues':  '#f59e0b',
  'ZAP Alerts':        '#fb7185',
  'Dependency CVEs':   '#ef4444',
  'Malware Artifacts': '#dc2626',
};
const PIE_FALLBACK = ['#6366f1', '#8b5cf6', '#a78bfa', '#38bdf8', '#22c55e'];

const tooltipStyle = {
  background: '#1c1c22',
  border: '1px solid #3f3f46',
  borderRadius: '10px',
  color: '#fafafa',
  fontSize: '12px',
  fontFamily: 'Plus Jakarta Sans, sans-serif',
  boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
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

/* ── Stat card ── */
const StatCard = ({ icon: Icon, label, value, sub, danger, warn, secure }) => {
  const accent = danger ? C.danger : warn ? C.warn : secure ? C.secure : C.primary;
  const dimBg  = danger ? '#ef444418' : warn ? '#f59e0b18' : secure ? '#22c55e18' : '#6366f118';
  const glowColor = danger ? 'rgba(239,68,68,0.2)' : warn ? 'rgba(245,158,11,0.2)' : secure ? 'rgba(34,197,94,0.15)' : 'rgba(99,102,241,0.2)';
  const count = useCountUp(value);
  return (
    <div
      className="card card-hover card-accent p-5 flex flex-col gap-3"
      style={{ transition: 'border-color 150ms ease, box-shadow 200ms ease' }}
    >
      <div className="flex items-center justify-between">
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center"
          style={{ background: dimBg, boxShadow: `0 0 12px ${glowColor}` }}
        >
          <Icon size={14} style={{ color: accent }} />
        </div>
        <span
          className="text-2xl font-bold tabular-nums stat-value"
          style={{ color: accent === C.primary ? 'var(--color-text)' : accent, letterSpacing: '-0.04em' }}
        >
          {count ?? '—'}
        </span>
      </div>
      <div>
        <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)' }}>{label}</p>
        {sub && <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>{sub}</p>}
      </div>
    </div>
  );
};

/* ── Activity row ── */
const ActivityRow = ({ icon: Icon, iconBg, iconColor, primary, badge, badgeColor, meta, onAction }) => (
  <div
    className="flex items-center gap-3 px-4 py-3 transition-colors duration-100 hover:bg-[var(--color-elevated)] group"
    style={{ borderBottom: '1px solid var(--color-border)' }}
  >
    <div
      className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
      style={{ background: iconBg, color: iconColor }}
    >
      <Icon size={12} />
    </div>
    <div className="flex-1 min-w-0">
      <p
        className="text-xs font-medium truncate"
        style={{ color: 'var(--color-text)', fontFamily: 'IBM Plex Mono, monospace' }}
      >
        {primary}
      </p>
      {badge && (
        <span className="text-xs font-semibold mt-0.5" style={{ color: badgeColor }}>
          {badge}
        </span>
      )}
    </div>
    <div className="flex items-center gap-2 flex-shrink-0">
      {meta && (
        <span
          className="text-xs"
          style={{ color: 'var(--color-text-dim)', fontFamily: 'IBM Plex Mono, monospace' }}
        >
          {meta}
        </span>
      )}
      {onAction && (
        <button
          onClick={onAction}
          className="text-xs font-medium cursor-pointer opacity-0 group-hover:opacity-100 transition-opacity duration-150 px-2 py-1 rounded"
          style={{ color: 'var(--color-primary)', background: 'var(--color-primary-dim)' }}
        >
          View →
        </button>
      )}
    </div>
  </div>
);

/* ── Section header ── */
const SectionHead = ({ icon: Icon, accent, title, action }) => (
  <div
    className="flex items-center justify-between px-5 py-3.5"
    style={{ borderBottom: '1px solid var(--color-border)' }}
  >
    <div className="flex items-center gap-2">
      <Icon size={13} style={{ color: accent || 'var(--color-text-dim)' }} />
      <span className="section-label">{title}</span>
    </div>
    {action && (
      <button
        onClick={action.onClick}
        className="text-xs font-medium flex items-center gap-1 cursor-pointer transition-colors duration-150 hover:underline"
        style={{ color: 'var(--color-primary)' }}
      >
        {action.label} <ArrowRight size={10} />
      </button>
    )}
  </div>
);

/* ── Empty state ── */
const Empty = ({ icon: Icon, label, cta, onCta }) => (
  <div className="flex flex-col items-center gap-3 py-10">
    <div
      className="w-10 h-10 rounded-xl flex items-center justify-center"
      style={{ background: 'var(--color-elevated)' }}
    >
      <Icon size={18} style={{ color: 'var(--color-text-dim)' }} />
    </div>
    <p className="text-sm" style={{ color: 'var(--color-text-dim)' }}>{label}</p>
    {cta && (
      <button
        onClick={onCta}
        className="text-xs font-semibold cursor-pointer"
        style={{ color: 'var(--color-primary)' }}
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
    const diff = Math.floor((Date.now() - new Date(d)) / 60000);
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
            <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: 'var(--color-danger-dim)' }}>
              <AlertTriangle size={18} style={{ color: 'var(--color-danger)' }} />
            </div>
            <div>
              <p className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Failed to load statistics</p>
              <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>{statsError}</p>
            </div>
            <button onClick={fetchDashboardStats} className="btn-primary">
              <RefreshCw size={12} /> Retry
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-2 xl:grid-cols-5 gap-3 stagger">
            <StatCard icon={Search}        label="Total Scans"      value={dashboardStats.totalScans}           sub={`${dashboardStats.today.scans} today`} />
            <StatCard icon={Flame}         label="Vulnerable"       value={dashboardStats.vulnerableScans}      sub={`${dashboardStats.today.vulnerabilities} new today`} danger />
            <StatCard icon={Database}      label="Dependency CVEs"  value={dashboardStats.dependencyAdvisories} sub="Across saved scans" warn />
            <StatCard icon={Shield}        label="Blocked Sites"    value={dashboardStats.blockedSites}         sub={`${dashboardStats.today.blockedAttempts} blocked today`} />
            <StatCard icon={Activity}      label="Uptime Monitors"  value={dashboardStats.uptimeMonitors}       sub={dashboardStats.averageUptimePercent != null ? `${dashboardStats.averageUptimePercent}% avg 24h` : 'No checks yet'} secure />
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
                dashboardStats.recentScans.slice(0, 6).map((scan) => (
                  <ActivityRow
                    key={scan.id}
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
                dashboardStats.recentMonitors.map((m) => (
                  <ActivityRow
                    key={m.id}
                    icon={m.status === 'up' ? CheckCircle : m.status === 'down' ? AlertTriangle : Clock}
                    iconBg={m.status === 'up' ? '#22c55e20' : m.status === 'down' ? '#ef444420' : '#6366f120'}
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
                recentScanJobs.map((job) => (
                  <ActivityRow
                    key={job.id}
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
                      className="flex items-center gap-3 px-4 py-3"
                      style={{ borderBottom: '1px solid var(--color-border)' }}
                    >
                      <div
                        className="w-6 h-6 rounded-md flex items-center justify-center flex-shrink-0"
                        style={{ background: '#ef444420' }}
                      >
                        <AlertTriangle size={11} style={{ color: C.danger }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p
                          className="text-xs truncate"
                          style={{ color: 'var(--color-text)', fontFamily: 'IBM Plex Mono, monospace' }}
                        >
                          {a.url}
                        </p>
                        <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>{a.ip_address}</p>
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
              <SectionHead icon={Shield} accent={C.purple} title="Capabilities" />
              <div className="p-3 flex flex-col gap-1">
                {[
                  { icon: Database, color: C.danger,  title: 'SQL Injection',     desc: 'Forms and URL parameters.' },
                  { icon: Lock,     color: C.secure,  title: 'SSL / TLS',         desc: 'Certificate and cipher checks.' },
                  { icon: Shield,   color: C.purple,  title: 'Malicious Sites',   desc: 'Phishing and malware domains.' },
                  { icon: Globe,    color: C.primary, title: 'Access Monitoring', desc: 'Proxy-level blocked attempts.', nav: 'blockedAccess' },
                ].map(({ icon: Icon, color, title, desc, nav }) => (
                  <button
                    key={title}
                    onClick={nav ? () => navigateTo(nav) : undefined}
                    className={`flex items-center gap-3 p-2.5 rounded-lg text-left w-full transition-colors duration-150 ${nav ? 'cursor-pointer hover:bg-[var(--color-elevated)]' : 'cursor-default'}`}
                  >
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ background: `${color}18` }}
                    >
                      <Icon size={13} style={{ color }} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-semibold" style={{ color: 'var(--color-text)' }}>{title}</p>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>{desc}</p>
                    </div>
                    {nav && <ArrowRight size={11} style={{ color: 'var(--color-text-dim)', flexShrink: 0 }} />}
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
                    <XAxis dataKey="date" tick={{ fill: C.dim, fontSize: 11, fontFamily: 'IBM Plex Mono' }}
                      tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                      axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: C.dim, fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
                    <Tooltip contentStyle={tooltipStyle}
                      labelFormatter={(v) => new Date(v).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })} />
                    <Legend wrapperStyle={{ color: C.muted, fontSize: '11px' }} />
                    <Bar dataKey="scans" name="Scans" fill={C.primary} radius={[4,4,0,0]} />
                    <Bar dataKey="vulnerabilities" name="Vulnerabilities" fill={C.danger} radius={[4,4,0,0]} />
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
                        style={{ color: C.text, fontFamily: 'IBM Plex Mono, monospace' }}
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
              <SectionHead icon={Shield} accent={C.purple} title="Blocked Access Attempts — Last 7 Days" />
              <div className="p-5" style={{ height: 190 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={dashboardStats.blockedAttemptsByDay}>
                    <defs>
                      <linearGradient id="blockGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={C.purple} stopOpacity={0.2} />
                        <stop offset="95%" stopColor={C.purple} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="2 4" stroke={C.border} vertical={false} />
                    <XAxis dataKey="date" tick={{ fill: C.dim, fontSize: 11, fontFamily: 'IBM Plex Mono' }}
                      tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                      axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: C.dim, fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Area type="monotone" dataKey="count" name="Blocked"
                      stroke={C.purple} fill="url(#blockGrad)" strokeWidth={2} dot={false} />
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
