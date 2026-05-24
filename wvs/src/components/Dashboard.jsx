import React, { useEffect } from 'react';
import {
  Shield, AlertTriangle, Lock, Database,
  RefreshCw, CheckCircle, Search,
  Award, Clock, Activity, PieChart,
  BarChart as BarChartIcon, Globe, Filter,
  ArrowRight, User, Zap, TrendingUp
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
  PieChart as RechartsPieChart, Pie, Cell,
  AreaChart, Area
} from 'recharts';
import { useDashboardData } from '../hooks/useDashboardData';

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

/* Recharts can't read CSS vars — keep chart colors as literals */
const VULN_COLORS = {
  'SQL Injection':     '#F43F5E',
  'SSL Issues':        '#F59E0B',
  'Malicious Content': '#A78BFA',
  'Header Issues':     '#38BDF8',
  'WordPress Issues':  '#F59E0B',
  'ZAP Alerts':        '#FB7185',
  'Dependency CVEs':   '#EF4444',
};
const PIE_FALLBACK = ['#3B82F6', '#60A5FA', '#93C5FD', '#38BDF8', '#A78BFA'];

const tooltipStyle = {
  background: '#162035',
  border: '1px solid #2D4163',
  borderRadius: '8px',
  color: '#EEF2FF',
  fontSize: '12px',
  fontFamily: 'DM Sans, sans-serif',
};

/* ── Stat card with left accent bar ── */
const StatCard = ({ icon, iconColor, iconBg, label, value, sub }) => (
  <div
    className="rounded-xl p-5 flex flex-col gap-4 card-hover relative overflow-hidden"
    style={{ background: T.card, border: `1px solid ${T.border}` }}
  >
    <div
      className="absolute left-0 top-0 bottom-0 w-0.5 rounded-l-xl"
      style={{ background: iconColor }}
    />
    <div className="flex items-start justify-between pl-2">
      <div>
        <p className="text-xs font-medium tracking-widest uppercase mb-2" style={{ color: T.dim, fontFamily: 'IBM Plex Mono, monospace' }}>{label}</p>
        <p className="text-4xl font-bold tracking-tight" style={{ color: T.text }}>{value ?? '—'}</p>
      </div>
      <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: iconBg }}>
        {React.createElement(icon, { size: 18, style: { color: iconColor } })}
      </div>
    </div>
    {sub && (
      <div className="pl-2 flex items-center gap-1.5 text-xs" style={{ color: T.muted }}>
        <TrendingUp size={11} style={{ color: iconColor }} />
        {sub}
      </div>
    )}
  </div>
);

/* ── Activity list row ── */
const ActivityRow = ({ icon, iconStyle, primary, secondary, meta, action }) => (
  <div className="flex items-center gap-3 px-4 py-3 transition-colors duration-150" style={{ borderBottom: `1px solid ${T.border}` }}>
    <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={iconStyle}>
      {React.createElement(icon, { size: 12 })}
    </div>
    <div className="flex-1 min-w-0">
      <p className="text-xs font-medium truncate" style={{ color: T.text, fontFamily: 'IBM Plex Mono, monospace' }}>{primary}</p>
      <div className="flex items-center gap-2 mt-0.5">
        {secondary}
        {action && <span className="opacity-0 group-hover:opacity-100">{action}</span>}
        {action}
      </div>
    </div>
    {meta && <span className="text-xs flex-shrink-0" style={{ color: T.dim, fontFamily: 'IBM Plex Mono, monospace' }}>{meta}</span>}
  </div>
);

const JobProgressMeta = ({ job }) => {
  const progress = job.progress;
  if (!progress || job.status === 'completed' || job.status === 'failed') {
    return null;
  }

  return (
    <div className="mt-1 flex items-center gap-2 min-w-0">
      <span className="text-xs truncate" style={{ color: T.dim }}>
        {progress.message || progress.current_step_label || 'Running'}
      </span>
      {typeof progress.percent === 'number' && (
        <span className="text-xs flex-shrink-0" style={{ color: T.warn, fontFamily: 'IBM Plex Mono, monospace' }}>
          {progress.percent}%
        </span>
      )}
    </div>
  );
};

/* ── Section heading ── */
const SectionHead = ({ icon, iconColor, title, action }) => (
  <div
    className="flex items-center justify-between px-5 py-3.5"
    style={{ borderBottom: `1px solid ${T.border}` }}
  >
    <div className="flex items-center gap-2.5">
      <div className="w-1.5 h-4 rounded-full" style={{ background: iconColor }} />
      {React.createElement(icon, { size: 14, style: { color: iconColor } })}
      <span className="text-xs font-semibold tracking-wide uppercase" style={{ color: T.muted, fontFamily: 'IBM Plex Mono, monospace' }}>{title}</span>
    </div>
    {action}
  </div>
);

/* ════════════════════════════════════════════════ */
const Dashboard = ({ navigateTo }) => {
  const {
    dashboardStats, fetchDashboardStats,
    isLoadingStats, statsError,
    recentScanJobs,
  } = useDashboardData();

  useEffect(() => { document.title = 'Dashboard — WebVulnScanner'; }, []);

  const rel = (d) => {
    const diff = Math.floor((Date.now() - new Date(d)) / 60000);
    if (diff < 1) return 'now';
    if (diff < 60) return `${diff}m`;
    const h = Math.floor(diff / 60);
    if (h < 24) return `${h}h`;
    return `${Math.floor(h / 24)}d`;
  };

  return (
    <div className="min-h-screen" style={{ background: T.bg }}>

      {/* ── Page header ── */}
      <div
        className="sticky top-0 z-10 px-6 lg:px-10 py-4 flex items-center justify-between"
        style={{ background: `${T.surface}E8`, borderBottom: `1px solid ${T.border}`, backdropFilter: 'blur(12px)' }}
      >
        <div>
          <h1 className="text-lg font-semibold tracking-tight" style={{ color: T.text }}>Security Dashboard</h1>
          <p className="text-xs mt-0.5" style={{ color: T.dim }}>Real-time vulnerability monitoring</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => navigateTo('scanners')}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all duration-150 cursor-pointer"
            style={{ background: T.primary, color: '#fff' }}
          >
            <Zap size={13} /> New Scan
          </button>
          <button
            onClick={fetchDashboardStats}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150 cursor-pointer"
            style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}
          >
            <RefreshCw size={12} />
          </button>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-8 flex flex-col gap-8">

        {/* ── Stats strip ── */}
        {isLoadingStats ? (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[0,1,2].map(i => (
              <div key={i} className="h-32 rounded-xl animate-pulse" style={{ background: T.card, border: `1px solid ${T.border}` }} />
            ))}
          </div>
        ) : statsError ? (
          <div className="rounded-xl p-8 flex flex-col items-center gap-4" style={{ background: T.card, border: `1px solid ${T.border}` }}>
            <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: '#F43F5E15' }}>
              <AlertTriangle size={22} style={{ color: T.danger }} />
            </div>
            <div className="text-center">
              <p className="text-sm font-semibold" style={{ color: T.text }}>Failed to load statistics</p>
              <p className="text-xs mt-1" style={{ color: T.muted }}>{statsError}</p>
            </div>
            <button onClick={fetchDashboardStats} className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium cursor-pointer" style={{ background: T.primary, color: '#fff' }}>
              <RefreshCw size={14} /> Retry
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
            <StatCard icon={Search} iconColor={T.primary} iconBg={`${T.primary}18`}
              label="Total Scans" value={dashboardStats.totalScans}
              sub={`${dashboardStats.today.scans} scans today`} />
            <StatCard icon={AlertTriangle} iconColor={T.danger} iconBg={`${T.danger}18`}
              label="Vulnerable" value={dashboardStats.vulnerableScans}
              sub={`${dashboardStats.today.vulnerabilities} new issues today`} />
            <StatCard icon={Database} iconColor={T.warn} iconBg={`${T.warn}18`}
              label="Dependency CVEs" value={dashboardStats.dependencyAdvisories}
              sub="Detected across saved scans" />
            <StatCard icon={Shield} iconColor={T.purple} iconBg={`${T.purple}18`}
              label="Blocked Sites" value={dashboardStats.blockedSites}
              sub={`${dashboardStats.today.blockedAttempts} attempts blocked today`} />
          </div>
        )}

        {/* ── Main content: 3-column grid ── */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

          {/* Left 2 cols: recent scans + jobs */}
          <div className="xl:col-span-2 flex flex-col gap-6">

            {/* Recent Scans */}
            <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <SectionHead
                icon={Clock} iconColor={T.primary} title="Recent Scans"
                action={
                  <button onClick={() => navigateTo('history')} className="text-xs font-medium flex items-center gap-1 cursor-pointer" style={{ color: T.primary }}>
                    View all <ArrowRight size={11} />
                  </button>
                }
              />
              <div>
                {dashboardStats?.recentScans?.slice(0, 6).map((scan) => (
                  <ActivityRow
                    key={scan.id}
                    icon={scan.hasVulnerabilities ? AlertTriangle : CheckCircle}
                    iconStyle={scan.hasVulnerabilities
                      ? { background: '#F43F5E15', color: T.danger }
                      : { background: '#10B98115', color: T.secure }}
                    primary={scan.url}
                    secondary={
                      <span className="text-xs font-medium" style={{ color: scan.hasVulnerabilities ? T.danger : T.secure }}>
                        {scan.hasVulnerabilities ? 'Vulnerable' : 'Secure'}
                      </span>
                    }
                    action={
                      <button onClick={() => navigateTo('report', scan.id)} className="text-xs cursor-pointer ml-1" style={{ color: T.primary }}>
                        View →
                      </button>
                    }
                    meta={rel(scan.timestamp)}
                  />
                ))}
                {!dashboardStats?.recentScans?.length && !isLoadingStats && (
                  <div className="flex flex-col items-center gap-3 py-12">
                    <Search size={24} style={{ color: T.dim }} />
                    <p className="text-sm" style={{ color: T.dim }}>No scans yet</p>
                    <button onClick={() => navigateTo('scanners')} className="text-xs cursor-pointer" style={{ color: T.primary }}>
                      Run your first scan →
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Recent Scan Jobs */}
            <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <SectionHead icon={RefreshCw} iconColor={T.info} title="Async Scan Jobs" />
              {recentScanJobs.length === 0 ? (
                <div className="flex flex-col items-center gap-3 py-12">
                  <Zap size={22} style={{ color: T.dim }} />
                  <p className="text-sm" style={{ color: T.dim }}>No queued jobs</p>
                </div>
              ) : (
                recentScanJobs.map((job) => (
                  <ActivityRow
                    key={job.id}
                    icon={job.status === 'completed' ? CheckCircle : RefreshCw}
                    iconStyle={
                      job.status === 'completed' ? { background: '#10B98115', color: T.secure }
                      : job.status === 'failed'   ? { background: '#F43F5E15', color: T.danger }
                      : { background: '#F59E0B15', color: T.warn }
                    }
                    primary={job.url}
                    secondary={
                      <div className="min-w-0">
                        <span className="text-xs font-medium" style={{
                          color: job.status === 'completed' ? T.secure : job.status === 'failed' ? T.danger : T.warn
                        }}>{job.status}</span>
                        <JobProgressMeta job={job} />
                      </div>
                    }
                    action={job.result_id &&
                      <button onClick={() => navigateTo('report', job.result_id)} className="text-xs cursor-pointer ml-1" style={{ color: T.primary }}>
                        Report →
                      </button>
                    }
                    meta={job.created_at ? rel(job.created_at) : ''}
                  />
                ))
              )}
            </div>
          </div>

          {/* Right col: blocked attempts + security features */}
          <div className="flex flex-col gap-6">

            {/* Blocked Attempts */}
            {!isLoadingStats && !statsError && (
              <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
                <SectionHead
                  icon={Globe} iconColor={T.danger} title="Blocked Attempts"
                  action={
                    <button onClick={() => navigateTo('blockedAccess')} className="text-xs cursor-pointer" style={{ color: T.primary }}>
                      View all →
                    </button>
                  }
                />
                {dashboardStats?.recentBlockedAttempts?.length > 0 ? (
                  dashboardStats.recentBlockedAttempts.slice(0, 5).map((a) => (
                    <div key={a.id} className="flex items-center gap-3 px-4 py-3" style={{ borderBottom: `1px solid ${T.border}` }}>
                      <div className="w-6 h-6 rounded flex items-center justify-center flex-shrink-0" style={{ background: '#F43F5E15' }}>
                        <AlertTriangle size={11} style={{ color: T.danger }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs truncate" style={{ color: T.text, fontFamily: 'IBM Plex Mono, monospace' }}>{a.url}</p>
                        <p className="text-xs mt-0.5" style={{ color: T.dim }}>{a.ip_address}</p>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="flex flex-col items-center gap-2 py-10">
                    <Shield size={20} style={{ color: T.dim }} />
                    <p className="text-xs" style={{ color: T.dim }}>No blocked attempts</p>
                  </div>
                )}
              </div>
            )}

            {/* Security Capabilities */}
            <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <SectionHead icon={Shield} iconColor={T.purple} title="Capabilities" />
              <div className="p-4 flex flex-col gap-1">
                {[
                  { icon: Database, color: T.danger,  title: 'SQL Injection',     desc: 'Forms and URL parameter injection.' },
                  { icon: Lock,     color: T.secure,  title: 'SSL / TLS',         desc: 'Certificate validity and cipher suite.' },
                  { icon: Shield,   color: T.purple,  title: 'Malicious Sites',   desc: 'Known phishing and malware domains.' },
                  { icon: Globe,    color: T.primary, title: 'Access Monitoring', desc: 'Proxy-level blocked site attempts.', nav: 'blockedAccess' },
                ].map(({ icon, color, title, desc, nav }) => (
                  <button
                    key={title}
                    onClick={nav ? () => navigateTo(nav) : undefined}
                    className={`flex items-center gap-3 p-3 rounded-lg text-left transition-colors duration-150 w-full ${nav ? 'cursor-pointer' : 'cursor-default'}`}
                    style={{ background: 'transparent' }}
                    onMouseEnter={e => { if (nav) e.currentTarget.style.background = T.elev; }}
                    onMouseLeave={e => { if (nav) e.currentTarget.style.background = 'transparent'; }}
                  >
                    <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: `${color}18` }}>
                      {React.createElement(icon, { size: 13, style: { color } })}
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-semibold" style={{ color: T.text }}>{title}</p>
                      <p className="text-xs mt-0.5 leading-relaxed" style={{ color: T.dim }}>{desc}</p>
                    </div>
                    {nav && <ArrowRight size={12} style={{ color: T.dim, flexShrink: 0 }} />}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Charts — full width below ── */}
        {!isLoadingStats && !statsError && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Bar — 2 cols */}
            <div className="lg:col-span-2 rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <SectionHead icon={BarChartIcon} iconColor={T.primary} title="Scan Activity — Last 7 Days" />
              <div className="p-5" style={{ height: 240 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={dashboardStats.scansByDay} barGap={4}>
                    <CartesianGrid strokeDasharray="3 3" stroke={T.border} vertical={false} />
                    <XAxis dataKey="date" tick={{ fill: T.dim, fontSize: 11, fontFamily: 'IBM Plex Mono' }}
                      tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month:'short', day:'numeric' })}
                      axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: T.dim, fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={tooltipStyle}
                      labelFormatter={(v) => new Date(v).toLocaleDateString(undefined, { weekday:'long', month:'short', day:'numeric' })} />
                    <Legend wrapperStyle={{ color: T.muted, fontSize: '11px', fontFamily: 'DM Sans' }} />
                    <Bar dataKey="scans" name="Scans" fill={T.primary} radius={[3,3,0,0]} />
                    <Bar dataKey="vulnerabilities" name="Vulnerabilities" fill={T.danger} radius={[3,3,0,0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Pie — 1 col */}
            <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <SectionHead icon={PieChart} iconColor={T.info} title="Vuln. Breakdown" />
              <div className="p-5">
                <div style={{ height: 140 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <RechartsPieChart>
                      <Pie data={dashboardStats.vulnerabilityTypes} cx="50%" cy="50%"
                        outerRadius={60} innerRadius={30} dataKey="value" labelLine={false}>
                        {dashboardStats.vulnerabilityTypes.map((e, i) => (
                          <Cell key={i} fill={VULN_COLORS[e.name] || PIE_FALLBACK[i % PIE_FALLBACK.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={tooltipStyle} />
                    </RechartsPieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-col gap-1.5 mt-3">
                  {dashboardStats.vulnerabilityTypes.map((t, i) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-sm flex-shrink-0" style={{ background: VULN_COLORS[t.name] || PIE_FALLBACK[i % PIE_FALLBACK.length] }} />
                        <span style={{ color: T.muted }}>{t.name}</span>
                      </div>
                      <span className="font-semibold" style={{ color: T.text, fontFamily: 'IBM Plex Mono, monospace' }}>{t.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Area — full width */}
            <div className="lg:col-span-3 rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <SectionHead icon={Shield} iconColor={T.purple} title="Blocked Access Attempts — Last 7 Days" />
              <div className="p-5" style={{ height: 200 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={dashboardStats.blockedAttemptsByDay}>
                    <defs>
                      <linearGradient id="blockGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor={T.purple} stopOpacity={0.25} />
                        <stop offset="95%" stopColor={T.purple} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={T.border} vertical={false} />
                    <XAxis dataKey="date" tick={{ fill: T.dim, fontSize: 11, fontFamily: 'IBM Plex Mono' }}
                      tickFormatter={(v) => new Date(v).toLocaleDateString(undefined, { month:'short', day:'numeric' })}
                      axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: T.dim, fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Area type="monotone" dataKey="count" name="Blocked"
                      stroke={T.purple} fill="url(#blockGrad)" strokeWidth={1.5} dot={false} />
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
