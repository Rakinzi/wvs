import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  AlertOctagon, Search, ArrowLeft, RefreshCw, ChevronDown,
  User, Globe, Calendar, Clock, Filter, Monitor, Info, AlertTriangle, Shield, MapPin
} from 'lucide-react';
import { useBlockedAccessData } from '../hooks/useBlockedAccessData';
import Spinner from './Spinner';

const geoCache = new Map();

const useGeoLookup = (ips) => {
  const [geoMap, setGeoMap] = useState({});
  const pendingRef = useRef(new Set());

  useEffect(() => {
    const unique = [...new Set(ips)].filter(ip => ip && ip !== 'Unknown' && !geoCache.has(ip) && !pendingRef.current.has(ip));
    if (!unique.length) {
      const snapshot = {};
      ips.forEach(ip => { if (ip && geoCache.has(ip)) snapshot[ip] = geoCache.get(ip); });
      setGeoMap(snapshot);
      return;
    }
    unique.forEach(ip => pendingRef.current.add(ip));
    Promise.allSettled(
      unique.map(ip =>
        fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode`, { cache: 'force-cache' })
          .then(r => r.json())
          .then(d => { if (d.country) geoCache.set(ip, { country: d.country, code: d.countryCode }); pendingRef.current.delete(ip); })
          .catch(() => { geoCache.set(ip, null); pendingRef.current.delete(ip); })
      )
    ).then(() => {
      const snapshot = {};
      ips.forEach(ip => { if (ip && geoCache.has(ip)) snapshot[ip] = geoCache.get(ip); });
      setGeoMap(snapshot);
    });
  }, [ips.join(',')]);

  return geoMap;
};

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
};

const getBrowserInfo = (ua) => {
  if (!ua) return 'Unknown';
  if (ua.includes('Firefox')) return 'Firefox';
  if (ua.includes('Chrome') && !ua.includes('Chromium')) return 'Chrome';
  if (ua.includes('Safari') && !ua.includes('Chrome')) return 'Safari';
  if (ua.includes('Edge')) return 'Edge';
  if (ua.includes('MSIE') || ua.includes('Trident/')) return 'IE';
  if (ua.includes('Opera') || ua.includes('OPR')) return 'Opera';
  return 'Other';
};

const getDeviceType = (ua) => {
  if (!ua) return 'Unknown';
  if (ua.includes('Mobile')) return 'Mobile';
  if (ua.includes('Tablet')) return 'Tablet';
  if (ua.includes('Windows') || ua.includes('Macintosh') || ua.includes('Linux')) return 'Desktop';
  return 'Other';
};

const fmt = (d) => {
  const dt = new Date(d);
  return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
    + ' · ' + dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const BROWSER_COLORS = { Chrome: T.secure, Firefox: T.warn, Safari: T.primary, Edge: '#818CF8', Mobile: T.danger };
const DEVICE_COLORS  = { Desktop: T.primary, Mobile: T.secure, Tablet: '#A78BFA' };
const FILTER_LABELS  = { all: 'All Browsers', chrome: 'Chrome', firefox: 'Firefox', safari: 'Safari', mobile: 'Mobile' };

const BarRow = ({ label, count, total, color }) => {
  const pct = total ? Math.round((count / total) * 100) : 0;
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-medium" style={{ color: T.text }}>{label}</span>
        <span className="text-xs font-mono" style={{ color: T.dim }}>{pct}% · {count}</span>
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: T.elev }}>
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
};

const SectionHead = ({ icon: Icon, color, label }) => (
  <div className="flex items-center gap-2 mb-4">
    <div className="w-5 h-5 rounded flex items-center justify-center" style={{ background: `${color}20` }}>
      <Icon size={11} style={{ color }} />
    </div>
    <p className="text-xs font-semibold uppercase tracking-widest font-mono" style={{ color: T.dim }}>{label}</p>
  </div>
);

const BlockedAccess = ({ navigateTo }) => {
  const [q, setQ]                   = useState('');
  const [filterType, setFilterType] = useState('all');
  const [filterOpen, setFilterOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);

  const { blockedRequests, loading, error, fetchBlockedRequests, requestsPerPage, totalCount } = useBlockedAccessData(currentPage);

  const allIps = useMemo(() => blockedRequests.map(r => r.ip_address).filter(Boolean), [blockedRequests]);
  const geoMap = useGeoLookup(allIps);

  useEffect(() => { document.title = 'Blocked Access — LaunchGuard'; }, []);

  const filteredRequests = useMemo(() => blockedRequests.filter(r => {
    const matchQ = !q ||
      r.url?.toLowerCase().includes(q.toLowerCase()) ||
      r.ip_address?.includes(q) ||
      r.reason?.toLowerCase().includes(q.toLowerCase());
    const browser = getBrowserInfo(r.user_agent);
    const matchF = filterType === 'all' ||
      (filterType === 'chrome'  && browser === 'Chrome') ||
      (filterType === 'firefox' && browser === 'Firefox') ||
      (filterType === 'safari'  && browser === 'Safari') ||
      (filterType === 'mobile'  && getDeviceType(r.user_agent) === 'Mobile');
    return matchQ && matchF;
  }), [blockedRequests, q, filterType]);

  const domainStats = useMemo(() => {
    const map = new Map();
    blockedRequests.forEach(r => {
      try { const d = new URL(r.url).hostname; map.set(d, (map.get(d) || 0) + 1); } catch {}
    });
    return [...map].sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [blockedRequests]);

  const browserStats = useMemo(() => {
    const map = new Map();
    blockedRequests.forEach(r => { const b = getBrowserInfo(r.user_agent); map.set(b, (map.get(b) || 0) + 1); });
    return [...map].sort((a, b) => b[1] - a[1]);
  }, [blockedRequests]);

  const deviceStats = useMemo(() => {
    const map = new Map();
    blockedRequests.forEach(r => { const d = getDeviceType(r.user_agent); map.set(d, (map.get(d) || 0) + 1); });
    return [...map].sort((a, b) => b[1] - a[1]);
  }, [blockedRequests]);

  const totalPages = Math.ceil(totalCount / requestsPerPage);

  return (
    <div className="min-h-screen" style={{ background: T.bg }}>

      {/* Sticky header */}
      <div className="sticky top-0 z-20 px-6 lg:px-10 py-4 flex items-center justify-between"
        style={{ background: `${T.surface}E0`, backdropFilter: 'blur(12px)', borderBottom: `1px solid ${T.border}` }}>
        <div className="flex items-center gap-4">
          <button onClick={() => navigateTo('dashboard')}
            className="flex items-center gap-1.5 text-xs font-medium cursor-pointer px-3 py-1.5 rounded-lg"
            style={{ color: T.muted, background: T.card, border: `1px solid ${T.border}` }}>
            <ArrowLeft size={13} /> Back
          </button>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: T.dangerDim, border: `1px solid ${T.danger}30` }}>
              <AlertOctagon size={15} style={{ color: T.danger }} />
            </div>
            <div>
              <h1 className="text-base font-bold leading-tight" style={{ color: T.text }}>Blocked Access Attempts</h1>
              <p className="text-xs" style={{ color: T.dim }}>{totalCount} total intercepts</p>
            </div>
          </div>
        </div>
        <button onClick={fetchBlockedRequests}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer"
          style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      <div className="px-6 lg:px-10 py-6 flex flex-col gap-5">

        {/* Info banner */}
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl" style={{ background: T.dangerDim, border: `1px solid ${T.danger}25` }}>
          <Shield size={13} className="flex-shrink-0" style={{ color: T.danger }} />
          <p className="text-xs" style={{ color: T.muted }}>
            All recorded attempts to access websites flagged as malicious and blocked by the scanner.
          </p>
        </div>

        {/* Table card */}
        <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>

          {/* Toolbar */}
          <div className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center gap-3"
            style={{ borderBottom: `1px solid ${T.border}`, background: T.surface }}>
            <div className="relative flex-1">
              <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: T.dim }} />
              <input value={q} onChange={e => { setQ(e.target.value); setCurrentPage(1); }}
                placeholder="Search by URL, IP, or reason…"
                className="w-full pl-9 pr-4 py-2 rounded-lg text-xs outline-none font-mono"
                style={{ background: T.card, border: `1px solid ${T.border}`, color: T.text }} />
            </div>
            <div className="relative flex-shrink-0">
              <button onClick={() => setFilterOpen(o => !o)}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer"
                style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>
                <Filter size={12} /> {FILTER_LABELS[filterType]} <ChevronDown size={11} />
              </button>
              {filterOpen && (
                <div className="absolute right-0 mt-1.5 w-44 rounded-xl overflow-hidden z-30 shadow-2xl"
                  style={{ background: T.elev, border: `1px solid ${T.border}` }}>
                  {Object.entries(FILTER_LABELS).map(([k, label]) => (
                    <button key={k} onClick={() => { setFilterType(k); setFilterOpen(false); setCurrentPage(1); }}
                      className="flex items-center gap-2 w-full px-4 py-2.5 text-xs text-left cursor-pointer transition-colors"
                      style={{ color: filterType === k ? T.primary : T.muted, background: filterType === k ? `${T.primary}12` : 'transparent' }}>
                      {label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Body */}
          {loading ? (
            <div className="flex items-center justify-center py-20">
              <Spinner size="md" label="Loading access attempts…" />
            </div>
          ) : error ? (
            <div className="flex flex-col items-center gap-4 py-20">
              <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: T.dangerDim }}>
                <AlertTriangle size={20} style={{ color: T.danger }} />
              </div>
              <p className="text-sm font-medium" style={{ color: T.text }}>Error loading access attempts</p>
              <p className="text-xs" style={{ color: T.muted }}>{error}</p>
              <button onClick={fetchBlockedRequests}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium cursor-pointer text-white" style={{ background: T.primary }}>
                <RefreshCw size={13} /> Retry
              </button>
            </div>
          ) : blockedRequests.length === 0 ? (
            <div className="flex flex-col items-center gap-4 py-20">
              <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: T.surface }}>
                <Info size={22} style={{ color: T.dim }} />
              </div>
              <p className="text-sm font-medium" style={{ color: T.text }}>No blocked access attempts</p>
              <p className="text-xs" style={{ color: T.muted }}>No one has attempted to access a blocked site yet.</p>
            </div>
          ) : filteredRequests.length === 0 ? (
            <div className="flex flex-col items-center gap-4 py-20">
              <p className="text-sm font-medium" style={{ color: T.text }}>No matching results</p>
              <button onClick={() => { setQ(''); setFilterType('all'); }} className="text-xs cursor-pointer" style={{ color: T.primary }}>
                Clear filters
              </button>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ background: T.surface, borderBottom: `1px solid ${T.border}` }}>
                      {['URL', 'IP Address', 'Browser', 'Date & Time', 'Reason'].map(h => (
                        <th key={h} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: T.dim }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRequests.map((r) => (
                      <tr key={r.id} className="transition-colors" style={{ borderBottom: `1px solid ${T.borderSubtle}` }}>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-2.5">
                            <div className="w-6 h-6 rounded flex items-center justify-center flex-shrink-0" style={{ background: T.dangerDim }}>
                              <Globe size={11} style={{ color: T.danger }} />
                            </div>
                            <p className="text-xs font-mono font-medium truncate max-w-xs" style={{ color: T.text }}>{r.url}</p>
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex flex-col gap-0.5">
                            <div className="flex items-center gap-1.5">
                              <User size={11} style={{ color: T.dim }} />
                              <span className="text-xs font-mono" style={{ color: T.muted }}>{r.ip_address || 'Unknown'}</span>
                            </div>
                            {r.ip_address && geoMap[r.ip_address] && (
                              <div className="flex items-center gap-1 ml-4">
                                <MapPin size={9} style={{ color: T.dim }} />
                                <span className="text-xs" style={{ color: T.dim }}>
                                  {geoMap[r.ip_address].country}
                                </span>
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-1.5">
                            <Monitor size={11} style={{ color: T.dim }} />
                            <span className="text-xs" style={{ color: T.muted }}>{getBrowserInfo(r.user_agent)}</span>
                            {getDeviceType(r.user_agent) === 'Mobile' && (
                              <span className="px-1.5 py-0.5 rounded text-xs font-medium" style={{ background: T.warnDim, color: T.warn }}>Mobile</span>
                            )}
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-1.5 text-xs font-mono" style={{ color: T.dim }}>
                            <Clock size={10} />
                            {r.timestamp ? fmt(r.timestamp) : '—'}
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <span className="px-2 py-0.5 rounded-md text-xs font-semibold" style={{ background: T.dangerDim, color: T.danger }}>
                            {r.reason || 'Malicious site'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {totalPages > 1 && (
                <div className="flex items-center justify-between px-5 py-3.5"
                  style={{ borderTop: `1px solid ${T.border}`, background: T.surface }}>
                  <p className="text-xs font-mono" style={{ color: T.dim }}>
                    {((currentPage - 1) * requestsPerPage) + 1}–{Math.min(currentPage * requestsPerPage, totalCount)} of {totalCount}
                  </p>
                  <div className="flex items-center gap-1">
                    <button onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}
                      className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer disabled:opacity-30"
                      style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>‹</button>
                    {[...Array(Math.min(totalPages, 5))].map((_, i) => (
                      <button key={i} onClick={() => setCurrentPage(i + 1)}
                        className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer"
                        style={{ background: currentPage === i + 1 ? T.primary : T.card, color: currentPage === i + 1 ? '#fff' : T.muted, border: `1px solid ${currentPage === i + 1 ? T.primary : T.border}` }}>
                        {i + 1}
                      </button>
                    ))}
                    <button onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}
                      className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer disabled:opacity-30"
                      style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>›</button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Analytics — visible when there is data */}
        {!loading && !error && blockedRequests.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

            {/* Most Blocked Domains */}
            <div className="rounded-xl p-5" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <SectionHead icon={Globe} color={T.danger} label="Top Blocked Domains" />
              <div className="flex flex-col gap-3">
                {domainStats.map(([domain, count], idx) => (
                  <div key={domain} className="flex items-center justify-between">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="w-5 h-5 rounded flex items-center justify-center text-xs font-bold font-mono flex-shrink-0" style={{ background: T.dangerDim, color: T.danger }}>
                        {idx + 1}
                      </span>
                      <span className="text-xs font-mono truncate" style={{ color: T.text }}>{domain}</span>
                    </div>
                    <span className="text-xs font-mono flex-shrink-0 ml-2" style={{ color: T.dim }}>{count}×</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Browser Distribution */}
            <div className="rounded-xl p-5" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <SectionHead icon={Monitor} color={T.primary} label="Browser Breakdown" />
              <div className="flex flex-col gap-3">
                {browserStats.map(([browser, count]) => (
                  <BarRow key={browser} label={browser} count={count} total={blockedRequests.length} color={BROWSER_COLORS[browser] || T.dim} />
                ))}
              </div>
            </div>

            {/* Device Distribution */}
            <div className="rounded-xl p-5" style={{ background: T.card, border: `1px solid ${T.border}` }}>
              <SectionHead icon={User} color={T.secure} label="Device Types" />
              <div className="flex flex-col gap-3">
                {deviceStats.map(([device, count]) => (
                  <BarRow key={device} label={device} count={count} total={blockedRequests.length} color={DEVICE_COLORS[device] || T.dim} />
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default BlockedAccess;
