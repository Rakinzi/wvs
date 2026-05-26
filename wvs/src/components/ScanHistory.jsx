import React, { useState, useEffect } from 'react';
import {
  Clock, Search, FileText, Filter,
  ChevronDown, ChevronUp, RefreshCw,
  AlertTriangle, CheckCircle, ExternalLink,
  ArrowLeft, Calendar, Download, ShieldAlert, ShieldCheck, Activity, Trash2,
  GitCompare, X
} from 'lucide-react';
import { useScanHistoryData } from '../hooks/useScanHistoryData';
import { apiJson } from '../lib/api';
import Spinner from './Spinner';
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
  secure:      'var(--color-secure)',
  secureDim:   'var(--color-secure-dim)',
  danger:      'var(--color-danger)',
  dangerDim:   'var(--color-danger-dim)',
  warn:        'var(--color-warn)',
  info:        'var(--color-info)',
};

const fmt = (d) => {
  const dt = new Date(d);
  return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    + ' · ' + dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const StatPill = ({ icon: Icon, label, value, color, dimColor }) => (
  <div className="flex items-center gap-3 px-4 py-3 rounded-xl" style={{ background: T.card, border: `1px solid ${T.border}` }}>
    <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: dimColor }}>
      <Icon size={14} style={{ color }} />
    </div>
    <div>
      <p className="text-xs font-medium" style={{ color: T.muted }}>{label}</p>
      <p className="text-lg font-bold leading-tight" style={{ color: T.text }}>{value}</p>
    </div>
  </div>
);

const Pagination = ({ page, totalPages, setPage }) => {
  if (totalPages <= 1) return null;
  const pages = [...Array(Math.min(totalPages, 5))].map((_, i) => i + 1);
  return (
    <div className="flex items-center justify-between px-5 py-3.5" style={{ borderTop: `1px solid ${T.border}`, background: T.surface }}>
      <p className="text-xs font-mono" style={{ color: T.dim }}>
        pg {page} / {totalPages}
      </p>
      <div className="flex items-center gap-1">
        <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
          className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer disabled:opacity-30 transition-colors"
          style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>‹</button>
        {pages.map(p => (
          <button key={p} onClick={() => setPage(p)}
            className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer transition-colors"
            style={{ background: page === p ? T.primary : T.card, color: page === p ? '#fff' : T.muted, border: `1px solid ${page === p ? T.primary : T.border}` }}>
            {p}
          </button>
        ))}
        <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
          className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer disabled:opacity-30 transition-colors"
          style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>›</button>
      </div>
    </div>
  );
};

const SCANNERS = ['sql', 'ssl', 'headers', 'xss', 'malicious', 'exposure'];
const SCANNER_LABELS = { sql: 'SQLi', ssl: 'SSL/TLS', headers: 'Headers', xss: 'XSS', malicious: 'Malicious', exposure: 'Exposure' };
const PROFILE_LABELS = {
  security_only: 'Security',
  product_readiness: 'Product Readiness',
  full_launch_audit: 'Full Launch Audit',
};

const ScoreBadge = ({ score }) => {
  const color = score >= 80 ? T.secure : score >= 50 ? T.warn : T.danger;
  const bg    = score >= 80 ? T.secureDim : score >= 50 ? `${T.warn}20` : T.dangerDim;
  return (
    <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-bold"
      style={{ background: bg, color }}>{score}</span>
  );
};

const CompareView = ({ ids, onClose }) => {
  const [reports, setReports] = useState([null, null]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all(ids.map(id => apiJson(`/report/${id}?format=json`, { auth: true }).then(r => r.data)))
      .then(data => { setReports(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, [ids.join(',')]);

  const fmt = (d) => new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

  return (
    <div className="fixed inset-0 z-50 flex flex-col" style={{ background: T.bg }}>
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 flex-shrink-0"
        style={{ background: T.surface, borderBottom: `1px solid ${T.border}` }}>
        <div className="flex items-center gap-2.5">
          <GitCompare size={16} style={{ color: T.primary }} />
          <span className="text-sm font-semibold" style={{ color: T.text }}>Scan Comparison</span>
        </div>
        <button onClick={onClose} className="cursor-pointer" style={{ color: T.muted }}>
          <X size={18} />
        </button>
      </div>

      {loading ? (
        <div className="flex-1 flex items-center justify-center">
          <Spinner size="md" label="Loading reports…" />
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto">
          <div className="grid grid-cols-2 divide-x h-full" style={{ borderColor: T.border }}>
            {reports.map((r, idx) => !r ? (
              <div key={idx} className="flex items-center justify-center p-10">
                <p className="text-sm" style={{ color: T.danger }}>Failed to load report</p>
              </div>
            ) : (
              <div key={idx} className="p-5 flex flex-col gap-5 overflow-y-auto">
                {/* Scan identity */}
                <div className="flex flex-col gap-1">
                  <p className="text-xs font-mono font-medium truncate" style={{ color: T.text }}>{r.url}</p>
                  <p className="text-xs font-mono" style={{ color: T.dim }}>{fmt(r.timestamp)} · {String(r.scan_id).slice(0, 8)}</p>
                </div>

                {/* Overall score */}
                <div className="flex items-center justify-between px-4 py-3 rounded-xl"
                  style={{ background: T.card, border: `1px solid ${T.border}` }}>
                  <span className="text-xs font-semibold" style={{ color: T.muted }}>Overall score</span>
                  <ScoreBadge score={r.summary?.score ?? 0} />
                </div>

                {/* Issue summary */}
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { label: 'Total issues', value: r.summary?.total_issues ?? 0 },
                    { label: 'Critical', value: r.summary?.critical ?? 0 },
                    { label: 'High', value: r.summary?.high ?? 0 },
                    { label: 'Medium', value: r.summary?.medium ?? 0 },
                  ].map(({ label, value }) => (
                    <div key={label} className="flex flex-col px-3 py-2.5 rounded-lg"
                      style={{ background: T.surface, border: `1px solid ${T.border}` }}>
                      <span className="text-xs" style={{ color: T.muted }}>{label}</span>
                      <span className="text-base font-bold" style={{ color: T.text }}>{value}</span>
                    </div>
                  ))}
                </div>

                {/* Per-scanner scores */}
                <div className="flex flex-col gap-2">
                  <p className="text-xs font-mono uppercase tracking-widest" style={{ color: T.dim }}>Scanner scores</p>
                  {SCANNERS.map(key => {
                    const s = r.findings?.[key]?.score ?? r.findings?.[key]?.score;
                    if (s === undefined) return null;
                    const color = s >= 80 ? T.secure : s >= 50 ? T.warn : T.danger;
                    return (
                      <div key={key} className="flex items-center justify-between">
                        <span className="text-xs" style={{ color: T.muted }}>{SCANNER_LABELS[key]}</span>
                        <div className="flex items-center gap-2 flex-1 mx-3">
                          <div className="flex-1 h-1.5 rounded-full" style={{ background: T.surface }}>
                            <div className="h-full rounded-full" style={{ width: `${s}%`, background: color }} />
                          </div>
                        </div>
                        <span className="text-xs font-mono w-8 text-right" style={{ color }}>{s}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

const ScanHistory = ({ navigateTo }) => {
  const [page, setPage]     = useState(1);
  const [q, setQ]           = useState('');
  const [sort, setSort]     = useState('desc');
  const [filter, setFilter] = useState('all');
  const [filterOpen, setFilterOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [selected, setSelected] = useState([]);
  const [deleting, setDeleting] = useState(null);
  const [pendingDelete, setPendingDelete] = useState(null);
  const [comparing, setComparing] = useState(false);
  const perPage = 10;
  const { scans, loading, error, fetchScans, deleteScan } = useScanHistoryData();

  useEffect(() => { document.title = 'Scan History — LaunchGuard'; }, []);

  const filtered = scans
    .filter(s => {
      const mq = !q || s.url.toLowerCase().includes(q.toLowerCase());
      const mf = filter === 'all'
        || (filter === 'vulnerable' && s.has_vulnerabilities)
        || (filter === 'secure' && !s.has_vulnerabilities);
      return mq && mf;
    })
    .sort((a, b) => sort === 'desc'
      ? new Date(b.timestamp) - new Date(a.timestamp)
      : new Date(a.timestamp) - new Date(b.timestamp));

  const totalPages = Math.ceil(filtered.length / perPage);
  const pageScans  = filtered.slice((page - 1) * perPage, page * perPage);

  const vulnCount   = scans.filter(s => s.has_vulnerabilities).length;
  const secureCount = scans.length - vulnCount;

  const toggleSelect = (id) => setSelected(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id]);
  const toggleAll    = () => setSelected(p => p.length === filtered.length ? [] : filtered.map(s => s.id));

  const handleDelete = async (id) => {
    setDeleting(id);
    try { await deleteScan(id); setSelected(p => p.filter(x => x !== id)); }
    catch { /* scan stays in list if delete fails */ }
    finally { setDeleting(null); setPendingDelete(null); }
  };

  return (
    <div className="min-h-screen" style={{ background: T.bg }}>

      {comparing && (
        <CompareView ids={selected} onClose={() => setComparing(false)} />
      )}

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Delete Scan"
        message="This scan record will be permanently removed. This cannot be undone."
        confirmLabel="Delete"
        onConfirm={() => handleDelete(pendingDelete)}
        onCancel={() => setPendingDelete(null)}
      />

      {/* Sticky header */}
      <div className="sticky top-0 z-20 px-6 lg:px-10 py-4 flex items-center justify-between"
        style={{ background: `${T.surface}E0`, backdropFilter: 'blur(12px)', borderBottom: `1px solid ${T.border}` }}>
        <div className="flex items-center gap-4">
          <button onClick={() => navigateTo('dashboard')}
            className="flex items-center gap-1.5 text-xs font-medium cursor-pointer transition-colors px-3 py-1.5 rounded-lg"
            style={{ color: T.muted, background: T.card, border: `1px solid ${T.border}` }}>
            <ArrowLeft size={13} /> Back
          </button>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${T.primary}22`, border: `1px solid ${T.primary}40` }}>
              <Clock size={15} style={{ color: T.primary }} />
            </div>
            <div>
              <h1 className="text-base font-bold leading-tight" style={{ color: T.text }}>Scan History</h1>
              <p className="text-xs" style={{ color: T.dim }}>{scans.length} total records</p>
            </div>
          </div>
        </div>
        <button onClick={fetchScans}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer transition-colors"
          style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      <div className="px-6 lg:px-10 py-6 flex flex-col gap-5">

        {/* Stats strip */}
        <div className="grid grid-cols-3 gap-3">
          <StatPill icon={Activity}     label="Total Scans"  value={scans.length} color={T.primary}  dimColor={`${T.primary}20`} />
          <StatPill icon={ShieldAlert}  label="Vulnerable"   value={vulnCount}    color={T.danger}   dimColor={T.dangerDim} />
          <StatPill icon={ShieldCheck}  label="Secure"       value={secureCount}  color={T.secure}   dimColor={T.secureDim} />
        </div>

        {/* Table card */}
        <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>

          {/* Toolbar */}
          <div className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center gap-3"
            style={{ borderBottom: `1px solid ${T.border}`, background: T.surface }}>
            <div className="relative flex-1">
              <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: T.dim }} />
              <input type="text" value={q} onChange={e => { setQ(e.target.value); setPage(1); }}
                placeholder="Search by URL…"
                className="w-full pl-9 pr-4 py-2 rounded-lg text-xs outline-none font-mono"
                style={{ background: T.card, border: `1px solid ${T.border}`, color: T.text }} />
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">

              {/* Filter dropdown */}
              <div className="relative">
                <button onClick={() => setFilterOpen(o => !o)}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer"
                  style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>
                  <Filter size={12} />
                  {filter === 'all' ? 'All' : filter.charAt(0).toUpperCase() + filter.slice(1)}
                  <ChevronDown size={11} />
                </button>
                {filterOpen && (
                  <div className="absolute right-0 mt-1.5 w-40 rounded-xl overflow-hidden z-30 shadow-2xl"
                    style={{ background: T.elev, border: `1px solid ${T.border}` }}>
                    {['all', 'vulnerable', 'secure'].map(f => (
                      <button key={f} onClick={() => { setFilter(f); setFilterOpen(false); setPage(1); }}
                        className="flex items-center gap-2 w-full px-4 py-2.5 text-xs text-left cursor-pointer transition-colors"
                        style={{ color: filter === f ? T.primary : T.muted, background: filter === f ? `${T.primary}12` : 'transparent' }}>
                        {f === 'vulnerable' && <AlertTriangle size={11} style={{ color: T.danger }} />}
                        {f === 'secure'     && <CheckCircle  size={11} style={{ color: T.secure }} />}
                        {f.charAt(0).toUpperCase() + f.slice(1)}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Compare — shown only when exactly 2 selected */}
              {selected.length === 2 && (
                <button onClick={() => setComparing(true)}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold cursor-pointer text-white"
                  style={{ background: T.primary }}>
                  <GitCompare size={12} /> Compare
                </button>
              )}

              {/* Export */}
              {selected.length > 0 && selected.length !== 2 && (
                <div className="relative">
                  <button onClick={() => setExportOpen(o => !o)}
                    className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold cursor-pointer text-white"
                    style={{ background: T.primary }}>
                    <Download size={12} /> Export ({selected.length}) <ChevronDown size={11} />
                  </button>
                  {exportOpen && (
                    <div className="absolute right-0 mt-1.5 w-40 rounded-xl overflow-hidden z-30 shadow-2xl"
                      style={{ background: T.elev, border: `1px solid ${T.border}` }}>
                      {['PDF', 'CSV'].map(f => (
                        <button key={f} onClick={() => setExportOpen(false)}
                          className="flex items-center gap-2 w-full px-4 py-2.5 text-xs text-left cursor-pointer transition-colors"
                          style={{ color: T.muted }}>
                          Export as {f}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Body states */}
          {loading ? (
            <div className="flex items-center justify-center py-20">
              <Spinner size="md" label="Loading scan history…" />
            </div>
          ) : error ? (
            <div className="flex flex-col items-center gap-4 py-20">
              <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: T.dangerDim }}>
                <AlertTriangle size={20} style={{ color: T.danger }} />
              </div>
              <p className="text-sm font-medium" style={{ color: T.text }}>Error loading history</p>
              <p className="text-xs" style={{ color: T.muted }}>{error}</p>
              <button onClick={fetchScans} className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium cursor-pointer text-white" style={{ background: T.primary }}>
                <RefreshCw size={13} /> Retry
              </button>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center gap-4 py-20">
              <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: T.surface }}>
                <Search size={20} style={{ color: T.dim }} />
              </div>
              {q || filter !== 'all' ? (
                <>
                  <p className="text-sm font-medium" style={{ color: T.text }}>No matching scans</p>
                  <button onClick={() => { setQ(''); setFilter('all'); }} className="text-xs cursor-pointer" style={{ color: T.primary }}>
                    Clear filters
                  </button>
                </>
              ) : (
                <>
                  <p className="text-sm font-medium" style={{ color: T.text }}>No scan history yet</p>
                  <button onClick={() => navigateTo('scanners')} className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium cursor-pointer text-white" style={{ background: T.primary }}>
                    Start scanning
                  </button>
                </>
              )}
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ background: T.surface, borderBottom: `1px solid ${T.border}` }}>
                      <th className="px-5 py-3 w-10" style={{ borderBottom: `1px solid ${T.border}` }}>
                        <input type="checkbox"
                          checked={selected.length === filtered.length && filtered.length > 0}
                          onChange={toggleAll}
                          style={{ accentColor: T.primary }} />
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: T.dim }}>Target URL</th>
                      <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest cursor-pointer select-none"
                        style={{ color: T.dim }}
                        onClick={() => setSort(s => s === 'desc' ? 'asc' : 'desc')}>
                        <div className="flex items-center gap-1">
                          Date {sort === 'desc' ? <ChevronDown size={11} /> : <ChevronUp size={11} />}
                        </div>
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: T.dim }}>Status</th>
                      <th className="px-5 py-3 text-right text-xs font-semibold uppercase tracking-widest" style={{ color: T.dim }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageScans.map((scan, i) => (
                      <tr key={scan.id}
                        className="transition-colors group"
                        style={{ borderBottom: `1px solid ${T.borderSubtle}` }}>
                        <td className="px-5 py-4">
                          <input type="checkbox" checked={selected.includes(scan.id)}
                            onChange={() => toggleSelect(scan.id)} style={{ accentColor: T.primary }} />
                        </td>
                        <td className="px-5 py-4">
                          <p className="text-xs font-mono font-medium truncate max-w-sm" style={{ color: T.text }}>{scan.url}</p>
                          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                            <p className="text-xs font-mono" style={{ color: T.dim }}>{String(scan.id).slice(0, 8)}</p>
                            <span className="px-2 py-0.5 rounded text-[11px] font-semibold" style={{ background: T.surface, color: T.primary, border: `1px solid ${T.border}` }}>
                              {PROFILE_LABELS[scan.scan_profile] || 'Security'}
                            </span>
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-1.5 text-xs font-mono" style={{ color: T.muted }}>
                            <Calendar size={11} />
                            {fmt(scan.timestamp)}
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold"
                            style={scan.has_vulnerabilities
                              ? { background: T.dangerDim, color: T.danger }
                              : { background: T.secureDim, color: T.secure }}>
                            {scan.has_vulnerabilities
                              ? <><AlertTriangle size={10} /> Vulnerable</>
                              : <><CheckCircle size={10} /> Secure</>}
                          </span>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center justify-end gap-3">
                            <a href={scan.url} target="_blank" rel="noopener noreferrer" title="Visit site"
                              className="transition-colors" style={{ color: T.dim }}>
                              <ExternalLink size={14} />
                            </a>
                            <button onClick={() => navigateTo('report', scan.id)} title="View report"
                              className="cursor-pointer transition-colors" style={{ color: T.primary }}>
                              <FileText size={14} />
                            </button>
                            <button onClick={() => setPendingDelete(scan.id)} title="Delete scan"
                              disabled={deleting === scan.id}
                              className="cursor-pointer transition-colors disabled:opacity-40"
                              style={{ color: T.danger }}>
                              {deleting === scan.id
                                ? <Spinner size="sm" color={T.danger} style={{ width: 14, height: 14 }} />
                                : <Trash2 size={14} />}
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={page} totalPages={totalPages} setPage={setPage} />
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanHistory;
