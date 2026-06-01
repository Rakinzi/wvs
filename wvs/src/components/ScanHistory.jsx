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

const fmt = (d) => {
  const dt = new Date(d);
  return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    + ' · ' + dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const StatPill = ({ icon: Icon, label, value, danger, warn }) => {
  const accent = danger ? 'var(--color-danger)' : warn ? 'var(--color-warn)' : 'var(--color-primary)';
  return (
    <div style={{
      background: 'var(--color-card)',
      borderTop: `2px solid ${accent}`,
      border: '1px solid var(--color-border)',
      borderTop: `2px solid ${accent}`,
      padding: '14px 16px',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <Icon size={11} style={{ color: accent, opacity: 0.6, marginTop: 2 }} />
        <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 22, fontWeight: 700, color: accent, letterSpacing: '-0.04em', lineHeight: 1 }}>{value}</span>
      </div>
      <p style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: "'IBM Plex Mono', monospace", marginTop: 8 }}>{label}</p>
    </div>
  );
};

const Pagination = ({ page, totalPages, setPage }) => {
  if (totalPages <= 1) return null;
  const start = Math.max(1, Math.min(page - 2, totalPages - 4));
  const pages = Array.from({ length: Math.min(5, totalPages) }, (_, i) => start + i);
  return (
    <div className="flex items-center justify-between px-5 py-3.5" style={{ borderTop: '1px solid var(--color-border)', background: 'var(--color-surface)' }}>
      <p className="text-xs font-mono" style={{ color: 'var(--color-text-dim)' }}>
        pg {page} / {totalPages}
      </p>
      <div className="flex items-center gap-1">
        <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
          className="btn-secondary px-2.5 py-1.5 text-xs disabled:opacity-30">‹</button>
        {pages.map(p => (
          <button key={p} onClick={() => setPage(p)}
            className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer transition-colors"
            style={{
              background: page === p ? 'var(--color-primary)' : 'var(--color-card)',
              color: page === p ? '#fff' : 'var(--color-text-muted)',
              border: `1px solid ${page === p ? 'var(--color-primary)' : 'var(--color-border)'}`,
            }}>
            {p}
          </button>
        ))}
        <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
          className="btn-secondary px-2.5 py-1.5 text-xs disabled:opacity-30">›</button>
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
  const color = score >= 80 ? 'var(--color-secure)' : score >= 50 ? 'var(--color-warn)' : 'var(--color-danger)';
  const bg    = score >= 80 ? 'var(--color-secure-dim)' : score >= 50 ? 'var(--color-warn-dim)' : 'var(--color-danger-dim)';
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

  const fmtShort = (d) => new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });

  return (
    <div className="fixed inset-0 z-50 flex flex-col" style={{ background: 'var(--color-bg)' }}>
      <div className="page-header px-6 py-4 flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-2.5">
          <GitCompare size={15} style={{ color: 'var(--color-primary)' }} />
          <span className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Scan Comparison</span>
        </div>
        <button onClick={onClose} className="btn-secondary w-8 h-8 p-0 justify-center" aria-label="Close">
          <X size={14} />
        </button>
      </div>

      {loading ? (
        <div className="flex-1 flex items-center justify-center">
          <Spinner size="md" label="Loading reports…" />
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto">
          <div className="grid grid-cols-2 divide-x h-full" style={{ borderColor: 'var(--color-border)' }}>
            {reports.map((r, idx) => !r ? (
              <div key={idx} className="flex items-center justify-center p-10">
                <p className="text-sm" style={{ color: 'var(--color-danger)' }}>Failed to load report</p>
              </div>
            ) : (
              <div key={idx} className="p-5 flex flex-col gap-5 overflow-y-auto">
                <div className="flex flex-col gap-1">
                  <p className="text-xs font-mono font-medium truncate" style={{ color: 'var(--color-text)' }}>{r.url}</p>
                  <p className="text-xs font-mono" style={{ color: 'var(--color-text-dim)' }}>{fmtShort(r.timestamp)} · {String(r.scan_id).slice(0, 8)}</p>
                </div>

                <div className="card flex items-center justify-between px-4 py-3">
                  <span className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)' }}>Overall score</span>
                  <ScoreBadge score={r.summary?.score ?? 0} />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  {[
                    { label: 'Total issues', value: r.summary?.total_issues ?? 0 },
                    { label: 'SQL injection', value: r.summary?.sqli_count ?? 0 },
                    { label: 'Exposure', value: r.summary?.exposure_count ?? 0 },
                    { label: 'Headers', value: r.summary?.header_issue_count ?? 0 },
                  ].map(({ label, value }) => (
                    <div key={label} className="card px-3 py-2.5 flex flex-col">
                      <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{label}</span>
                      <span className="text-base font-bold" style={{ color: 'var(--color-text)' }}>{value}</span>
                    </div>
                  ))}
                </div>

                <div className="flex flex-col gap-2">
                  <p className="section-label">Scanner scores</p>
                  {SCANNERS.map(key => {
                    const s = r.findings?.[key]?.score;
                    if (s === undefined) return null;
                    const color = s >= 80 ? 'var(--color-secure)' : s >= 50 ? 'var(--color-warn)' : 'var(--color-danger)';
                    return (
                      <div key={key} className="flex items-center justify-between">
                        <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{SCANNER_LABELS[key]}</span>
                        <div className="flex items-center gap-2 flex-1 mx-3">
                          <div className="flex-1 h-1.5 rounded-full" style={{ background: 'var(--color-elevated)' }}>
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
    <div className="min-h-screen" style={{ background: 'var(--color-bg)' }}>

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

      {/* Page header */}
      <div className="page-header px-6 lg:px-10 py-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button onClick={() => navigateTo('dashboard')} className="btn-secondary flex items-center gap-1.5 text-xs">
            <ArrowLeft size={13} /> Back
          </button>
          <div style={{ borderLeft: '2px solid var(--color-primary)', paddingLeft: 10 }}>
            <h1 style={{ fontSize: 14, fontWeight: 700, color: 'var(--color-text)', letterSpacing: '-0.02em', margin: 0 }}>Scan History</h1>
            <p style={{ fontSize: 10, color: 'var(--color-text-dim)', fontFamily: "'IBM Plex Mono', monospace", marginTop: 2 }}>{scans.length} total records</p>
          </div>
        </div>
        <button onClick={fetchScans} className="btn-secondary flex items-center gap-2 text-xs">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      <div className="px-6 lg:px-10 py-6 flex flex-col gap-5">

        {/* Stats strip */}
        <div className="grid grid-cols-3 gap-px" style={{ background: 'var(--color-border)' }}>
          <StatPill icon={Activity}    label="Total Scans" value={scans.length} />
          <StatPill icon={ShieldAlert} label="Vulnerable"  value={vulnCount}    danger />
          <StatPill icon={ShieldCheck} label="Secure"      value={secureCount} />
        </div>

        {/* Table card */}
        <div className="card overflow-hidden">

          {/* Toolbar */}
          <div className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center gap-3"
            style={{ borderBottom: '1px solid var(--color-border)', background: 'var(--color-surface)' }}>
            <div className="relative flex-1">
              <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--color-text-dim)' }} />
              <input type="text" value={q} onChange={e => { setQ(e.target.value); setPage(1); }}
                placeholder="Search by URL…"
                className="input pl-9 text-xs font-mono" />
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">

              {/* Filter */}
              <div className="relative">
                <button onClick={() => setFilterOpen(o => !o)} className="btn-secondary flex items-center gap-1.5 text-xs">
                  <Filter size={12} />
                  {filter === 'all' ? 'All' : filter.charAt(0).toUpperCase() + filter.slice(1)}
                  <ChevronDown size={11} />
                </button>
                {filterOpen && (
                  <div className="absolute right-0 mt-1.5 w-40 rounded-xl overflow-hidden z-30 shadow-2xl"
                    style={{ background: 'var(--color-overlay)', border: '1px solid var(--color-border-bright)' }}>
                    {['all', 'vulnerable', 'secure'].map(f => (
                      <button key={f} onClick={() => { setFilter(f); setFilterOpen(false); setPage(1); }}
                        className="flex items-center gap-2 w-full px-4 py-2.5 text-xs text-left cursor-pointer transition-colors"
                        style={{ color: filter === f ? 'var(--color-primary)' : 'var(--color-text-muted)', background: filter === f ? 'var(--color-primary-dim)' : 'transparent' }}>
                        {f === 'vulnerable' && <AlertTriangle size={11} style={{ color: 'var(--color-danger)' }} />}
                        {f === 'secure'     && <CheckCircle  size={11} style={{ color: 'var(--color-secure)' }} />}
                        {f.charAt(0).toUpperCase() + f.slice(1)}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Compare — shown only when exactly 2 selected */}
              {selected.length === 2 && (
                <button onClick={() => setComparing(true)} className="btn-primary flex items-center gap-1.5 text-xs">
                  <GitCompare size={12} /> Compare
                </button>
              )}

              {/* Export */}
              {selected.length > 0 && selected.length !== 2 && (
                <div className="relative">
                  <button onClick={() => setExportOpen(o => !o)} className="btn-primary flex items-center gap-1.5 text-xs">
                    <Download size={12} /> Export ({selected.length}) <ChevronDown size={11} />
                  </button>
                  {exportOpen && (
                    <div className="absolute right-0 mt-1.5 w-40 rounded-xl overflow-hidden z-30 shadow-2xl"
                      style={{ background: 'var(--color-overlay)', border: '1px solid var(--color-border-bright)' }}>
                      {['PDF', 'CSV'].map(f => (
                        <button key={f} onClick={() => setExportOpen(false)}
                          className="flex items-center gap-2 w-full px-4 py-2.5 text-xs text-left cursor-pointer transition-colors hover:bg-[var(--color-elevated)]"
                          style={{ color: 'var(--color-text-muted)' }}>
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
            <div className="flex flex-col items-center gap-3 py-16">
              <AlertTriangle size={16} style={{ color: 'var(--color-danger)' }} />
              <p style={{ fontSize: 12, color: 'var(--color-text-muted)', fontFamily: "'IBM Plex Mono', monospace" }}>Error loading history</p>
              <p style={{ fontSize: 11, color: 'var(--color-text-dim)', fontFamily: "'IBM Plex Mono', monospace" }}>{error}</p>
              <button onClick={fetchScans} className="btn-primary">
                <RefreshCw size={13} /> Retry
              </button>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-16">
              <Search size={14} style={{ color: 'var(--color-text-dim)' }} />
              {q || filter !== 'all' ? (
                <>
                  <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>No matching scans</p>
                  <button onClick={() => { setQ(''); setFilter('all'); }}
                    className="text-xs font-medium cursor-pointer" style={{ color: 'var(--color-primary)' }}>
                    Clear filters
                  </button>
                </>
              ) : (
                <>
                  <p className="text-sm font-medium" style={{ color: 'var(--color-text)' }}>No scan history yet</p>
                  <button onClick={() => navigateTo('scanners')} className="btn-primary">
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
                    <tr style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)' }}>
                      <th className="px-5 py-3 w-10">
                        <input type="checkbox"
                          checked={selected.length === filtered.length && filtered.length > 0}
                          onChange={toggleAll}
                          style={{ accentColor: 'var(--color-primary)' }} />
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--color-text-dim)' }}>Target URL</th>
                      <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest cursor-pointer select-none"
                        style={{ color: 'var(--color-text-dim)' }}
                        onClick={() => setSort(s => s === 'desc' ? 'asc' : 'desc')}>
                        <div className="flex items-center gap-1">
                          Date {sort === 'desc' ? <ChevronDown size={11} /> : <ChevronUp size={11} />}
                        </div>
                      </th>
                      <th className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--color-text-dim)' }}>Status</th>
                      <th className="px-5 py-3 text-right text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--color-text-dim)' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageScans.map((scan) => (
                      <tr key={scan.id} className="transition-colors hover:bg-[var(--color-elevated)]"
                        style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
                        <td className="px-5 py-4">
                          <input type="checkbox" checked={selected.includes(scan.id)}
                            onChange={() => toggleSelect(scan.id)} style={{ accentColor: 'var(--color-primary)' }} />
                        </td>
                        <td className="px-5 py-4">
                          <p className="text-xs font-mono font-medium truncate max-w-sm" style={{ color: 'var(--color-text)' }}>{scan.url}</p>
                          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                            <p className="text-xs font-mono" style={{ color: 'var(--color-text-dim)' }}>{String(scan.id).slice(0, 8)}</p>
                            <span className="px-2 py-0.5 rounded text-[11px] font-semibold"
                              style={{ background: 'var(--color-primary-dim)', color: 'var(--color-primary)', border: '1px solid var(--color-border)' }}>
                              {PROFILE_LABELS[scan.scan_profile] || 'Security'}
                            </span>
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-1.5 text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>
                            <Calendar size={11} />
                            {fmt(scan.timestamp)}
                          </div>
                        </td>
                        <td className="px-5 py-4">
                          <span className="badge" style={scan.has_vulnerabilities
                            ? { background: 'var(--color-danger-dim)', color: 'var(--color-danger)' }
                            : { background: 'var(--color-secure-dim)', color: 'var(--color-secure)' }}>
                            {scan.has_vulnerabilities
                              ? <><AlertTriangle size={10} /> Vulnerable</>
                              : <><CheckCircle size={10} /> Secure</>}
                          </span>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center justify-end gap-3">
                            <a href={scan.url} target="_blank" rel="noopener noreferrer" title="Visit site"
                              className="transition-colors" style={{ color: 'var(--color-text-dim)' }}>
                              <ExternalLink size={14} />
                            </a>
                            <button onClick={() => navigateTo('report', scan.id)} title="View report"
                              className="cursor-pointer transition-colors" style={{ color: 'var(--color-primary)' }}>
                              <FileText size={14} />
                            </button>
                            <button onClick={() => setPendingDelete(scan.id)} title="Delete scan"
                              disabled={deleting === scan.id}
                              className="cursor-pointer transition-colors disabled:opacity-40"
                              style={{ color: 'var(--color-danger)' }}>
                              {deleting === scan.id
                                ? <Spinner size="sm" color="var(--color-danger)" style={{ width: 14, height: 14 }} />
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
