import React, { useState, useEffect } from 'react';
import {
  AlertOctagon, Search, ArrowLeft, RefreshCw,
  Plus, AlertTriangle, Filter, ChevronDown,
  ExternalLink, Trash2, CheckCircle, X, Globe, Calendar, ShieldOff
} from 'lucide-react';
import { useBlockedSitesData } from '../hooks/useBlockedSitesData';

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
  warnDim:     'var(--color-warn-dim)',
  info:        'var(--color-info)',
  infoDim:     'var(--color-info-dim)',
};

const fmtSource = (s) => ({ scan: 'Security Scan', api_scan: 'API Scan', manual: 'Manual', ai: 'AI Detection', external: 'External' }[s] || s);
const fmt = (d) => {
  const dt = new Date(d);
  return dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
    + ' · ' + dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const Pagination = ({ page, totalPages, setPage, perPage, total }) => {
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between px-5 py-3.5"
      style={{ borderTop: `1px solid ${T.border}`, background: T.surface }}>
      <p className="text-xs font-mono" style={{ color: T.dim }}>
        {(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} of {total}
      </p>
      <div className="flex items-center gap-1">
        <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
          className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer disabled:opacity-30"
          style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>‹</button>
        {[...Array(Math.min(totalPages, 5))].map((_, i) => (
          <button key={i} onClick={() => setPage(i + 1)}
            className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer"
            style={{ background: page === i + 1 ? T.primary : T.card, color: page === i + 1 ? '#fff' : T.muted, border: `1px solid ${page === i + 1 ? T.primary : T.border}` }}>
            {i + 1}
          </button>
        ))}
        <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
          className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer disabled:opacity-30"
          style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>›</button>
      </div>
    </div>
  );
};

const BlockedSites = ({ navigateTo }) => {
  const [q, setQ]               = useState('');
  const [src, setSrc]           = useState('all');
  const [filterOpen, setFilterOpen] = useState(false);
  const [page, setPage]         = useState(1);
  const [showAdd, setShowAdd]   = useState(false);
  const [newUrl, setNewUrl]     = useState('');
  const [newReason, setNewReason] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(null);
  const perPage = 10;

  const { addBlockedSite, addingUrl, blockedSites, error, fetchBlockedSites, loading, removeBlockedSite, successMessage } = useBlockedSitesData();
  const sources = ['all', ...new Set(blockedSites.map(s => s.source))];

  useEffect(() => { document.title = 'Blocked Sites — WebVulnScanner'; }, []);

  const filtered = blockedSites.filter(s => {
    const mq = !q || s.domain?.toLowerCase().includes(q.toLowerCase()) || s.reason?.toLowerCase().includes(q.toLowerCase());
    const ms = src === 'all' || s.source === src;
    return mq && ms;
  });
  const totalPages = Math.ceil(filtered.length / perPage);
  const current   = filtered.slice((page - 1) * perPage, page * perPage);

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!newUrl) return;
    const ok = await addBlockedSite({ url: newUrl, reason: newReason });
    if (ok) { setNewUrl(''); setNewReason(''); setShowAdd(false); }
  };

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
              <ShieldOff size={15} style={{ color: T.danger }} />
            </div>
            <div>
              <h1 className="text-base font-bold leading-tight" style={{ color: T.text }}>Blocked Sites</h1>
              <p className="text-xs" style={{ color: T.dim }}>{blockedSites.length} domains on blocklist</p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={fetchBlockedSites}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer"
            style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>
            <RefreshCw size={12} /> Refresh
          </button>
          <button onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold text-white cursor-pointer"
            style={{ background: T.danger }}>
            <Plus size={12} /> Block Site
          </button>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6 flex flex-col gap-5">

        {/* Success banner */}
        {successMessage && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl" style={{ background: T.secureDim, border: `1px solid ${T.secure}30`, color: T.secure }}>
            <CheckCircle size={14} /> {successMessage}
          </div>
        )}

        {/* Table card */}
        <div className="rounded-xl overflow-hidden" style={{ background: T.card, border: `1px solid ${T.border}` }}>

          {/* Toolbar */}
          <div className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center gap-3"
            style={{ borderBottom: `1px solid ${T.border}`, background: T.surface }}>
            <div className="relative flex-1">
              <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: T.dim }} />
              <input value={q} onChange={e => { setQ(e.target.value); setPage(1); }}
                placeholder="Search domains or reasons…"
                className="w-full pl-9 pr-4 py-2 rounded-lg text-xs outline-none font-mono"
                style={{ background: T.card, border: `1px solid ${T.border}`, color: T.text }} />
            </div>
            <div className="relative flex-shrink-0">
              <button onClick={() => setFilterOpen(o => !o)}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium cursor-pointer"
                style={{ background: T.card, color: T.muted, border: `1px solid ${T.border}` }}>
                <Filter size={12} /> {src === 'all' ? 'All Sources' : fmtSource(src)} <ChevronDown size={11} />
              </button>
              {filterOpen && (
                <div className="absolute right-0 mt-1.5 w-44 rounded-xl overflow-hidden z-30 shadow-2xl"
                  style={{ background: T.elev, border: `1px solid ${T.border}` }}>
                  {sources.map(s => (
                    <button key={s} onClick={() => { setSrc(s); setFilterOpen(false); setPage(1); }}
                      className="flex items-center gap-2 w-full px-4 py-2.5 text-xs text-left cursor-pointer transition-colors"
                      style={{ color: src === s ? T.primary : T.muted, background: src === s ? `${T.primary}12` : 'transparent' }}>
                      {s === 'all' ? 'All Sources' : fmtSource(s)}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Body */}
          {loading ? (
            <div className="flex items-center justify-center gap-3 py-20">
              <RefreshCw size={16} className="animate-spin" style={{ color: T.primary }} />
              <p className="text-sm" style={{ color: T.muted }}>Loading blocked sites…</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center gap-3 py-16">
              <AlertTriangle size={20} style={{ color: T.danger }} />
              <p className="text-sm" style={{ color: T.muted }}>{error}</p>
            </div>
          ) : current.length === 0 ? (
            <div className="flex flex-col items-center gap-4 py-20">
              <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: T.surface }}>
                <Globe size={22} style={{ color: T.dim }} />
              </div>
              <p className="text-sm font-medium" style={{ color: T.text }}>No blocked sites</p>
              <p className="text-xs" style={{ color: T.muted }}>Sites flagged as malicious will appear here.</p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ background: T.surface, borderBottom: `1px solid ${T.border}` }}>
                      {['Domain', 'Reason', 'Source', 'Date Added', ''].map(h => (
                        <th key={h} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: T.dim }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {current.map((site) => (
                      <tr key={site.id} className="transition-colors"
                        style={{ borderBottom: `1px solid ${T.borderSubtle}` }}>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-2.5">
                            <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: T.dangerDim }}>
                              <AlertOctagon size={12} style={{ color: T.danger }} />
                            </div>
                            <div>
                              <p className="text-xs font-mono font-medium" style={{ color: T.text }}>{site.domain}</p>
                              <a href={`https://${site.domain}`} target="_blank" rel="noopener noreferrer"
                                className="text-xs flex items-center gap-0.5" style={{ color: T.dim }}>
                                <ExternalLink size={9} /> view
                              </a>
                            </div>
                          </div>
                        </td>
                        <td className="px-5 py-4 max-w-xs">
                          <p className="text-xs truncate" style={{ color: T.muted }}>{site.reason || '—'}</p>
                        </td>
                        <td className="px-5 py-4">
                          <span className="px-2 py-0.5 rounded-md text-xs font-semibold" style={{ background: T.infoDim, color: T.info }}>
                            {fmtSource(site.source)}
                          </span>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-1.5 text-xs font-mono" style={{ color: T.dim }}>
                            <Calendar size={10} />
                            {site.created_at ? fmt(site.created_at) : '—'}
                          </div>
                        </td>
                        <td className="px-5 py-4 text-right">
                          <button onClick={() => setConfirmDelete(site)}
                            className="w-7 h-7 rounded-lg flex items-center justify-center cursor-pointer ml-auto transition-colors"
                            style={{ background: T.dangerDim, color: T.danger }} title="Remove">
                            <Trash2 size={12} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={page} totalPages={totalPages} setPage={setPage} perPage={perPage} total={filtered.length} />
            </>
          )}
        </div>
      </div>

      {/* Add modal */}
      {showAdd && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.8)' }}>
          <div className="w-full max-w-md rounded-2xl overflow-hidden shadow-2xl" style={{ background: T.card, border: `1px solid ${T.border}` }}>
            <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: `1px solid ${T.border}`, background: T.surface }}>
              <div className="flex items-center gap-2">
                <ShieldOff size={15} style={{ color: T.danger }} />
                <h3 className="text-sm font-semibold" style={{ color: T.text }}>Block a Site</h3>
              </div>
              <button onClick={() => setShowAdd(false)} className="cursor-pointer transition-colors" style={{ color: T.dim }}><X size={15} /></button>
            </div>
            <form onSubmit={handleAdd} className="px-6 py-5 flex flex-col gap-4">
              <div>
                <label className="text-xs font-medium mb-1.5 block" style={{ color: T.muted }}>URL *</label>
                <input type="text" value={newUrl} onChange={e => setNewUrl(e.target.value)}
                  placeholder="https://malicious-site.com"
                  className="w-full px-3 py-2.5 rounded-lg text-xs font-mono outline-none"
                  style={{ background: T.surface, border: `1px solid ${T.border}`, color: T.text }} required />
              </div>
              <div>
                <label className="text-xs font-medium mb-1.5 block" style={{ color: T.muted }}>Reason (optional)</label>
                <input type="text" value={newReason} onChange={e => setNewReason(e.target.value)}
                  placeholder="Phishing, malware, etc."
                  className="w-full px-3 py-2.5 rounded-lg text-xs outline-none"
                  style={{ background: T.surface, border: `1px solid ${T.border}`, color: T.text }} />
              </div>
              <div className="flex justify-end gap-2 pt-1">
                <button type="button" onClick={() => setShowAdd(false)}
                  className="px-4 py-2.5 rounded-lg text-xs cursor-pointer"
                  style={{ background: T.surface, color: T.muted, border: `1px solid ${T.border}` }}>Cancel</button>
                <button type="submit" disabled={addingUrl}
                  className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold text-white cursor-pointer"
                  style={{ background: T.danger, opacity: addingUrl ? 0.7 : 1 }}>
                  {addingUrl ? <RefreshCw size={12} className="animate-spin" /> : <Plus size={12} />}
                  {addingUrl ? 'Adding…' : 'Block Site'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirm delete modal */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.8)' }}>
          <div className="w-full max-w-sm rounded-2xl overflow-hidden shadow-2xl" style={{ background: T.card, border: `1px solid ${T.border}` }}>
            <div className="px-6 py-6 flex flex-col items-center gap-4">
              <div className="w-12 h-12 rounded-xl flex items-center justify-center" style={{ background: T.dangerDim }}>
                <Trash2 size={20} style={{ color: T.danger }} />
              </div>
              <div className="text-center">
                <h3 className="text-sm font-semibold mb-1.5" style={{ color: T.text }}>Remove from blocklist?</h3>
                <p className="text-xs font-mono" style={{ color: T.muted }}>{confirmDelete.domain}</p>
              </div>
              <div className="flex gap-2 w-full">
                <button onClick={() => setConfirmDelete(null)}
                  className="flex-1 py-2.5 rounded-lg text-sm cursor-pointer"
                  style={{ background: T.surface, color: T.muted, border: `1px solid ${T.border}` }}>Cancel</button>
                <button onClick={() => { removeBlockedSite(confirmDelete.id); setConfirmDelete(null); }}
                  className="flex-1 py-2.5 rounded-lg text-sm font-semibold text-white cursor-pointer"
                  style={{ background: T.danger }}>Remove</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BlockedSites;
