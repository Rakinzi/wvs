import React, { useState, useEffect } from 'react';
import {
  AlertOctagon, Search, ArrowLeft, RefreshCw,
  Plus, AlertTriangle, Filter, ChevronDown,
  ExternalLink, Trash2, CheckCircle, X, Globe, Calendar, ShieldOff
} from 'lucide-react';
import { useBlockedSitesData } from '../hooks/useBlockedSitesData';
import Spinner from './Spinner';

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
      style={{ borderTop: '1px solid var(--color-border)', background: 'var(--color-surface)' }}>
      <p className="text-xs font-mono" style={{ color: 'var(--color-text-dim)' }}>
        {(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} of {total}
      </p>
      <div className="flex items-center gap-1">
        <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
          className="btn-secondary px-2.5 py-1.5 text-xs disabled:opacity-30">‹</button>
        {[...Array(Math.min(totalPages, 5))].map((_, i) => (
          <button key={i} onClick={() => setPage(i + 1)}
            className="px-2.5 py-1.5 rounded-lg text-xs cursor-pointer transition-colors"
            style={{
              background: page === i + 1 ? 'var(--color-primary)' : 'var(--color-card)',
              color: page === i + 1 ? '#fff' : 'var(--color-text-muted)',
              border: `1px solid ${page === i + 1 ? 'var(--color-primary)' : 'var(--color-border)'}`,
            }}>
            {i + 1}
          </button>
        ))}
        <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
          className="btn-secondary px-2.5 py-1.5 text-xs disabled:opacity-30">›</button>
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

  useEffect(() => { document.title = 'Blocked Sites — LaunchGuard'; }, []);

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
    <div className="min-h-screen" style={{ background: 'var(--color-bg)' }}>

      {/* Page header */}
      <div className="page-header px-6 lg:px-10 py-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button onClick={() => navigateTo('dashboard')} className="btn-secondary flex items-center gap-1.5 text-xs">
            <ArrowLeft size={13} /> Back
          </button>
          <div style={{ borderLeft: '2px solid var(--color-danger)', paddingLeft: 10 }}>
            <h1 style={{ fontSize: 14, fontWeight: 700, color: 'var(--color-text)', letterSpacing: '-0.02em', margin: 0 }}>Blocked Sites</h1>
            <p style={{ fontSize: 10, color: 'var(--color-text-dim)', fontFamily: "var(--font-mono)", marginTop: 2 }}>{blockedSites.length} domains on blocklist</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={fetchBlockedSites} className="btn-secondary flex items-center gap-2 text-xs">
            <RefreshCw size={12} /> Refresh
          </button>
          <button onClick={() => setShowAdd(true)} className="btn-primary" style={{ background: 'var(--color-danger)', boxShadow: 'none' }}>
            <Plus size={12} /> Block Site
          </button>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6 flex flex-col gap-5">

        {successMessage && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl"
            style={{ background: 'var(--color-secure-dim)', border: '1px solid rgba(34,197,94,0.2)', color: 'var(--color-secure)' }}>
            <CheckCircle size={14} /> {successMessage}
          </div>
        )}

        {/* Table card */}
        <div className="card overflow-hidden">

          {/* Toolbar */}
          <div className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center gap-3"
            style={{ borderBottom: '1px solid var(--color-border)', background: 'var(--color-surface)' }}>
            <div className="relative flex-1">
              <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--color-text-dim)' }} />
              <input value={q} onChange={e => { setQ(e.target.value); setPage(1); }}
                placeholder="Search domains or reasons…"
                className="input pl-9 text-xs font-mono" />
            </div>
            <div className="relative flex-shrink-0">
              <button onClick={() => setFilterOpen(o => !o)} className="btn-secondary flex items-center gap-1.5 text-xs">
                <Filter size={12} /> {src === 'all' ? 'All Sources' : fmtSource(src)} <ChevronDown size={11} />
              </button>
              {filterOpen && (
                <div className="absolute right-0 mt-1.5 w-44 rounded-xl overflow-hidden z-30 shadow-2xl"
                  style={{ background: 'var(--color-overlay)', border: '1px solid var(--color-border-bright)' }}>
                  {sources.map(s => (
                    <button key={s} onClick={() => { setSrc(s); setFilterOpen(false); setPage(1); }}
                      className="flex items-center gap-2 w-full px-4 py-2.5 text-xs text-left cursor-pointer transition-colors hover:bg-[var(--color-elevated)]"
                      style={{ color: src === s ? 'var(--color-primary)' : 'var(--color-text-muted)', background: src === s ? 'var(--color-primary-dim)' : 'transparent' }}>
                      {s === 'all' ? 'All Sources' : fmtSource(s)}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-20">
              <Spinner size="md" label="Loading blocked sites…" />
            </div>
          ) : error ? (
            <div className="flex flex-col items-center gap-3 py-16">
              <AlertTriangle size={20} style={{ color: 'var(--color-danger)' }} />
              <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>{error}</p>
            </div>
          ) : current.length === 0 ? (
            <div className="flex flex-col items-center gap-4 py-20">
              <Globe size={22} style={{ color: 'var(--color-text-dim)' }} />
              <p className="text-sm font-medium font-mono" style={{ color: 'var(--color-text)' }}>No blocked sites</p>
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Sites flagged as malicious will appear here.</p>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ background: 'var(--color-surface)', borderBottom: '1px solid var(--color-border)' }}>
                      {['Domain', 'Reason', 'Source', 'Date Added', ''].map(h => (
                        <th key={h} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest" style={{ color: 'var(--color-text-dim)' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {current.map((site) => (
                      <tr key={site.id} className="transition-colors hover:bg-[var(--color-elevated)]"
                        style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-2.5">
                            <AlertOctagon size={12} className="flex-shrink-0" style={{ color: 'var(--color-danger)' }} />
                            <div>
                              <p className="text-xs font-mono font-medium" style={{ color: 'var(--color-text)' }}>{site.domain}</p>
                              <a href={`https://${site.domain}`} target="_blank" rel="noopener noreferrer"
                                className="text-xs flex items-center gap-0.5" style={{ color: 'var(--color-text-dim)' }}>
                                <ExternalLink size={9} /> view
                              </a>
                            </div>
                          </div>
                        </td>
                        <td className="px-5 py-4 max-w-xs">
                          <p className="text-xs truncate" style={{ color: 'var(--color-text-muted)' }}>{site.reason || '—'}</p>
                        </td>
                        <td className="px-5 py-4">
                          <span className="badge" style={{ background: 'var(--color-info-dim)', color: 'var(--color-info)' }}>
                            {fmtSource(site.source)}
                          </span>
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-1.5 text-xs font-mono" style={{ color: 'var(--color-text-dim)' }}>
                            <Calendar size={10} />
                            {site.created_at ? fmt(site.created_at) : '—'}
                          </div>
                        </td>
                        <td className="px-5 py-4 text-right">
                          <button onClick={() => setConfirmDelete(site)}
                            className="w-7 h-7 rounded-lg flex items-center justify-center cursor-pointer ml-auto transition-colors"
                            style={{ background: 'var(--color-danger-dim)', color: 'var(--color-danger)' }} title="Remove">
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
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)' }}
          onClick={e => e.target === e.currentTarget && setShowAdd(false)}>
          <div className="w-full max-w-md rounded-2xl overflow-hidden shadow-2xl fade-up"
            style={{ background: 'var(--color-card)', border: '1px solid var(--color-border-bright)' }}>
            <div className="flex items-center justify-between px-6 py-4"
              style={{ borderBottom: '1px solid var(--color-border)', background: 'var(--color-surface)' }}>
              <div className="flex items-center gap-2">
                <ShieldOff size={14} style={{ color: 'var(--color-danger)' }} />
                <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Block a Site</h3>
              </div>
              <button onClick={() => setShowAdd(false)}
                className="w-6 h-6 flex items-center justify-center rounded-md cursor-pointer hover:bg-[var(--color-elevated)]"
                style={{ color: 'var(--color-text-dim)' }}>
                <X size={14} />
              </button>
            </div>
            <form onSubmit={handleAdd} className="px-6 py-5 flex flex-col gap-4">
              <div>
                <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--color-text-muted)' }}>URL *</label>
                <input type="text" value={newUrl} onChange={e => setNewUrl(e.target.value)}
                  placeholder="https://malicious-site.com"
                  className="input text-xs font-mono" required />
              </div>
              <div>
                <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--color-text-muted)' }}>Reason (optional)</label>
                <input type="text" value={newReason} onChange={e => setNewReason(e.target.value)}
                  placeholder="Phishing, malware, etc."
                  className="input text-xs" />
              </div>
              <div className="flex justify-end gap-2 pt-1">
                <button type="button" onClick={() => setShowAdd(false)} className="btn-secondary">Cancel</button>
                <button type="submit" disabled={addingUrl}
                  className="btn-primary" style={{ background: 'var(--color-danger)', boxShadow: 'none', opacity: addingUrl ? 0.75 : 1 }}>
                  {addingUrl ? <Spinner size="sm" /> : <Plus size={12} />}
                  {addingUrl ? 'Adding…' : 'Block Site'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirm delete modal */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(8px)' }}
          onClick={e => e.target === e.currentTarget && setConfirmDelete(null)}>
          <div className="w-full max-w-sm rounded-2xl overflow-hidden shadow-2xl fade-up"
            style={{ background: 'var(--color-card)', border: '1px solid var(--color-border-bright)' }}>
            <div className="px-6 py-6 flex flex-col items-center gap-4">
              <Trash2 size={20} style={{ color: 'var(--color-danger)' }} />
              <div className="text-center">
                <h3 className="text-sm font-semibold mb-1.5" style={{ color: 'var(--color-text)' }}>Remove from blocklist?</h3>
                <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{confirmDelete.domain}</p>
              </div>
              <div className="flex gap-2 w-full">
                <button onClick={() => setConfirmDelete(null)} className="btn-secondary flex-1 justify-center">Cancel</button>
                <button onClick={() => { removeBlockedSite(confirmDelete.id); setConfirmDelete(null); }}
                  className="btn-primary flex-1 justify-center" style={{ background: 'var(--color-danger)', boxShadow: 'none' }}>
                  Remove
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BlockedSites;
