import React, { useMemo, useState } from 'react';
import { Activity, AlertTriangle, Globe, Play, Plus, RefreshCw, Trash2, TrendingUp, Clock3 } from 'lucide-react';
import { useUptimeMonitorsData } from '../hooks/useUptimeMonitorsData';
import Spinner from './Spinner';

const StatusBadge = ({ status }) => {
  const map = {
    up:      { background: 'var(--color-secure-dim)',  color: 'var(--color-secure)' },
    down:    { background: 'var(--color-danger-dim)',  color: 'var(--color-danger)' },
    paused:  { background: 'var(--color-warn-dim)',    color: 'var(--color-warn)' },
    pending: { background: 'var(--color-primary-dim)', color: 'var(--color-primary)' },
  };
  return (
    <span className="badge" style={map[status] || map.pending}>
      {status}
    </span>
  );
};

const MetaCell = ({ label, value, mono }) => (
  <div className="flex flex-col gap-0.5 px-3 py-2.5 rounded-lg" style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)' }}>
    <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>{label}</p>
    <p className="text-sm font-medium" style={{ color: 'var(--color-text)', fontFamily: mono ? 'IBM Plex Mono, monospace' : undefined }}>
      {value ?? '—'}
    </p>
  </div>
);

const UptimeMonitors = ({ navigateTo }) => {
  const { monitors, loading, error, createMonitor, updateMonitor, runCheck, deleteMonitor, fetchMonitors } = useUptimeMonitorsData();
  const [name, setName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [intervalMinutes, setIntervalMinutes] = useState(5);
  const [actionError, setActionError] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const summary = useMemo(() => ({
    total: monitors.length,
    up: monitors.filter((m) => m.status === 'up').length,
    down: monitors.filter((m) => m.status === 'down').length,
    avg: (() => {
      const vals = monitors.map((m) => m.uptime_percent_24h).filter((v) => typeof v === 'number');
      if (!vals.length) return null;
      return (vals.reduce((s, v) => s + v, 0) / vals.length).toFixed(1);
    })(),
  }), [monitors]);

  const handleCreate = async () => {
    if (!name || !targetUrl) return;
    try {
      setSubmitting(true);
      setActionError(null);
      await createMonitor({ name, target_url: targetUrl, check_interval_minutes: Number(intervalMinutes) || 5 });
      setName(''); setTargetUrl(''); setIntervalMinutes(5);
    } catch (err) {
      setActionError(err.message || 'Failed to create monitor');
    } finally {
      setSubmitting(false);
    }
  };

  const toggleMonitor = async (monitor) => {
    try {
      setBusyId(monitor.id); setActionError(null);
      await updateMonitor(monitor.id, { is_enabled: !monitor.is_enabled });
    } catch (err) {
      setActionError(err.message || 'Failed to update monitor');
    } finally { setBusyId(null); }
  };

  const handleRunCheck = async (monitorId) => {
    try {
      setBusyId(monitorId); setActionError(null);
      await runCheck(monitorId);
    } catch (err) {
      setActionError(err.message || 'Failed to run uptime check');
    } finally { setBusyId(null); }
  };

  const handleDelete = async (monitorId) => {
    try {
      setBusyId(monitorId); setActionError(null);
      await deleteMonitor(monitorId);
    } catch (err) {
      setActionError(err.message || 'Failed to delete monitor');
    } finally { setBusyId(null); }
  };

  return (
    <div className="min-h-screen" style={{ background: 'var(--color-bg)' }}>

      {/* Page header */}
      <div className="page-header px-6 lg:px-10 py-4 flex items-center justify-between">
        <div style={{ borderLeft: '2px solid var(--color-primary)', paddingLeft: 10 }}>
          <h1 style={{ fontSize: 14, fontWeight: 700, color: 'var(--color-text)', letterSpacing: '-0.02em', margin: 0 }}>Uptime Monitors</h1>
          <p style={{ fontSize: 10, color: 'var(--color-text-dim)', fontFamily: "'IBM Plex Mono', monospace", marginTop: 2 }}>Track website availability and response times</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => navigateTo('dashboard')} className="btn-secondary text-xs">
            Dashboard
          </button>
          <button onClick={fetchMonitors} className="btn-secondary flex items-center gap-2 text-xs">
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6 flex flex-col gap-6">

        {/* Stats strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Monitors',       value: summary.total,                           icon: Globe },
            { label: 'Currently Up',   value: summary.up,                              icon: TrendingUp },
            { label: 'Currently Down', value: summary.down,                            icon: AlertTriangle, danger: summary.down > 0 },
            { label: 'Avg Uptime 24h', value: summary.avg ? `${summary.avg}%` : '—',  icon: Clock3 },
          ].map(({ label, value, icon: Icon, danger }) => {
            const accent = danger ? 'var(--color-danger)' : 'var(--color-primary)';
            return (
            <div key={label} style={{
              background: 'var(--color-card)', border: '1px solid var(--color-border)',
              borderTop: `2px solid ${accent}`, padding: '14px 16px',
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                <Icon size={11} style={{ color: accent, opacity: 0.6, marginTop: 2 }} />
                <span style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 22, fontWeight: 700, color: accent, letterSpacing: '-0.04em', lineHeight: 1 }}>{value}</span>
              </div>
              <p style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase', fontFamily: "'IBM Plex Mono', monospace", marginTop: 8 }}>{label}</p>
            </div>
            );
          })}
        </div>

        {/* Add monitor card */}
        <div className="card p-5">
          <p className="section-label mb-4" style={{ borderLeft: '2px solid var(--color-primary)', paddingLeft: 8 }}>Add Monitor</p>
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.4fr_180px_140px] gap-3">
            <input value={name} onChange={(e) => setName(e.target.value)}
              placeholder="Production Website"
              className="input text-sm" />
            <input value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              className="input text-sm font-mono" />
            <input value={intervalMinutes} onChange={(e) => setIntervalMinutes(e.target.value)}
              type="number" min="1" max="1440" placeholder="5 min"
              className="input text-sm" />
            <button onClick={handleCreate} disabled={submitting}
              className="btn-primary justify-center" style={{ opacity: submitting ? 0.75 : 1 }}>
              {submitting ? <Spinner size="sm" /> : <Plus size={14} />}
              {submitting ? 'Adding…' : 'Add'}
            </button>
          </div>
          {actionError && (
            <div className="flex items-center gap-2 mt-3 text-xs" style={{ color: 'var(--color-danger)' }}>
              <AlertTriangle size={12} /> {actionError}
            </div>
          )}
        </div>

        {/* Monitor list */}
        <div className="card overflow-hidden">
          <div className="px-5 py-3.5 flex items-center gap-2" style={{ borderBottom: '1px solid var(--color-border)', background: 'var(--color-surface)' }}>
            <Activity size={13} style={{ color: 'var(--color-primary)' }} />
            <p className="section-label">Monitor Status</p>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16">
              <Spinner size="md" label="Loading monitors…" />
            </div>
          ) : error ? (
            <div className="flex items-center gap-3 px-5 py-8">
              <AlertTriangle size={16} style={{ color: 'var(--color-danger)' }} />
              <p className="text-sm" style={{ color: 'var(--color-danger)' }}>{error}</p>
            </div>
          ) : monitors.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-16">
              <Activity size={18} style={{ color: 'var(--color-text-dim)' }} />
              <p className="text-sm font-mono" style={{ color: 'var(--color-text-dim)' }}>No uptime monitors added yet.</p>
            </div>
          ) : (
            <div style={{ borderColor: 'var(--color-border)' }}>
              {monitors.map((monitor, i) => (
                <div key={monitor.id} className="px-5 py-4 flex flex-col gap-4"
                  style={{ borderBottom: i < monitors.length - 1 ? '1px solid var(--color-border)' : 'none' }}>
                  <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>{monitor.name}</p>
                        <StatusBadge status={monitor.status} />
                        {!monitor.is_enabled && (
                          <span className="text-xs" style={{ color: 'var(--color-warn)' }}>disabled</span>
                        )}
                      </div>
                      <p className="text-xs mt-1 font-mono" style={{ color: 'var(--color-text-muted)' }}>{monitor.target_url}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button onClick={() => handleRunCheck(monitor.id)} disabled={busyId === monitor.id}
                        className="btn-primary text-xs disabled:opacity-50">
                        {busyId === monitor.id ? <Spinner size="sm" /> : <Play size={12} />}
                        Check now
                      </button>
                      <button onClick={() => toggleMonitor(monitor)} disabled={busyId === monitor.id}
                        className="btn-secondary text-xs disabled:opacity-50">
                        {monitor.is_enabled ? 'Pause' : 'Resume'}
                      </button>
                      <button onClick={() => handleDelete(monitor.id)} disabled={busyId === monitor.id}
                        className="w-8 h-8 rounded-lg flex items-center justify-center cursor-pointer transition-colors disabled:opacity-50"
                        style={{ background: 'var(--color-danger-dim)', color: 'var(--color-danger)' }}>
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <MetaCell label="24h Uptime" value={typeof monitor.uptime_percent_24h === 'number' ? `${monitor.uptime_percent_24h}%` : '—'} />
                    <MetaCell label="Last Response" value={typeof monitor.last_response_time_ms === 'number' ? `${monitor.last_response_time_ms} ms` : '—'} mono />
                    <MetaCell label="Interval" value={`${monitor.check_interval_minutes} min`} />
                    <MetaCell label="Consecutive Failures" value={monitor.consecutive_failures} />
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <MetaCell label="Last Checked" value={monitor.last_checked_at ? new Date(monitor.last_checked_at).toLocaleString() : 'Not checked yet'} />
                    <MetaCell label="Last Up" value={monitor.last_up_at ? new Date(monitor.last_up_at).toLocaleString() : '—'} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default UptimeMonitors;
