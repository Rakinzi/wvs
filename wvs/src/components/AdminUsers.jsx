import React, { useState, useEffect, useCallback } from 'react';
import { Users, Search, ChevronLeft, ChevronRight, Shield, AlertTriangle } from 'lucide-react';
import { apiJson, ApiError } from '../lib/api';
import Spinner from './Spinner';

const ROLES = ['free', 'pro', 'enterprise', 'admin'];

const ROLE_COLORS = {
  free:       { bg: 'var(--color-surface)',     text: 'var(--color-text-muted)' },
  pro:        { bg: 'var(--color-info-dim)',     text: 'var(--color-info)' },
  enterprise: { bg: 'var(--color-secure-dim)',  text: 'var(--color-secure)' },
  admin:      { bg: 'var(--color-danger-dim)',   text: 'var(--color-danger)' },
};

const RoleBadge = ({ role }) => {
  const c = ROLE_COLORS[role] || ROLE_COLORS.free;
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
      fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em',
      background: c.bg, color: c.text,
    }}>
      {role}
    </span>
  );
};

const RoleSelect = ({ userId, currentRole, onChanged }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleChange = async (e) => {
    const newRole = e.target.value;
    setLoading(true);
    setError(null);
    try {
      await apiJson(`/admin/users/${userId}/role`, { method: 'PATCH', auth: true, json: true, body: { role: newRole } });
      onChanged(userId, newRole);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update role');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <select
        value={currentRole}
        onChange={handleChange}
        disabled={loading}
        className="input text-xs cursor-pointer"
        style={{ padding: '3px 6px', fontSize: 12, minWidth: 110 }}
      >
        {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
      </select>
      {loading && <Spinner size="sm" />}
      {error && <span style={{ fontSize: 11, color: 'var(--color-danger)' }}>{error}</span>}
    </div>
  );
};

const AdminUsers = () => {
  const [users, setUsers]     = useState([]);
  const [total, setTotal]     = useState(0);
  const [page, setPage]       = useState(1);
  const [search, setSearch]   = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const PER_PAGE = 20;

  const load = useCallback(async (p) => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await apiJson(`/users?page=${p}&per_page=${PER_PAGE}`, { auth: true });
      setUsers(data.users || []);
      setTotal(data.total || 0);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    document.title = 'User Management — LaunchGuard';
    load(page);
  }, [load, page]);

  const handleRoleChanged = (userId, newRole) => {
    setUsers(prev => prev.map(u => u.id === userId ? { ...u, role: newRole, is_admin: newRole === 'admin' } : u));
  };

  const filtered = search.trim()
    ? users.filter(u =>
        u.username.toLowerCase().includes(search.toLowerCase()) ||
        u.email.toLowerCase().includes(search.toLowerCase())
      )
    : users;

  const totalPages = Math.ceil(total / PER_PAGE);

  return (
    <div className="min-h-screen" style={{ background: 'var(--color-bg)' }}>
      <div className="page-header px-6 lg:px-10 py-4">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Shield size={15} style={{ color: 'var(--color-danger)' }} />
          <h1 className="text-base font-bold" style={{ color: 'var(--color-text)', letterSpacing: '-0.025em', margin: 0 }}>
            User Management
          </h1>
        </div>
        <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>
          Manage accounts and assign pricing tiers
        </p>
      </div>

      <div className="px-6 lg:px-10 py-6">
        {/* Search + count */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
          <div style={{ position: 'relative', flex: 1, maxWidth: 340 }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--color-text-muted)', pointerEvents: 'none' }} />
            <input
              type="search"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter by username or email…"
              className="input text-sm"
              style={{ paddingLeft: '2rem' }}
            />
          </div>
          <span className="section-label" style={{ flexShrink: 0 }}>
            {total} user{total !== 1 ? 's' : ''}
          </span>
        </div>

        {error && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 14px', borderRadius: 9, background: 'var(--color-danger-dim)', color: 'var(--color-danger)', fontSize: 13, marginBottom: 16 }}>
            <AlertTriangle size={13} style={{ flexShrink: 0 }} />{error}
          </div>
        )}

        <div className="card overflow-hidden">
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--color-border)' }}>
                {['Username', 'Email', 'Role', 'Scans/hr', 'Monitors', 'Verified', 'Joined'].map(h => (
                  <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                    {h}
                  </th>
                ))}
                <th style={{ padding: '10px 14px', textAlign: 'left', fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)' }}>
                  Change Role
                </th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={8} style={{ padding: '32px', textAlign: 'center' }}>
                    <Spinner />
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '32px', textAlign: 'center', color: 'var(--color-text-dim)', fontSize: 13 }}>
                    <Users size={20} style={{ margin: '0 auto 8px', display: 'block', color: 'var(--color-text-dim)' }} />
                    No users found
                  </td>
                </tr>
              ) : filtered.map((u, i) => (
                <tr key={u.id}
                  style={{
                    borderBottom: i < filtered.length - 1 ? '1px solid var(--color-border-subtle)' : 'none',
                    transition: 'background 80ms',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = 'var(--color-elevated)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '10px 14px', fontWeight: 600, color: 'var(--color-text)' }}>
                    {u.username}
                  </td>
                  <td style={{ padding: '10px 14px', color: 'var(--color-text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {u.email}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <RoleBadge role={u.role} />
                  </td>
                  <td style={{ padding: '10px 14px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {u.scan_limit ?? '∞'}
                  </td>
                  <td style={{ padding: '10px 14px', color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {u.monitor_limit ?? '∞'}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: u.email_verified ? 'var(--color-secure)' : 'var(--color-warn)' }}>
                      {u.email_verified ? '✓' : '✗'}
                    </span>
                  </td>
                  <td style={{ padding: '10px 14px', color: 'var(--color-text-dim)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                    {u.created_on ? new Date(u.created_on).toLocaleDateString() : '—'}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <RoleSelect userId={u.id} currentRole={u.role} onChanged={handleRoleChanged} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
            <button
              disabled={page === 1}
              onClick={() => setPage(p => p - 1)}
              className="btn-secondary text-xs disabled:opacity-40"
              style={{ padding: '5px 10px' }}
            >
              <ChevronLeft size={13} /> Prev
            </button>
            <span style={{ fontSize: 12, color: 'var(--color-text-muted)', fontFamily: 'var(--font-mono)' }}>
              {page} / {totalPages}
            </span>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage(p => p + 1)}
              className="btn-secondary text-xs disabled:opacity-40"
              style={{ padding: '5px 10px' }}
            >
              Next <ChevronRight size={13} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminUsers;
