import React, { useState, useEffect, useCallback } from 'react';
import {
  Plus, Edit2, Trash2, Eye, EyeOff, RefreshCw, AlertTriangle,
  CheckCircle, Save, X, ChevronLeft, Search, FileText,
} from 'lucide-react';
import { apiJson, ApiError } from '../lib/api';

const T = {
  bg:          'var(--color-bg)',
  surface:     'var(--color-surface)',
  card:        'var(--color-card)',
  elev:        'var(--color-elevated)',
  border:      'var(--color-border)',
  borderSubtle:'var(--color-border-subtle)',
  text:        'var(--color-text)',
  muted:       'var(--color-text-muted)',
  dim:         'var(--color-text-dim)',
  primary:     'var(--color-primary)',
  danger:      'var(--color-danger)',
  dangerDim:   'var(--color-danger-dim)',
  warn:        'var(--color-warn)',
  warnDim:     'var(--color-warn-dim)',
  secure:      'var(--color-secure)',
  secureDim:   'var(--color-secure-dim)',
  info:        'var(--color-info)',
  infoDim:     'var(--color-info-dim)',
};

const CATEGORIES = ['General', 'Breach', 'Vulnerability', 'Advisory', 'Research', 'Tool'];
const SEVERITIES = ['', 'Critical', 'High', 'Medium', 'Low'];

const EMPTY_FORM = {
  title: '', slug: '', summary: '', body: '',
  category: 'General', tags: '', severity: '', cve_ids: '', source_url: '', published: false,
};

const fmt = (d) => d ? new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—';

const Input = ({ label, value, onChange, placeholder, type = 'text', required, hint }) => (
  <div>
    <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: T.muted, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {label}{required && <span style={{ color: T.danger }}> *</span>}
    </label>
    <input
      type={type} value={value} onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      style={{ width: '100%', padding: '9px 12px', borderRadius: 9, background: T.elev, border: `1px solid ${T.border}`, color: T.text, fontSize: 13, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box' }}
    />
    {hint && <p style={{ fontSize: 11, color: T.dim, marginTop: 4 }}>{hint}</p>}
  </div>
);

const Select = ({ label, value, onChange, options }) => (
  <div>
    <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: T.muted, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</label>
    <select value={value} onChange={e => onChange(e.target.value)}
      style={{ width: '100%', padding: '9px 12px', borderRadius: 9, background: T.elev, border: `1px solid ${T.border}`, color: T.text, fontSize: 13, fontFamily: 'inherit', outline: 'none', cursor: 'pointer' }}>
      {options.map((o) => <option key={o.value ?? o} value={o.value ?? o}>{(o.label ?? o) || '— None —'}</option>)}
    </select>
  </div>
);

const ArticleForm = ({ article, onSave, onCancel, saving, error }) => {
  const [form, setForm] = useState(
    article
      ? {
          title: article.title || '',
          slug: article.slug || '',
          summary: article.summary || '',
          body: article.body || '',
          category: article.category || 'General',
          tags: (article.tags || []).join(', '),
          severity: article.severity || '',
          cve_ids: (article.cve_ids || []).join(', '),
          source_url: article.source_url || '',
          published: article.published || false,
        }
      : { ...EMPTY_FORM }
  );
  const [autoSlug, setAutoSlug] = useState(!article);

  const set = (k) => (v) => setForm(f => ({ ...f, [k]: v }));

  const handleTitle = (v) => {
    setForm(f => ({
      ...f,
      title: v,
      slug: autoSlug ? v.toLowerCase().replace(/[^\w\s-]/g, '').replace(/[\s_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) : f.slug,
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const payload = {
      ...form,
      tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
      cve_ids: form.cve_ids.split(',').map(c => c.trim()).filter(Boolean),
      severity: form.severity || null,
      source_url: form.source_url || null,
    };
    onSave(payload);
  };

  return (
    <div style={{ background: T.card, border: `1px solid ${T.border}`, borderRadius: 16 }}>
      <div style={{ padding: '20px 24px', borderBottom: `1px solid ${T.border}`, display: 'flex', alignItems: 'center', gap: 12 }}>
        <FileText size={18} color={T.primary} />
        <h2 style={{ fontSize: 16, fontWeight: 700, color: T.text, margin: 0 }}>
          {article ? 'Edit Article' : 'New Article'}
        </h2>
        <button onClick={onCancel}
          style={{ marginLeft: 'auto', background: T.elev, border: `1px solid ${T.border}`, borderRadius: 7, padding: 6, cursor: 'pointer', color: T.muted }}>
          <X size={14} />
        </button>
      </div>

      <form onSubmit={handleSubmit} style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: 20 }}>
        {error && (
          <div style={{ padding: '12px 16px', borderRadius: 9, background: T.dangerDim, border: `1px solid ${T.danger}40`, color: T.danger, fontSize: 13, display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={14} /> {error}
          </div>
        )}

        <Input label="Title" value={form.title} onChange={handleTitle} placeholder="e.g. Critical RCE in Apache Struts" required />

        <div>
          <Input label="Slug" value={form.slug} onChange={(v) => { setAutoSlug(false); set('slug')(v); }} placeholder="e.g. critical-rce-apache-struts" hint="Auto-generated from title. Edit to customise." />
        </div>

        <div>
          <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: T.muted, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Summary <span style={{ color: T.danger }}>*</span>
          </label>
          <textarea value={form.summary} onChange={e => set('summary')(e.target.value)} rows={3} placeholder="One-paragraph summary shown in the article card."
            style={{ width: '100%', padding: '9px 12px', borderRadius: 9, background: T.elev, border: `1px solid ${T.border}`, color: T.text, fontSize: 13, fontFamily: 'inherit', outline: 'none', resize: 'vertical', boxSizing: 'border-box' }} />
        </div>

        <div>
          <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: T.muted, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Body <span style={{ color: T.danger }}>*</span>
          </label>
          <textarea value={form.body} onChange={e => set('body')(e.target.value)} rows={14} placeholder="Full article content. Plain text or light markdown."
            style={{ width: '100%', padding: '9px 12px', borderRadius: 9, background: T.elev, border: `1px solid ${T.border}`, color: T.text, fontSize: 13, fontFamily: "var(--font-mono)", outline: 'none', resize: 'vertical', lineHeight: 1.7, boxSizing: 'border-box' }} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 16 }}>
          <Select label="Category" value={form.category} onChange={set('category')} options={CATEGORIES} />
          <Select label="Severity" value={form.severity} onChange={set('severity')}
            options={SEVERITIES.map(s => ({ value: s, label: s || '— None —' }))} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <Input label="CVE IDs" value={form.cve_ids} onChange={set('cve_ids')} placeholder="CVE-2024-1234, CVE-2024-5678" hint="Comma-separated" />
          <Input label="Tags" value={form.tags} onChange={set('tags')} placeholder="rce, apache, java" hint="Comma-separated" />
        </div>

        <Input label="Source URL" value={form.source_url} onChange={set('source_url')} placeholder="https://nvd.nist.gov/vuln/detail/CVE-2024-1234" type="url" />

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 16px', borderRadius: 10, background: T.elev, border: `1px solid ${T.border}` }}>
          <button type="button" onClick={() => set('published')(!form.published)}
            style={{ width: 36, height: 20, borderRadius: 10, border: 'none', background: form.published ? T.secure : T.dim, cursor: 'pointer', position: 'relative', transition: 'background 200ms', flexShrink: 0 }}>
            <div style={{ position: 'absolute', top: 3, left: form.published ? 18 : 3, width: 14, height: 14, borderRadius: '50%', background: 'white', transition: 'left 200ms', boxShadow: '0 1px 3px rgba(0,0,0,0.3)' }} />
          </button>
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: T.text, margin: 0 }}>
              {form.published ? 'Published' : 'Draft'}
            </p>
            <p style={{ fontSize: 11, color: T.dim, margin: 0 }}>
              {form.published ? 'Visible to the public' : 'Only visible to admins'}
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', paddingTop: 8, borderTop: `1px solid ${T.borderSubtle}` }}>
          <button type="button" onClick={onCancel}
            style={{ padding: '9px 20px', borderRadius: 9, fontSize: 13, fontWeight: 600, background: T.elev, border: `1px solid ${T.border}`, color: T.muted, cursor: 'pointer', fontFamily: 'inherit' }}>
            Cancel
          </button>
          <button type="submit" disabled={saving}
            style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '9px 20px', borderRadius: 9, fontSize: 13, fontWeight: 700, background: 'linear-gradient(135deg, var(--color-primary), #4f46e5)', border: 'none', color: 'white', cursor: saving ? 'not-allowed' : 'pointer', fontFamily: 'inherit', opacity: saving ? 0.7 : 1 }}>
            {saving ? <RefreshCw size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <Save size={13} />}
            {saving ? 'Saving…' : article ? 'Save changes' : 'Publish article'}
          </button>
        </div>
      </form>
    </div>
  );
};

const NewsAdmin = ({ navigateTo }) => {
  useEffect(() => { document.title = 'News Admin — LaunchGuard'; }, []);
  const [articles, setArticles] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [editing, setEditing] = useState(null);
  const [isNew, setIsNew] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);
  const [deleteId, setDeleteId] = useState(null);
  const [toast, setToast] = useState(null);

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const fetchArticles = useCallback(async (p = 1) => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await apiJson(`/news/admin/all?page=${p}&per_page=20`, { auth: true });
      setArticles(data.articles || []);
      setTotal(data.total);
      setPage(data.page);
      setPages(data.pages);
    } catch (e) {
      setError(e.message || 'Failed to load articles');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchArticles(1); }, [fetchArticles]);

  const handleSave = async (payload) => {
    setSaving(true);
    setSaveError(null);
    try {
      if (editing && !isNew) {
        await apiJson(`/news/${editing.id}`, { method: 'PATCH', auth: true, json: true, body: payload });
        showToast('Article updated');
      } else {
        await apiJson('/news', { method: 'POST', auth: true, json: true, body: payload });
        showToast('Article created');
      }
      setEditing(null);
      setIsNew(false);
      fetchArticles(page);
    } catch (e) {
      setSaveError(e instanceof ApiError ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id) => {
    setDeleteId(id);
    try {
      await apiJson(`/news/${id}`, { method: 'DELETE', auth: true, json: true });
      showToast('Article deleted');
      fetchArticles(page);
    } catch (e) {
      showToast(e.message || 'Delete failed', 'error');
    } finally {
      setDeleteId(null);
    }
  };

  const handleEditLoad = async (article) => {
    try {
      const { data } = await apiJson(`/news/admin/all?page=1&per_page=1`, { auth: true });
      const full = await apiJson(`/news/${article.slug}`, { auth: false }).catch(() => ({ data: article }));
      setEditing({ ...article, body: full.data?.body || '' });
      setIsNew(false);
    } catch {
      setEditing(article);
      setIsNew(false);
    }
  };

  const filtered = search
    ? (articles || []).filter(a => a.title.toLowerCase().includes(search.toLowerCase()) || a.category.toLowerCase().includes(search.toLowerCase()))
    : (articles || []);

  if (editing || isNew) {
    return (
      <div className="min-h-screen" style={{ background: T.bg }}>
        <div className="page-header px-6 lg:px-10 py-4 flex items-center gap-3">
          <button onClick={() => { setEditing(null); setIsNew(false); setSaveError(null); }}
            className="btn-secondary flex items-center gap-1.5 text-xs">
            <ChevronLeft size={13} /> Back to CMS
          </button>
          <span style={{ fontSize: 13, color: T.dim }}>·</span>
          <span style={{ fontSize: 13, color: T.muted }}>{isNew ? 'New article' : 'Edit article'}</span>
        </div>
        <div className="px-6 lg:px-10 py-6 max-w-4xl mx-auto">
          <ArticleForm
            article={isNew ? null : editing}
            onSave={handleSave}
            onCancel={() => { setEditing(null); setIsNew(false); setSaveError(null); }}
            saving={saving}
            error={saveError}
          />
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  return (
    <div className="min-h-screen" style={{ background: T.bg }}>
      {/* Toast */}
      {toast && (
        <div style={{ position: 'fixed', bottom: 24, right: 24, zIndex: 100, padding: '12px 20px', borderRadius: 10, background: toast.type === 'error' ? T.dangerDim : T.secureDim, border: `1px solid ${toast.type === 'error' ? T.danger : T.secure}40`, color: toast.type === 'error' ? T.danger : T.secure, fontSize: 13, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 8, boxShadow: '0 8px 32px rgba(0,0,0,0.4)' }}>
          {toast.type === 'error' ? <AlertTriangle size={14} /> : <CheckCircle size={14} />}
          {toast.msg}
        </div>
      )}

      <div className="page-header px-6 lg:px-10 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-base font-bold" style={{ color: T.text }}>Security News CMS</h1>
          <p className="text-xs mt-0.5" style={{ color: T.muted }}>{total} article{total !== 1 ? 's' : ''} total</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => navigateTo('news')}
            className="btn-secondary text-xs flex items-center gap-1.5">
            <Eye size={12} /> View public
          </button>
          <button onClick={() => { setIsNew(true); setSaveError(null); }}
            className="btn-primary text-xs flex items-center gap-1.5">
            <Plus size={12} /> New article
          </button>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6">
        {/* Search */}
        <div className="relative mb-5" style={{ maxWidth: 400 }}>
          <Search size={13} color={T.dim} style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter articles…"
            className="w-full"
            style={{ paddingLeft: 34, paddingRight: 12, paddingTop: 8, paddingBottom: 8, borderRadius: 9, background: T.card, border: `1px solid ${T.border}`, color: T.text, fontSize: 13, fontFamily: 'inherit', outline: 'none' }} />
        </div>

        {error && (
          <div className="mb-4 rounded-xl px-4 py-3 text-xs flex items-center gap-2"
            style={{ background: T.dangerDim, color: T.danger, border: `1px solid ${T.danger}30` }}>
            <AlertTriangle size={13} /> {error}
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-20">
            <RefreshCw size={18} color={T.muted} style={{ animation: 'spin 1s linear infinite' }} />
          </div>
        ) : (
          <div className="card overflow-hidden">
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: T.surface, borderBottom: `1px solid ${T.border}` }}>
                  {['Title', 'Category', 'Severity', 'Status', 'Published', 'Actions'].map((h) => (
                    <th key={h} style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 700, color: T.dim, letterSpacing: '0.06em', textTransform: 'uppercase', fontFamily: "var(--font-mono)", whiteSpace: 'nowrap' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ padding: '48px 16px', textAlign: 'center', color: T.muted, fontSize: 13 }}>
                      No articles yet. Create your first one.
                    </td>
                  </tr>
                ) : filtered.map((a) => (
                  <tr key={a.id} style={{ borderBottom: `1px solid ${T.borderSubtle}` }}
                    onMouseEnter={e => e.currentTarget.style.background = T.surface}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                    <td style={{ padding: '12px 16px', maxWidth: 300 }}>
                      <p className="text-sm font-semibold truncate" style={{ color: T.text, maxWidth: 260 }}>{a.title}</p>
                      <p className="text-xs mt-0.5 font-mono truncate" style={{ color: T.dim, maxWidth: 260 }}>{a.slug}</p>
                    </td>
                    <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                      <span style={{ fontSize: 11, padding: '3px 8px', borderRadius: 6, background: T.elev, color: T.muted, fontFamily: "var(--font-mono)" }}>{a.category}</span>
                    </td>
                    <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                      {a.severity ? (
                        <span style={{ fontSize: 11, padding: '3px 8px', borderRadius: 6, fontFamily: "var(--font-mono)", fontWeight: 700,
                          color: a.severity === 'Critical' ? T.danger : a.severity === 'High' ? T.warn : a.severity === 'Medium' ? T.info : T.secure,
                          background: a.severity === 'Critical' ? T.dangerDim : a.severity === 'High' ? T.warnDim : a.severity === 'Medium' ? T.infoDim : T.secureDim,
                        }}>{a.severity}</span>
                      ) : <span style={{ fontSize: 11, color: T.dim }}>—</span>}
                    </td>
                    <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {a.published
                          ? <><CheckCircle size={12} color="var(--color-secure)" /><span style={{ fontSize: 12, color: 'var(--color-secure)' }}>Published</span></>
                          : <><EyeOff size={12} color={T.dim} /><span style={{ fontSize: 12, color: T.dim }}>Draft</span></>}
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                      <span style={{ fontSize: 12, color: T.muted, fontFamily: "var(--font-mono)" }}>{fmt(a.published_at)}</span>
                    </td>
                    <td style={{ padding: '12px 16px', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button onClick={() => handleEditLoad(a)}
                          style={{ padding: '5px 10px', borderRadius: 7, fontSize: 12, background: T.elev, border: `1px solid ${T.border}`, color: T.muted, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'inherit' }}>
                          <Edit2 size={11} /> Edit
                        </button>
                        <button onClick={() => handleDelete(a.id)} disabled={deleteId === a.id}
                          style={{ padding: '5px 10px', borderRadius: 7, fontSize: 12, background: T.dangerDim, border: `1px solid ${T.danger}30`, color: T.danger, cursor: deleteId === a.id ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'inherit', opacity: deleteId === a.id ? 0.6 : 1 }}>
                          {deleteId === a.id ? <RefreshCw size={11} style={{ animation: 'spin 1s linear infinite' }} /> : <Trash2 size={11} />} Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {pages > 1 && (
              <div style={{ padding: '16px', borderTop: `1px solid ${T.borderSubtle}`, display: 'flex', justifyContent: 'center', gap: 6 }}>
                {page > 1 && (
                  <button onClick={() => fetchArticles(page - 1)}
                    style={{ padding: '6px 14px', borderRadius: 7, fontSize: 12, background: T.elev, border: `1px solid ${T.border}`, color: T.muted, cursor: 'pointer', fontFamily: 'inherit' }}>
                    Previous
                  </button>
                )}
                {Array.from({ length: Math.min(pages, 7) }, (_, i) => i + 1).map((p) => (
                  <button key={p} onClick={() => fetchArticles(p)}
                    style={{ padding: '6px 10px', borderRadius: 7, fontSize: 12, background: p === page ? T.primary : T.elev, border: `1px solid ${p === page ? T.primary : T.border}`, color: p === page ? 'white' : T.muted, cursor: 'pointer', fontFamily: 'inherit', minWidth: 32 }}>
                    {p}
                  </button>
                ))}
                {page < pages && (
                  <button onClick={() => fetchArticles(page + 1)}
                    style={{ padding: '6px 14px', borderRadius: 7, fontSize: 12, background: T.elev, border: `1px solid ${T.border}`, color: T.muted, cursor: 'pointer', fontFamily: 'inherit' }}>
                    Next
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
};

export default NewsAdmin;
