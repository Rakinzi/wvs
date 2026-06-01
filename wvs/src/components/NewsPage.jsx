import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield, ArrowLeft, AlertTriangle, ChevronRight, RefreshCw,
  Tag, ExternalLink, Clock, Search, Filter, ChevronDown,
} from 'lucide-react';
import { apiJson } from '../lib/api';
import Footer from './Footer';
import PublicNav from './PublicNav';

const T = {
  bg:      'var(--color-bg)',
  surface: 'var(--color-surface)',
  card:    'var(--color-card)',
  elev:    'var(--color-elevated)',
  border:  'var(--color-border)',
  borderSubtle: 'var(--color-border-subtle)',
  text:    'var(--color-text)',
  muted:   'var(--color-text-muted)',
  dim:     'var(--color-text-dim)',
  primary: 'var(--color-primary)',
  danger:  'var(--color-danger)',
  dangerDim: 'var(--color-danger-dim)',
  warn:    'var(--color-warn)',
  warnDim: 'var(--color-warn-dim)',
  info:    'var(--color-info)',
  infoDim: 'var(--color-info-dim)',
  secure:  'var(--color-secure)',
  secureDim: 'var(--color-secure-dim)',
  purple:  'var(--color-info)',
  purpleDim: 'var(--color-info-dim)',
};

const CATEGORIES = ['All', 'Vulnerability', 'Advisory', 'Research', 'Tool', 'General'];
const SEVERITIES = ['All', 'Critical', 'High', 'Medium', 'Low'];

const severityColor = (s) => {
  if (!s) return { color: T.muted, bg: T.elev };
  const sl = s.toLowerCase();
  if (sl === 'critical') return { color: T.danger, bg: T.dangerDim };
  if (sl === 'high') return { color: T.warn, bg: T.warnDim };
  if (sl === 'medium') return { color: T.info, bg: T.infoDim };
  return { color: T.secure, bg: T.secureDim };
};

const fmt = (d) => {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
};

const ArticleCard = ({ article, onClick }) => {
  const sev = severityColor(article.severity);
  return (
    <button onClick={() => onClick(article)}
      style={{ background: T.card, border: `1px solid ${T.border}`, borderRadius: 10, padding: 0, textAlign: 'left', width: '100%', cursor: 'pointer', transition: 'border-color 200ms', fontFamily: 'inherit', overflow: 'hidden' }}
      onMouseEnter={e => e.currentTarget.style.borderColor = T.primary + '60'}
      onMouseLeave={e => e.currentTarget.style.borderColor = T.border}>
      {article.image_url && (
        <div style={{ height: 150, background: T.elev, borderBottom: `1px solid ${T.borderSubtle}` }}>
          <img
            src={article.image_url}
            alt={article.image_alt || ''}
            loading="lazy"
            style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }}
          />
        </div>
      )}
      <div style={{ padding: 24 }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
          <span style={{ padding: '3px 10px', borderRadius: 100, fontSize: 11, fontWeight: 700, background: T.elev, color: T.muted, fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.04em' }}>
            {article.category}
          </span>
          {article.severity && (
            <span style={{ padding: '3px 10px', borderRadius: 100, fontSize: 11, fontWeight: 700, background: sev.bg, color: sev.color, fontFamily: "'IBM Plex Mono', monospace" }}>
              {article.severity.toUpperCase()}
            </span>
          )}
        </div>
        <p style={{ fontWeight: 700, fontSize: 16, color: T.text, lineHeight: 1.4, marginBottom: 10 }}>{article.title}</p>
        <p style={{ fontSize: 13, color: T.muted, lineHeight: 1.6, marginBottom: 16 }}>{article.summary}</p>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={12} color={T.dim} />
            <span style={{ fontSize: 12, color: T.dim, fontFamily: "'IBM Plex Mono', monospace" }}>{fmt(article.published_at)}</span>
            {article.author && <span style={{ fontSize: 12, color: T.dim }}>· {article.author}</span>}
          </div>
          {(article.cve_ids || []).length > 0 && (
            <span style={{ fontSize: 11, fontFamily: "'IBM Plex Mono', monospace", color: T.purple, background: T.purpleDim, padding: '2px 8px', borderRadius: 6 }}>
              {article.cve_ids[0]}{article.cve_ids.length > 1 ? ` +${article.cve_ids.length - 1}` : ''}
            </span>
          )}
        </div>
        {(article.tags || []).length > 0 && (
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 12, paddingTop: 12, borderTop: `1px solid ${T.borderSubtle}` }}>
            {article.tags.slice(0, 4).map((t) => (
              <span key={t} style={{ fontSize: 11, color: T.dim, display: 'flex', alignItems: 'center', gap: 4 }}>
                <Tag size={9} /> {t}
              </span>
            ))}
          </div>
        )}
      </div>
    </button>
  );
};

const ArticleDetail = ({ article, onBack }) => {
  const sev = severityColor(article.severity);
  return (
    <div style={{ maxWidth: 760, margin: '0 auto' }}>
      <button onClick={onBack}
        style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginBottom: 32, background: 'none', border: `1px solid ${T.border}`, borderRadius: 8, padding: '7px 14px', color: T.muted, cursor: 'pointer', fontSize: 13, fontFamily: 'inherit', transition: 'border-color 150ms' }}
        onMouseEnter={e => e.currentTarget.style.borderColor = T.dim}
        onMouseLeave={e => e.currentTarget.style.borderColor = T.border}>
        <ArrowLeft size={13} /> Back to news
      </button>

      <div style={{ background: T.card, border: `1px solid ${T.border}`, borderRadius: 16, overflow: 'hidden' }}>
        {article.image_url && (
          <div style={{ height: 'min(340px, 44vw)', minHeight: 190, background: T.elev, borderBottom: `1px solid ${T.borderSubtle}` }}>
            <img
              src={article.image_url}
              alt={article.image_alt || ''}
              style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }}
            />
          </div>
        )}
        <div style={{ padding: '36px 36px' }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 20 }}>
          <span style={{ padding: '4px 12px', borderRadius: 100, fontSize: 12, fontWeight: 700, background: T.elev, color: T.muted, fontFamily: "'IBM Plex Mono', monospace" }}>
            {article.category}
          </span>
          {article.severity && (
            <span style={{ padding: '4px 12px', borderRadius: 100, fontSize: 12, fontWeight: 700, background: sev.bg, color: sev.color, fontFamily: "'IBM Plex Mono', monospace" }}>
              {article.severity.toUpperCase()}
            </span>
          )}
          {(article.cve_ids || []).map((c) => (
            <span key={c} style={{ padding: '4px 12px', borderRadius: 100, fontSize: 12, fontWeight: 700, background: T.purpleDim, color: T.purple, fontFamily: "'IBM Plex Mono', monospace" }}>
              {c}
            </span>
          ))}
        </div>

        <h1 style={{ fontSize: 'clamp(22px, 3vw, 30px)', fontWeight: 800, color: T.text, lineHeight: 1.3, letterSpacing: '-0.02em', marginBottom: 16 }}>
          {article.title}
        </h1>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 28, paddingBottom: 24, borderBottom: `1px solid ${T.border}` }}>
          <div style={{ width: 28, height: 28, borderRadius: '50%', background: T.primary + '30', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700, color: T.primary }}>
            {(article.author || 'L')[0].toUpperCase()}
          </div>
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: T.text }}>{article.author || 'LaunchGuard Security Team'}</p>
            <p style={{ fontSize: 12, color: T.dim, fontFamily: "'IBM Plex Mono', monospace" }}>{fmt(article.published_at)}</p>
          </div>
          {article.source_url && (
            <a href={article.source_url} target="_blank" rel="noopener noreferrer"
              style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: T.primary, textDecoration: 'none', padding: '5px 10px', borderRadius: 7, background: T.primary + '12', border: `1px solid ${T.primary}30` }}>
              Source <ExternalLink size={11} />
            </a>
          )}
        </div>

        <p style={{ fontSize: 15, color: T.muted, lineHeight: 1.7, marginBottom: 28, fontStyle: 'italic', borderLeft: `3px solid ${T.primary}`, paddingLeft: 16 }}>
          {article.summary}
        </p>

        <div style={{ fontSize: 14, color: T.muted, lineHeight: 1.8, whiteSpace: 'pre-wrap' }}>
          {article.body}
        </div>

        {(article.tags || []).length > 0 && (
          <div style={{ marginTop: 32, paddingTop: 24, borderTop: `1px solid ${T.border}`, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <Tag size={12} color={T.dim} />
            {article.tags.map((t) => (
              <span key={t} style={{ padding: '4px 10px', borderRadius: 8, fontSize: 12, background: T.elev, color: T.dim, border: `1px solid ${T.border}` }}>{t}</span>
            ))}
          </div>
        )}
        </div>
      </div>
    </div>
  );
};


const NewsPage = ({ navigateTo, isAuthenticated }) => {
  const [articles, setArticles] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [category, setCategory] = useState('All');
  const [severity, setSeverity] = useState('All');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [filterOpen, setFilterOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const fetchArticles = useCallback(async (p = 1) => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ page: p, per_page: 12 });
      if (category !== 'All') params.set('category', category);
      if (severity !== 'All') params.set('severity', severity);
      const { data } = await apiJson(`/news?${params}`);
      const payload = data.data;
      setArticles(payload.articles);
      setTotal(payload.total);
      setPage(payload.page);
      setPages(payload.pages);
    } catch (e) {
      setError(e.message || 'Failed to load news');
    } finally {
      setLoading(false);
    }
  }, [category, severity]);

  useEffect(() => { fetchArticles(1); }, [fetchArticles]);

  const handleSelect = async (article) => {
    setDetailLoading(true);
    setSelected(article);
    try {
      const { data } = await apiJson(`/news/${article.slug}`);
      setSelected(data.data);
    } catch {
      // use the list article data as fallback
    } finally {
      setDetailLoading(false);
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const filtered = search
    ? articles.filter(a =>
        a.title.toLowerCase().includes(search.toLowerCase()) ||
        a.summary.toLowerCase().includes(search.toLowerCase()) ||
        (a.tags || []).some(t => t.toLowerCase().includes(search.toLowerCase()))
      )
    : articles;

  return (
    <div style={{ background: T.bg, minHeight: '100vh', color: T.text, fontFamily: "'Plus Jakarta Sans', system-ui, sans-serif" }}>

      {/* Navbar */}
      <PublicNav
        scrolled={scrolled}
        onLogoClick={() => navigateTo('landing')}
        onLogin={() => isAuthenticated ? navigateTo('dashboard') : navigateTo('login')}
        isAuthenticated={isAuthenticated}
        breadcrumb="Security News"
      />

      <div style={{ maxWidth: 1040, margin: '0 auto', padding: '48px 24px' }}>

        {selected ? (
          detailLoading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
              <RefreshCw size={20} color={T.muted} style={{ animation: 'spin 1s linear infinite' }} />
            </div>
          ) : (
            <ArticleDetail article={selected} onBack={() => setSelected(null)} />
          )
        ) : (
          <>
            {/* Page header */}
            <div style={{ marginBottom: 40 }}>
              <p style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.12em', color: T.primary, marginBottom: 12, fontFamily: "'IBM Plex Mono', monospace" }}>SECURITY INTELLIGENCE</p>
              <h1 style={{ fontFamily: "'Syne', system-ui, sans-serif", fontSize: 'clamp(26px, 3.5vw, 38px)', fontWeight: 800, letterSpacing: '-0.04em', margin: '0 0 10px' }}>
                Security News & Advisories
              </h1>
              <p style={{ fontSize: 15, color: T.muted }}>
                Latest vulnerabilities, CVEs, and security research — curated for developers and security teams.
              </p>
            </div>

            {/* Search & filters */}
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 32, alignItems: 'center' }}>
              <div style={{ position: 'relative', flex: '1 1 240px' }}>
                <Search size={14} color={T.dim} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Search articles, tags, CVEs…"
                  style={{ width: '100%', paddingLeft: 36, paddingRight: 14, paddingTop: 8, paddingBottom: 8, borderRadius: 6, background: T.card, border: `1px solid ${T.border}`, color: T.text, fontSize: 13, fontFamily: 'inherit', outline: 'none', boxSizing: 'border-box' }}
                />
              </div>

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {CATEGORIES.map((c) => (
                  <button key={c} onClick={() => { setCategory(c); setPage(1); }}
                    style={{ padding: '6px 12px', borderRadius: 4, fontSize: 11, fontWeight: 600, background: category === c ? T.primary + '15' : T.card, border: `1px solid ${category === c ? T.primary + '50' : T.border}`, color: category === c ? T.primary : T.muted, cursor: 'pointer', fontFamily: "'IBM Plex Mono', monospace", letterSpacing: '0.04em', transition: 'all 150ms' }}>
                    {c}
                  </button>
                ))}
              </div>

              <div style={{ position: 'relative' }}>
                <button onClick={() => setFilterOpen(o => !o)}
                  style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', borderRadius: 8, fontSize: 12, fontWeight: 600, background: severity !== 'All' ? T.danger + '20' : T.card, border: `1px solid ${severity !== 'All' ? T.danger + '60' : T.border}`, color: severity !== 'All' ? T.danger : T.muted, cursor: 'pointer', fontFamily: 'inherit' }}>
                  <Filter size={12} /> Severity{severity !== 'All' ? `: ${severity}` : ''} <ChevronDown size={11} />
                </button>
                {filterOpen && (
                  <div style={{ position: 'absolute', top: 'calc(100% + 8px)', right: 0, background: T.elev, border: `1px solid ${T.border}`, borderRadius: 10, overflow: 'hidden', zIndex: 20, minWidth: 130 }}>
                    {SEVERITIES.map((s) => (
                      <button key={s} onClick={() => { setSeverity(s); setFilterOpen(false); setPage(1); }}
                        style={{ display: 'block', width: '100%', padding: '9px 14px', fontSize: 13, fontWeight: 600, background: severity === s ? T.primary + '15' : 'none', color: severity === s ? T.primary : T.muted, cursor: 'pointer', fontFamily: 'inherit', textAlign: 'left', border: 'none', borderBottom: `1px solid ${T.border}` }}>
                        {s}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Stats bar */}
            {!loading && (
              <p style={{ fontSize: 12, color: T.dim, marginBottom: 24, fontFamily: "'IBM Plex Mono', monospace" }}>
                {filtered.length} article{filtered.length !== 1 ? 's' : ''} {search ? `matching "${search}"` : `— page ${page} of ${pages}`}
              </p>
            )}

            {/* Grid */}
            {loading ? (
              <div style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
                <RefreshCw size={20} color={T.muted} style={{ animation: 'spin 1s linear infinite' }} />
              </div>
            ) : error ? (
              <div style={{ textAlign: 'center', padding: '80px 0', color: T.muted }}>
                <AlertTriangle size={32} color={T.danger} style={{ margin: '0 auto 12px', display: 'block' }} />
                <p style={{ fontSize: 14 }}>{error}</p>
                <button onClick={() => fetchArticles(page)}
                  style={{ marginTop: 16, padding: '8px 20px', borderRadius: 8, background: T.card, border: `1px solid ${T.border}`, color: T.muted, cursor: 'pointer', fontSize: 13, fontFamily: 'inherit' }}>
                  Retry
                </button>
              </div>
            ) : filtered.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '80px 0' }}>
                <Shield size={36} color={T.dim} style={{ margin: '0 auto 16px', display: 'block' }} />
                <p style={{ fontSize: 15, fontWeight: 600, color: T.text, marginBottom: 6 }}>No articles found</p>
                <p style={{ fontSize: 13, color: T.muted }}>Try adjusting your filters or check back soon.</p>
              </div>
            ) : (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
                  {filtered.map((a) => (
                    <ArticleCard key={a.id} article={a} onClick={handleSelect} />
                  ))}
                </div>

                {/* Pagination */}
                {pages > 1 && (
                  <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 40 }}>
                    {page > 1 && (
                      <button onClick={() => fetchArticles(page - 1)}
                        style={{ padding: '7px 16px', borderRadius: 8, fontSize: 13, background: T.card, border: `1px solid ${T.border}`, color: T.muted, cursor: 'pointer', fontFamily: 'inherit' }}>
                        Previous
                      </button>
                    )}
                    {Array.from({ length: Math.min(pages, 7) }, (_, i) => i + 1).map((p) => (
                      <button key={p} onClick={() => fetchArticles(p)}
                        style={{ padding: '7px 12px', borderRadius: 5, fontSize: 13, background: p === page ? T.primary : T.card, border: `1px solid ${p === page ? T.primary : T.border}`, color: p === page ? '#060608' : T.muted, cursor: 'pointer', fontFamily: "'IBM Plex Mono', monospace", fontWeight: p === page ? 700 : 400, minWidth: 36 }}>
                        {p}
                      </button>
                    ))}
                    {page < pages && (
                      <button onClick={() => fetchArticles(page + 1)}
                        style={{ padding: '7px 16px', borderRadius: 8, fontSize: 13, background: T.card, border: `1px solid ${T.border}`, color: T.muted, cursor: 'pointer', fontFamily: 'inherit' }}>
                        Next
                      </button>
                    )}
                  </div>
                )}
              </>
            )}
          </>
        )}
      </div>

      <Footer />

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @media (min-width: 768px) {
          .hidden-mobile { display: flex !important; }
          .show-desktop { display: block !important; }
        }
        @media (max-width: 767px) {
          .hidden-mobile { display: none !important; }
          .show-mobile { display: flex !important; }
        }
      `}</style>
    </div>
  );
};

export default NewsPage;
