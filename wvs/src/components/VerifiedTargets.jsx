import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  CheckCircle2,
  Copy,
  ExternalLink,
  Globe,
  KeyRound,
  RefreshCw,
  Shield,
  Trash2,
  AlertTriangle,
  ClipboardCopy,
} from 'lucide-react';
import { useVerifiedTargetsData } from '../hooks/useVerifiedTargetsData';
import Spinner from './Spinner';

const STATUS_STYLES = {
  verified: { background: 'var(--color-secure-dim)',  color: 'var(--color-secure)' },
  pending:  { background: 'var(--color-warn-dim)',    color: 'var(--color-warn)' },
  failed:   { background: 'var(--color-danger-dim)',  color: 'var(--color-danger)' },
  expired:  { background: 'var(--color-danger-dim)',  color: 'var(--color-danger)' },
  revoked:  { background: 'var(--color-danger-dim)',  color: 'var(--color-danger)' },
};

const MethodPill = ({ method }) => (
  <span className="badge" style={{ background: 'var(--color-primary-dim)', color: 'var(--color-primary)' }}>
    {method === 'well_known_file' ? 'Well-Known File' : 'Meta Tag'}
  </span>
);

const StatusPill = ({ status }) => (
  <span className="badge" style={STATUS_STYLES[status] || { background: 'var(--color-primary-dim)', color: 'var(--color-primary)' }}>
    {status}
  </span>
);

const CodeBlock = ({ value }) => {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };
  return (
    <div className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--color-border-subtle)', background: 'var(--color-elevated)' }}>
      <div className="flex items-center justify-between px-3 py-2" style={{ borderBottom: '1px solid var(--color-border-subtle)' }}>
        <span className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Value</span>
        <button type="button" onClick={copy}
          className="flex items-center gap-1.5 text-xs"
          style={{ color: copied ? 'var(--color-secure)' : 'var(--color-primary)' }}>
          <ClipboardCopy size={11} />
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <pre className="px-3 py-2 text-xs break-all whitespace-pre-wrap font-mono" style={{ color: 'var(--color-text)' }}>
        {value}
      </pre>
    </div>
  );
};

// Per-target card that manages its own token input and instructions state
const TargetCard = ({ target, onVerify, onRegenerate, onDelete, working }) => {
  const [tokenInput, setTokenInput] = useState(target.verification_token || '');
  const [freshToken, setFreshToken] = useState(null);
  const [freshInstructions, setFreshInstructions] = useState(target.instructions || null);
  const [cardError, setCardError] = useState(null);

  const handleRegenerate = async () => {
    setCardError(null);
    const result = await onRegenerate(target);
    if (result) {
      setFreshToken(result.verification_token);
      setFreshInstructions(result.instructions);
      setTokenInput(result.verification_token);
    }
  };

  const handleVerify = async () => {
    const token = tokenInput.trim();
    if (!token) {
      setCardError('Paste your verification token before checking ownership.');
      return;
    }
    setCardError(null);
    await onVerify(target, token);
  };

  const isWorking = working === target.id;
  const isVerified = target.verification_status === 'verified';

  return (
    <article className="rounded-xl flex flex-col gap-0 overflow-hidden"
      style={{ border: `1px solid ${isVerified ? 'rgba(34,197,94,0.25)' : 'var(--color-border-subtle)'}`, background: 'var(--color-surface)' }}>

      {/* Header */}
      <div className="flex items-start justify-between gap-3 px-4 pt-4 pb-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-semibold truncate" style={{ color: 'var(--color-text)' }}>
              {target.normalized_domain}
            </p>
            <StatusPill status={target.verification_status} />
            <MethodPill method={target.verification_method} />
          </div>
          <a href={target.target_url} target="_blank" rel="noreferrer"
            className="mt-1 inline-flex items-center gap-1.5 text-xs break-all"
            style={{ color: 'var(--color-text-dim)' }}>
            {target.target_url}
            <ExternalLink size={11} />
          </a>
        </div>
        <button type="button" onClick={() => onDelete(target)}
          className="btn-secondary text-xs flex-shrink-0"
          style={{ color: 'var(--color-danger)', borderColor: 'rgba(239,68,68,0.2)', background: 'var(--color-danger-dim)' }}>
          <Trash2 size={12} />
        </button>
      </div>

      {cardError && (
        <div className="mx-4 mb-2 flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
          style={{ background: 'var(--color-danger-dim)', color: 'var(--color-danger)' }}>
          <AlertTriangle size={12} /> {cardError}
        </div>
      )}

      {/* Token + instructions — shown whenever token is available */}
      {(() => {
        const activeInstructions = freshInstructions || target.instructions;
        const activeToken = freshToken || target.verification_token;
        if (!activeToken && !activeInstructions) return null;
        return (
          <div className="mx-4 mb-3 rounded-xl flex flex-col gap-3 p-4"
            style={{ background: 'var(--color-elevated)', border: '1px solid var(--color-border-subtle)' }}>
            {freshToken && (
              <p className="text-xs font-semibold" style={{ color: 'var(--color-warn)' }}>
                New token generated.
              </p>
            )}
            {activeToken && <CodeBlock value={activeToken} />}
            {activeInstructions?.method === 'well_known_file' ? (
              <div className="flex flex-col gap-2">
                <p className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                  Create this file on your server:
                </p>
                <CodeBlock value={`${activeInstructions.path}`} />
                <p className="text-xs font-medium mt-1" style={{ color: 'var(--color-text-muted)' }}>
                  File contents (paste exactly):
                </p>
                <CodeBlock value={activeInstructions.content} />
                <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>
                  Must be accessible at:{' '}
                  <a href={activeInstructions.verification_url} target="_blank" rel="noreferrer"
                    className="font-mono" style={{ color: 'var(--color-info)' }}>
                    {activeInstructions.verification_url}
                  </a>
                </p>
              </div>
            ) : activeInstructions?.method === 'meta_tag' ? (
              <div className="flex flex-col gap-2">
                <p className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
                  Add this inside your site's &lt;head&gt;:
                </p>
                <CodeBlock value={activeInstructions.tag} />
              </div>
            ) : null}
          </div>
        );
      })()}

      {/* Token input + actions */}
      {!isVerified && (
        <div className="px-4 pb-4 flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
              Verification Token
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                className="input text-xs font-mono flex-1"
                placeholder="Paste your token here…"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
              />
              <button type="button" onClick={handleVerify}
                disabled={isWorking || !tokenInput.trim()}
                className="btn-primary text-xs flex-shrink-0 disabled:opacity-50">
                {isWorking ? <><Spinner size="sm" /> Checking…</> : 'Verify Now'}
              </button>
            </div>
            <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>
              Don't have the token? Click <strong>Regenerate</strong> to get a new one.
            </p>
          </div>
          <button type="button" onClick={handleRegenerate}
            disabled={isWorking}
            className="btn-secondary text-xs w-fit disabled:opacity-50">
            <RefreshCw size={12} /> Regenerate Token
          </button>
        </div>
      )}

      {isVerified && (
        <div className="px-4 pb-4">
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
            style={{ background: 'var(--color-secure-dim)', color: 'var(--color-secure)' }}>
            <CheckCircle2 size={12} />
            Verified {target.verified_at ? `on ${new Date(target.verified_at).toLocaleString()}` : ''}
          </div>
        </div>
      )}

      <div className="px-4 pb-3 text-xs font-mono" style={{ color: 'var(--color-text-dim)' }}>
        Created: {target.created_at ? new Date(target.created_at).toLocaleString() : '—'}
      </div>
    </article>
  );
};


const VerifiedTargets = ({ navigateTo }) => {
  useEffect(() => { document.title = 'Verified Targets — LaunchGuard'; }, []);
  const { targets, loading, error, createTarget, verifyTarget, regenerateToken, deleteTarget } = useVerifiedTargetsData();

  const [newTargetUrl, setNewTargetUrl] = useState('');
  const [newTargetMethod, setNewTargetMethod] = useState('meta_tag');
  const [workingId, setWorkingId] = useState(null);
  const [pageError, setPageError] = useState(null);
  const [success, setSuccess] = useState(null);

  // After create: show the new token + instructions in the left panel
  const [createdToken, setCreatedToken] = useState(null);
  const [createdInstructions, setCreatedInstructions] = useState(null);

  const sortedTargets = useMemo(() => (
    [...targets].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))
  ), [targets]);

  const handleCreate = async (e) => {
    e.preventDefault();
    setPageError(null); setSuccess(null); setWorkingId('create');
    setCreatedToken(null); setCreatedInstructions(null);
    try {
      const result = await createTarget({ target_url: newTargetUrl, verification_method: newTargetMethod });
      setCreatedToken(result.verification_token);
      setCreatedInstructions(result.instructions);
      setSuccess(`Token generated for ${result.target.normalized_domain}. Copy it and add it to your site.`);
      setNewTargetUrl('');
    } catch (err) {
      setPageError(err.message || 'Failed to create verified target');
    } finally { setWorkingId(null); }
  };

  const handleVerify = async (target, token) => {
    setPageError(null); setSuccess(null); setWorkingId(target.id);
    try {
      await verifyTarget(target.id, token);
      setSuccess(`Ownership verified for ${target.normalized_domain}.`);
    } catch (err) {
      setPageError(err.message || 'Verification failed');
    } finally { setWorkingId(null); }
  };

  const handleRegenerate = async (target) => {
    setPageError(null); setSuccess(null); setWorkingId(target.id);
    try {
      const result = await regenerateToken(target.id);
      setSuccess(`New token generated for ${result.target.normalized_domain}.`);
      return result;
    } catch (err) {
      setPageError(err.message || 'Failed to generate a new token');
      return null;
    } finally { setWorkingId(null); }
  };

  const handleDelete = async (target) => {
    setPageError(null); setSuccess(null); setWorkingId(target.id);
    try {
      await deleteTarget(target.id);
      setSuccess(`Removed ${target.normalized_domain} from verified targets.`);
    } catch (err) {
      setPageError(err.message || 'Failed to remove target');
    } finally { setWorkingId(null); }
  };

  return (
    <div className="min-h-screen" style={{ background: 'var(--color-bg)' }}>

      {/* Page header */}
      <div className="page-header px-6 lg:px-10 py-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button onClick={() => navigateTo('scanners')} className="btn-secondary flex items-center gap-1.5 text-xs">
            <ArrowLeft size={13} /> Back
          </button>
          <div style={{ borderLeft: '2px solid var(--color-primary)', paddingLeft: 10 }}>
            <h1 style={{ fontSize: 14, fontWeight: 700, color: 'var(--color-text)', letterSpacing: '-0.02em', margin: 0 }}>Verified Targets</h1>
            <p style={{ fontSize: 10, color: 'var(--color-text-dim)', fontFamily: "var(--font-mono)", marginTop: 2 }}>Manage ownership verification before running product-readiness scans.</p>
          </div>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6 flex flex-col gap-6">
        {(error || pageError) && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl"
            style={{ background: 'var(--color-danger-dim)', border: '1px solid rgba(239,68,68,0.2)', color: 'var(--color-danger)' }}>
            <AlertTriangle size={14} />
            {pageError || error}
          </div>
        )}
        {success && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl"
            style={{ background: 'var(--color-secure-dim)', border: '1px solid rgba(34,197,94,0.2)', color: 'var(--color-secure)' }}>
            <CheckCircle2 size={14} />
            {success}
          </div>
        )}

        <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)] gap-6 items-start">

          {/* Add target panel */}
          <section className="card p-5 flex flex-col gap-5">
            <div style={{ borderLeft: '2px solid var(--color-primary)', paddingLeft: 10 }}>
              <h2 style={{ fontSize: 13, fontWeight: 700, color: 'var(--color-text)', letterSpacing: '-0.02em', margin: 0 }}>Add a Target</h2>
              <p style={{ fontSize: 10, color: 'var(--color-text-dim)', fontFamily: "var(--font-mono)", marginTop: 2 }}>Generate a token, add it to your site, then verify.</p>
            </div>

            <form className="flex flex-col gap-4" onSubmit={handleCreate}>
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Target URL</label>
                <input type="url" required value={newTargetUrl}
                  onChange={(e) => setNewTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="input text-sm" />
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>Verification Method</label>
                <select value={newTargetMethod}
                  onChange={(e) => setNewTargetMethod(e.target.value)}
                  className="input text-sm cursor-pointer">
                  <option value="meta_tag">HTML Meta Tag</option>
                  <option value="well_known_file">Well-Known File</option>
                </select>
              </div>
              <button type="submit" disabled={workingId === 'create'}
                className="btn-primary justify-center" style={{ opacity: workingId === 'create' ? 0.75 : 1 }}>
                {workingId === 'create' ? <><Spinner size="sm" /> Generating…</> : 'Create Verification Token'}
              </button>
            </form>

            {/* Token + instructions shown immediately after create */}
            {createdToken && (
              <div className="flex flex-col gap-3 rounded-xl p-4"
                style={{ background: 'var(--color-elevated)', border: '1px solid var(--color-border-subtle)' }}>
                <div className="flex items-center gap-2">
                  <KeyRound size={13} style={{ color: 'var(--color-warn)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--color-warn)' }}>
                    Copy this token — it won't be shown again
                  </p>
                </div>
                <CodeBlock value={createdToken} />

                {createdInstructions?.method === 'well_known_file' ? (
                  <div className="flex flex-col gap-2">
                    <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)' }}>
                      Step 1 — Create this file on your server:
                    </p>
                    <CodeBlock value={`${createdInstructions.path}`} />
                    <p className="text-xs font-semibold mt-1" style={{ color: 'var(--color-text-muted)' }}>
                      Step 2 — File contents (paste exactly):
                    </p>
                    <CodeBlock value={createdInstructions.content} />
                    <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>
                      Must be reachable at:{' '}
                      <a href={createdInstructions.verification_url} target="_blank" rel="noreferrer"
                        className="font-mono" style={{ color: 'var(--color-info)' }}>
                        {createdInstructions.verification_url}
                      </a>
                    </p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-2">
                    <p className="text-xs font-semibold" style={{ color: 'var(--color-text-muted)' }}>
                      Add this inside your site's &lt;head&gt;:
                    </p>
                    <CodeBlock value={createdInstructions?.tag || ''} />
                  </div>
                )}

                <p className="text-xs" style={{ color: 'var(--color-text-dim)' }}>
                  Once the file or tag is live, find the target below and paste the token to verify.
                </p>
              </div>
            )}

            {/* Scan safety notice */}
            <div className="rounded-xl p-4" style={{ background: 'var(--color-elevated)', border: '1px solid var(--color-border-subtle)' }}>
              <p className="section-label mb-3">Scan Safety</p>
              <ul className="flex flex-col gap-2 text-xs" style={{ color: 'var(--color-text-dim)' }}>
                <li className="flex items-start gap-2"><Shield size={12} className="mt-0.5 flex-shrink-0" /> Product-readiness scans should only target systems you control.</li>
                <li className="flex items-start gap-2"><KeyRound size={12} className="mt-0.5 flex-shrink-0" /> Tokens are only shown on creation or regeneration.</li>
                <li className="flex items-start gap-2"><RefreshCw size={12} className="mt-0.5 flex-shrink-0" /> Re-scan after fixes to confirm launch blockers are resolved.</li>
              </ul>
            </div>
          </section>

          {/* Saved targets panel */}
          <section className="card p-5">
            <div className="flex items-center justify-between gap-3 mb-5">
              <div>
                <h2 className="text-sm font-semibold" style={{ color: 'var(--color-text)' }}>Saved Targets</h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-dim)' }}>
                  Paste the token into a target card and click Verify Now.
                </p>
              </div>
              <span className="badge" style={{ background: 'var(--color-elevated)', color: 'var(--color-text-muted)' }}>
                {sortedTargets.length} total
              </span>
            </div>

            <div className="flex flex-col gap-4">
              {loading && (
                <div className="flex items-center justify-center py-10 rounded-xl" style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border-subtle)' }}>
                  <Spinner size="md" label="Loading targets…" />
                </div>
              )}

              {!loading && sortedTargets.length === 0 && (
                <div className="flex flex-col items-center gap-3 py-10 rounded-xl text-center"
                  style={{ background: 'var(--color-surface)', border: '1px solid var(--color-border-subtle)' }}>
                  <Shield size={20} style={{ color: 'var(--color-text-dim)' }} />
                  <p className="text-sm" style={{ color: 'var(--color-text-dim)' }}>No verified targets yet.</p>
                </div>
              )}

              {sortedTargets.map((target) => (
                <TargetCard
                  key={target.id}
                  target={target}
                  working={workingId}
                  onVerify={handleVerify}
                  onRegenerate={handleRegenerate}
                  onDelete={handleDelete}
                />
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default VerifiedTargets;
