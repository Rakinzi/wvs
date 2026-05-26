import React, { useMemo, useState } from 'react';
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
} from 'lucide-react';
import { useVerifiedTargetsData } from '../hooks/useVerifiedTargetsData';
import Spinner from './Spinner';

const T = {
  bg: 'var(--color-bg)',
  surface: 'var(--color-surface)',
  card: 'var(--color-card)',
  elevated: 'var(--color-elevated)',
  border: 'var(--color-border)',
  borderSubtle: 'var(--color-border-subtle)',
  text: 'var(--color-text)',
  muted: 'var(--color-text-muted)',
  dim: 'var(--color-text-dim)',
  primary: 'var(--color-primary)',
  primaryDim: 'var(--color-primary-dim)',
  secure: 'var(--color-secure)',
  secureDim: 'var(--color-secure-dim)',
  danger: 'var(--color-danger)',
  dangerDim: 'var(--color-danger-dim)',
  warn: 'var(--color-warn)',
};

const STATUS_STYLES = {
  verified: { background: '#10B98115', color: T.secure, border: '1px solid #10B98130' },
  pending: { background: '#F59E0B15', color: T.warn, border: '1px solid #F59E0B30' },
  failed: { background: '#F43F5E15', color: T.danger, border: '1px solid #F43F5E30' },
  expired: { background: '#F43F5E15', color: T.danger, border: '1px solid #F43F5E30' },
  revoked: { background: '#F43F5E15', color: T.danger, border: '1px solid #F43F5E30' },
};

const MethodPill = ({ method }) => (
  <span
    className="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold"
    style={{ background: T.primaryDim, color: T.primary, border: `1px solid ${T.primary}30` }}
  >
    {method === 'well_known_file' ? 'Well-Known File' : 'Meta Tag'}
  </span>
);

const StatusPill = ({ status }) => (
  <span
    className="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold"
    style={STATUS_STYLES[status] || { background: `${T.primary}15`, color: T.primary, border: `1px solid ${T.primary}30` }}
  >
    {status}
  </span>
);

const Field = ({ label, children }) => (
  <label className="flex flex-col gap-1.5">
    <span className="text-xs font-medium" style={{ color: T.muted }}>{label}</span>
    {children}
  </label>
);

const InstructionBlock = ({ title, body, actionLabel, onAction }) => (
  <div className="rounded-xl p-4" style={{ background: T.surface, border: `1px solid ${T.borderSubtle}` }}>
    <div className="flex items-center justify-between gap-3">
      <div>
        <p className="text-sm font-semibold" style={{ color: T.text }}>{title}</p>
        <p className="text-xs mt-1 whitespace-pre-wrap" style={{ color: T.muted }}>{body}</p>
      </div>
      {onAction && (
        <button
          type="button"
          onClick={onAction}
          className="px-3 py-2 rounded-lg text-xs font-semibold cursor-pointer whitespace-nowrap"
          style={{ background: T.elevated, border: `1px solid ${T.border}`, color: T.text }}
        >
          {actionLabel}
        </button>
      )}
    </div>
  </div>
);

const VerifiedTargets = ({ navigateTo }) => {
  const {
    targets,
    loading,
    error,
    createTarget,
    verifyTarget,
    regenerateToken,
    deleteTarget,
  } = useVerifiedTargetsData();

  const [newTargetUrl, setNewTargetUrl] = useState('');
  const [newTargetMethod, setNewTargetMethod] = useState('meta_tag');
  const [workingId, setWorkingId] = useState(null);
  const [pageError, setPageError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [verificationToken, setVerificationToken] = useState('');
  const [verificationInstructions, setVerificationInstructions] = useState(null);

  const sortedTargets = useMemo(() => {
    return [...targets].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  }, [targets]);

  const handleCreate = async (event) => {
    event.preventDefault();
    setPageError(null);
    setSuccess(null);
    setWorkingId('create');
    try {
      const { target } = await createTarget({
        target_url: newTargetUrl,
        verification_method: newTargetMethod,
      });
      setVerificationToken(target.verification_token);
      setVerificationInstructions(target.instructions);
      setSuccess(`Verification token created for ${target.normalized_domain}.`);
      setNewTargetUrl('');
    } catch (err) {
      setPageError(err.message || 'Failed to create verified target');
    } finally {
      setWorkingId(null);
    }
  };

  const handleVerify = async (target) => {
    const token = verificationToken.trim();
    if (!token) {
      setPageError('Enter the verification token before checking ownership.');
      return;
    }
    setPageError(null);
    setSuccess(null);
    setWorkingId(target.id);
    try {
      await verifyTarget(target.id, token);
      setSuccess(`Ownership verified for ${target.normalized_domain}.`);
    } catch (err) {
      setPageError(err.message || 'Verification failed');
    } finally {
      setWorkingId(null);
    }
  };

  const handleRegenerate = async (target) => {
    setPageError(null);
    setSuccess(null);
    setWorkingId(target.id);
    try {
      const { target: updated } = await regenerateToken(target.id);
      setVerificationToken(updated.verification_token);
      setVerificationInstructions(updated.instructions);
      setSuccess(`Generated a new verification token for ${updated.normalized_domain}.`);
    } catch (err) {
      setPageError(err.message || 'Failed to generate a new token');
    } finally {
      setWorkingId(null);
    }
  };

  const handleDelete = async (target) => {
    setPageError(null);
    setSuccess(null);
    setWorkingId(target.id);
    try {
      await deleteTarget(target.id);
      setSuccess(`Removed ${target.normalized_domain} from verified targets.`);
    } catch (err) {
      setPageError(err.message || 'Failed to remove target');
    } finally {
      setWorkingId(null);
    }
  };

  const copyToken = async () => {
    if (!verificationToken) return;
    try {
      await navigator.clipboard.writeText(verificationToken);
      setSuccess('Verification token copied.');
    } catch {
      setPageError('Could not copy the verification token.');
    }
  };

  return (
    <div className="min-h-screen" style={{ background: T.bg }}>
      <div
        className="sticky top-0 z-20 px-6 lg:px-10 py-4 flex items-center justify-between"
        style={{ background: `${T.surface}E0`, backdropFilter: 'blur(12px)', borderBottom: `1px solid ${T.border}` }}
      >
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigateTo('scanners')}
            className="flex items-center gap-1.5 text-xs font-medium cursor-pointer px-3 py-1.5 rounded-lg"
            style={{ color: T.muted, background: T.card, border: `1px solid ${T.border}` }}
          >
            <ArrowLeft size={13} />
            Back
          </button>
          <div className="flex items-center gap-2.5">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: T.primaryDim, border: `1px solid ${T.primary}40` }}
            >
              <Shield size={15} style={{ color: T.primary }} />
            </div>
            <div>
              <h1 className="text-base font-bold leading-tight" style={{ color: T.text }}>Verified Targets</h1>
              <p className="text-xs" style={{ color: T.dim }}>
                Manage ownership verification before running product-readiness and launch-audit scans.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="px-6 lg:px-10 py-6 flex flex-col gap-6">
        {error && !loading && (
          <div className="rounded-xl px-4 py-3 flex items-center gap-3" style={{ background: T.dangerDim, border: `1px solid ${T.danger}30`, color: T.danger }}>
            <AlertTriangle size={14} />
            {error}
          </div>
        )}
        {pageError && (
          <div className="rounded-xl px-4 py-3 flex items-center gap-3" style={{ background: T.dangerDim, border: `1px solid ${T.danger}30`, color: T.danger }}>
            <AlertTriangle size={14} />
            {pageError}
          </div>
        )}
        {success && (
          <div className="rounded-xl px-4 py-3 flex items-center gap-3" style={{ background: T.secureDim, border: `1px solid ${T.secure}30`, color: T.secure }}>
            <CheckCircle2 size={14} />
            {success}
          </div>
        )}

        <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)] gap-6 items-start">
          <section className="rounded-2xl p-5" style={{ background: T.card, border: `1px solid ${T.border}` }}>
            <div className="flex items-center gap-3 mb-5">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: T.primaryDim }}>
                <Globe size={18} style={{ color: T.primary }} />
              </div>
              <div>
                <h2 className="text-sm font-semibold" style={{ color: T.text }}>Add a Target</h2>
                <p className="text-xs" style={{ color: T.dim }}>
                  Generate a token, add it to the live site, then verify ownership.
                </p>
              </div>
            </div>

            <form className="flex flex-col gap-4" onSubmit={handleCreate}>
              <Field label="Target URL">
                <input
                  type="url"
                  required
                  value={newTargetUrl}
                  onChange={(event) => setNewTargetUrl(event.target.value)}
                  placeholder="https://example.com"
                  className="w-full px-3 py-2.5 rounded-lg text-sm outline-none"
                  style={{ background: T.surface, border: `1px solid ${T.border}`, color: T.text }}
                />
              </Field>

              <Field label="Verification Method">
                <select
                  value={newTargetMethod}
                  onChange={(event) => setNewTargetMethod(event.target.value)}
                  className="w-full px-3 py-2.5 rounded-lg text-sm outline-none"
                  style={{ background: T.surface, border: `1px solid ${T.border}`, color: T.text }}
                >
                  <option value="meta_tag">HTML Meta Tag</option>
                  <option value="well_known_file">Well-Known File</option>
                </select>
              </Field>

              <button
                type="submit"
                disabled={workingId === 'create'}
                className="px-4 py-2.5 rounded-lg text-sm font-semibold cursor-pointer disabled:opacity-70"
                style={{ background: T.primary, color: '#fff' }}
              >
                {workingId === 'create' ? 'Generating…' : 'Create Verification Token'}
              </button>
            </form>

            <div className="mt-5 rounded-xl p-4" style={{ background: T.surface, border: `1px solid ${T.borderSubtle}` }}>
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: T.muted }}>Current token</p>
                  <p className="mt-2 text-sm break-all" style={{ color: T.text, fontFamily: 'IBM Plex Mono, monospace' }}>
                    {verificationToken || 'Create or regenerate a token to show it here.'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={copyToken}
                  disabled={!verificationToken}
                  className="px-3 py-2 rounded-lg text-xs font-semibold cursor-pointer disabled:opacity-50"
                  style={{ background: T.elevated, border: `1px solid ${T.border}`, color: T.text }}
                >
                  <span className="inline-flex items-center gap-1.5">
                    <Copy size={12} />
                    Copy
                  </span>
                </button>
              </div>
            </div>

            {verificationInstructions && (
              <div className="mt-5 flex flex-col gap-3">
                <InstructionBlock
                  title="Meta Tag"
                  body={verificationInstructions.meta_tag || 'Create a target to generate instructions.'}
                />
                <InstructionBlock
                  title="Well-Known File"
                  body={verificationInstructions.well_known_file || 'Create a target to generate instructions.'}
                />
              </div>
            )}
          </section>

          <section className="rounded-2xl p-5" style={{ background: T.card, border: `1px solid ${T.border}` }}>
            <div className="flex items-center justify-between gap-3 mb-5">
              <div>
                <h2 className="text-sm font-semibold" style={{ color: T.text }}>Saved Targets</h2>
                <p className="text-xs" style={{ color: T.dim }}>
                  Verified targets can be reused in product-readiness and full launch audit jobs.
                </p>
              </div>
              <span className="text-xs font-semibold px-2 py-1 rounded-md" style={{ background: T.surface, border: `1px solid ${T.borderSubtle}`, color: T.muted }}>
                {sortedTargets.length} total
              </span>
            </div>

            <div className="flex flex-col gap-4">
              {loading && (
                <div className="rounded-xl px-4 py-8 flex items-center justify-center" style={{ background: T.surface, border: `1px solid ${T.borderSubtle}` }}>
                  <Spinner size="md" label="Loading targets…" />
                </div>
              )}

              {!loading && sortedTargets.length === 0 && (
                <div className="rounded-xl px-4 py-5 text-sm" style={{ background: T.surface, border: `1px solid ${T.borderSubtle}`, color: T.muted }}>
                  No verified targets yet.
                </div>
              )}

              {sortedTargets.map((target) => {
                const origin = target.target_url || target.normalized_domain;
                return (
                  <article
                    key={target.id}
                    className="rounded-xl p-4 flex flex-col gap-4"
                    style={{ background: T.surface, border: `1px solid ${T.borderSubtle}` }}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="text-sm font-semibold truncate" style={{ color: T.text }}>
                            {target.normalized_domain}
                          </p>
                          <StatusPill status={target.verification_status} />
                          <MethodPill method={target.verification_method} />
                        </div>
                        <a
                          href={origin}
                          target="_blank"
                          rel="noreferrer"
                          className="mt-1 inline-flex items-center gap-1.5 text-xs break-all"
                          style={{ color: T.dim }}
                        >
                          {target.target_url}
                          <ExternalLink size={11} />
                        </a>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <InstructionBlock
                        title="Verify ownership"
                        body="Use the current token shown on the left. Add it via the selected method, then run a verification check."
                        actionLabel={workingId === target.id ? 'Working…' : 'Verify now'}
                        onAction={() => handleVerify(target)}
                      />
                      <InstructionBlock
                        title="Rotate token"
                        body="Generate a new token if the previous one was exposed or you want to restart verification."
                        actionLabel={workingId === target.id ? 'Working…' : 'Regenerate'}
                        onAction={() => handleRegenerate(target)}
                      />
                    </div>

                    <div className="flex items-center justify-between gap-3 text-xs" style={{ color: T.muted }}>
                      <div className="flex items-center gap-3 flex-wrap">
                        <span>Created: {target.created_at ? new Date(target.created_at).toLocaleString() : '—'}</span>
                        <span>Verified: {target.verified_at ? new Date(target.verified_at).toLocaleString() : 'Not yet'}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleDelete(target)}
                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold cursor-pointer"
                        style={{ background: T.dangerDim, border: `1px solid ${T.danger}25`, color: T.danger }}
                      >
                        <Trash2 size={12} />
                        Delete
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>

            <div className="mt-5 rounded-xl p-4" style={{ background: T.elevated, border: `1px solid ${T.borderSubtle}` }}>
              <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: T.muted }}>
                Scan Safety
              </p>
              <ul className="flex flex-col gap-2 text-xs" style={{ color: T.dim }}>
                <li className="flex items-start gap-2"><Shield size={12} className="mt-0.5 flex-shrink-0" /> Product-readiness and full-launch scans should only be run against systems you control.</li>
                <li className="flex items-start gap-2"><KeyRound size={12} className="mt-0.5 flex-shrink-0" /> Verification tokens are only returned on creation or regeneration.</li>
                <li className="flex items-start gap-2"><RefreshCw size={12} className="mt-0.5 flex-shrink-0" /> Re-scan after fixing issues to confirm launch blockers are actually resolved.</li>
              </ul>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default VerifiedTargets;
