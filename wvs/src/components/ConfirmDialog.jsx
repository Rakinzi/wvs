import React, { useEffect, useRef } from 'react';
import { AlertTriangle, X } from 'lucide-react';

const T = {
  bg:      'var(--color-bg)',
  surface: 'var(--color-surface)',
  card:    'var(--color-card)',
  border:  'var(--color-border)',
  text:    'var(--color-text)',
  muted:   'var(--color-text-muted)',
  dim:     'var(--color-text-dim)',
  danger:  'var(--color-danger)',
  dangerDim: 'var(--color-danger-dim)',
};

const ConfirmDialog = ({ open, title, message, confirmLabel = 'Delete', onConfirm, onCancel }) => {
  const cancelRef = useRef(null);

  useEffect(() => {
    if (open) cancelRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e) => { if (e.key === 'Escape') onCancel(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onCancel]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center px-4"
      style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
      onClick={(e) => { if (e.target === e.currentTarget) onCancel(); }}>

      <div className="w-full max-w-sm rounded-2xl overflow-hidden shadow-2xl"
        style={{ background: T.surface, border: `1px solid ${T.border}` }}
        role="alertdialog" aria-modal="true" aria-labelledby="cd-title" aria-describedby="cd-msg">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4"
          style={{ borderBottom: `1px solid ${T.border}` }}>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{ background: T.dangerDim }}>
              <AlertTriangle size={15} style={{ color: T.danger }} />
            </div>
            <p id="cd-title" className="text-sm font-semibold" style={{ color: T.text }}>{title}</p>
          </div>
          <button onClick={onCancel} className="cursor-pointer" style={{ color: T.dim }}>
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4">
          <p id="cd-msg" className="text-sm leading-relaxed" style={{ color: T.muted }}>{message}</p>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-end gap-2 px-5 py-4"
          style={{ borderTop: `1px solid ${T.border}`, background: T.card }}>
          <button ref={cancelRef} onClick={onCancel}
            className="px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer"
            style={{ background: T.surface, color: T.muted, border: `1px solid ${T.border}` }}>
            Cancel
          </button>
          <button onClick={onConfirm}
            className="px-4 py-2 rounded-lg text-xs font-semibold cursor-pointer text-white"
            style={{ background: T.danger }}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmDialog;
