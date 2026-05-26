import React from 'react';

/**
 * size="sm"  — inline button spinner (16px)
 * size="md"  — section loader (default, 40px)
 * size="lg"  — full-page loader (56px)
 * color      — optional hex/CSS color override (defaults to --color-primary)
 */
export default function Spinner({ size = 'md', label, color, style = {} }) {
  const c = color || 'var(--color-primary)';

  if (size === 'sm') {
    const borderColor = color
      ? `${color}4d`  // ~30% opacity hex
      : 'rgba(255,255,255,0.3)';
    const borderTopColor = color || 'white';
    return (
      <div
        className="rounded-full border-2 animate-spin"
        style={{ width: 16, height: 16, borderColor, borderTopColor, ...style }}
      />
    );
  }

  const dim = size === 'lg' ? 56 : 40;
  const ring = size === 'lg' ? 3 : 2.5;
  const circumference = Math.PI * (dim - ring * 2);

  return (
    <div className="flex flex-col items-center justify-center gap-3" style={style}>
      <div style={{ width: dim, height: dim, position: 'relative' }}>
        <svg
          width={dim}
          height={dim}
          viewBox={`0 0 ${dim} ${dim}`}
          fill="none"
          style={{ position: 'absolute', inset: 0 }}
        >
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={dim / 2 - ring}
            stroke={c}
            strokeOpacity="0.15"
            strokeWidth={ring}
          />
        </svg>
        <svg
          width={dim}
          height={dim}
          viewBox={`0 0 ${dim} ${dim}`}
          fill="none"
          className="animate-spin"
          style={{ position: 'absolute', inset: 0, animationDuration: '700ms' }}
        >
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={dim / 2 - ring}
            stroke={c}
            strokeWidth={ring}
            strokeLinecap="round"
            strokeDasharray={`${circumference * 0.25} ${circumference * 0.75}`}
          />
        </svg>
      </div>
      {label && (
        <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
          {label}
        </p>
      )}
    </div>
  );
}
