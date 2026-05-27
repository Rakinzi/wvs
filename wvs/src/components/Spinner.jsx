import React from 'react';

export default function Spinner({ size = 'md', label, color, style = {} }) {
  const c = color || 'var(--color-primary)';

  if (size === 'sm') {
    return (
      <div
        className="rounded-full border-2 animate-spin flex-shrink-0"
        style={{
          width: 14,
          height: 14,
          borderColor: color ? `${color}33` : 'rgba(255,255,255,0.2)',
          borderTopColor: color || 'white',
          animationDuration: '600ms',
          ...style,
        }}
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
