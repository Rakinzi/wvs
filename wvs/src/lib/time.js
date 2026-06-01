export const parseApiDate = (value) => {
  if (!value) return null;
  if (value instanceof Date) return value;
  if (typeof value !== 'string') {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  const trimmed = value.trim();
  const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(trimmed);
  const normalized = hasTimezone ? trimmed : `${trimmed}Z`;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
};

export const apiDateMs = (value) => {
  const date = parseApiDate(value);
  return date ? date.getTime() : 0;
};

export const formatApiDateTime = (value, options = {}) => {
  const date = parseApiDate(value);
  if (!date) return '—';
  return date.toLocaleString([], options);
};

export const formatApiTime = (value, options = {}) => {
  const date = parseApiDate(value);
  if (!date) return '—';
  return date.toLocaleTimeString([], options);
};
