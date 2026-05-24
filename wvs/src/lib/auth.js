const SESSION_KEY = 'wvs.session';
const LEGACY_SESSION_KEYS = ['token', 'username'];

const getStorage = () => window.sessionStorage;

const parseCookieValue = (cookieName) => {
  const encodedName = `${encodeURIComponent(cookieName)}=`;
  const found = document.cookie
    .split('; ')
    .find((cookie) => cookie.startsWith(encodedName));
  if (!found) {
    return null;
  }
  return decodeURIComponent(found.slice(encodedName.length));
};

const clearLegacyLocalStorage = () => {
  localStorage.removeItem(SESSION_KEY);
  LEGACY_SESSION_KEYS.forEach((key) => localStorage.removeItem(key));
};

const readStoredSession = () => {
  const storage = getStorage();
  const raw = storage.getItem(SESSION_KEY);
  if (!raw) {
    const legacyRaw = localStorage.getItem(SESSION_KEY);
    if (legacyRaw) {
      try {
        storage.setItem(SESSION_KEY, legacyRaw);
        const parsed = JSON.parse(legacyRaw);
        clearLegacyLocalStorage();
        return parsed;
      } catch {
        clearLegacyLocalStorage();
        return null;
      }
    }
    return null;
  }

  try {
    return JSON.parse(raw);
  } catch {
    storage.removeItem(SESSION_KEY);
    return null;
  }
};

export const clearSession = () => {
  getStorage().removeItem(SESSION_KEY);
  clearLegacyLocalStorage();
};

export const getSession = () => {
  const session = readStoredSession();
  if (!session?.username) {
    return null;
  }

  if (session.expiresAt && Date.now() >= session.expiresAt) {
    clearSession();
    return null;
  }

  return session;
};

export const saveSession = ({ username, userId, expiresInSeconds }) => {
  const expiresAt = expiresInSeconds
    ? Date.now() + (expiresInSeconds * 1000)
    : null;

  getStorage().setItem(SESSION_KEY, JSON.stringify({
    username,
    userId,
    expiresAt,
  }));
  clearLegacyLocalStorage();
};

export const getCsrfToken = () => parseCookieValue('csrf_access_token');
export const getSessionUsername = () => getSession()?.username || null;
export const isAuthenticated = () => Boolean(getSession());
