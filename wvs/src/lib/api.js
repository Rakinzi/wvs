import { clearSession, getCsrfToken } from './auth';

const DEFAULT_API_BASE_URL = 'http://localhost:5000';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL;

export class ApiError extends Error {
  constructor(message, status, data = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

const buildHeaders = ({ auth = false, json = false, headers = {} } = {}) => {
  const requestHeaders = { ...headers };

  if (json) {
    requestHeaders['Content-Type'] = 'application/json';
  }

  if (auth && !requestHeaders['X-CSRF-TOKEN']) {
    const csrfToken = getCsrfToken();
    if (csrfToken) {
      requestHeaders['X-CSRF-TOKEN'] = csrfToken;
    }
  }

  return requestHeaders;
};

const parseErrorMessage = (data, fallbackMessage) => {
  if (!data || typeof data !== 'object') {
    return fallbackMessage;
  }

  return data.message || data.error || fallbackMessage;
};

const handleUnauthorized = () => {
  clearSession();
  window.location.href = '/login';
};

export const apiFetch = async (path, options = {}) => {
  const {
    auth = false,
    json = false,
    headers,
    body,
    credentials,
    ...fetchOptions
  } = options;

  const resolvedCredentials = credentials ?? (auth ? 'include' : 'omit');
  const method = (fetchOptions.method || 'GET').toUpperCase();
  const includeCsrfHeader = auth && !['GET', 'HEAD', 'OPTIONS'].includes(method);

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...fetchOptions,
    credentials: resolvedCredentials,
    headers: buildHeaders({ auth: includeCsrfHeader, json, headers }),
    body: body === undefined ? undefined : (json ? JSON.stringify(body) : body)
  });

  if (response.status === 401 && auth) {
    handleUnauthorized();
  }

  return response;
};

export const apiJson = async (path, options = {}) => {
  const response = await apiFetch(path, options);
  const data = await response.json().catch(() => null);

  if (!response.ok) {
    throw new ApiError(
      parseErrorMessage(data, `Request failed with status ${response.status}`),
      response.status,
      data
    );
  }

  return { response, data };
};
