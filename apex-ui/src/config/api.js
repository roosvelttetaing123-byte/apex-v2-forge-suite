/**
 * Centralized API configuration — no more hardcoded localhost:1337 scattered
 * across every damn JSX file like breadcrumbs from a drunk dev.
 *
 * In production: auto-detects current host via window.location
 * In dev mode:   uses VITE_API_HOST / VITE_WS_HOST env vars (see .env.development)
 * Via Vite proxy: /api and /ws paths are proxied to the backend automatically
 */

// HTTP API base — empty string means "use relative paths" (Vite proxy handles it)
// Falls back to env var for direct backend connections (no proxy)
const resolveApiBase = () => {
  // If Vite env var is explicitly set, use it
  if (import.meta.env.VITE_API_HOST) {
    return import.meta.env.VITE_API_HOST;
  }
  // In production builds, use the current origin (served from same host as API)
  if (import.meta.env.PROD) {
    return window.location.origin;
  }
  // Dev mode: empty string = relative paths, Vite proxy handles /api → backend
  return '';
};

// WebSocket URL — auto-detects protocol (ws/wss) and host
const resolveWsUrl = () => {
  if (import.meta.env.VITE_WS_HOST) {
    return `${import.meta.env.VITE_WS_HOST}/ws/dashboard`;
  }
  // In production, derive from current page location
  if (import.meta.env.PROD) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}/ws/dashboard`;
  }
  // Dev mode: relative WebSocket path, Vite proxy handles /ws → backend
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/ws/dashboard`;
};

export const API_BASE = resolveApiBase();
export const WS_URL   = resolveWsUrl();

export const AUTH_TOKEN_KEY = 'forge_token';
export const NO_AUTH_TOKEN = '__forge_no_auth__';

export const getAuthToken = () => localStorage.getItem(AUTH_TOKEN_KEY) || '';

export const setAuthToken = (token) => {
  if (token) localStorage.setItem(AUTH_TOKEN_KEY, token);
  else localStorage.removeItem(AUTH_TOKEN_KEY);
};

export const authHeaders = (headers = {}) => {
  const token = getAuthToken();
  return token && token !== NO_AUTH_TOKEN ? { ...headers, Authorization: `Bearer ${token}` } : headers;
};

export const apiFetch = (path, options = {}) => {
  const headers = authHeaders(options.headers || {});
  return fetch(`${API_BASE}${path}`, { ...options, headers });
};
