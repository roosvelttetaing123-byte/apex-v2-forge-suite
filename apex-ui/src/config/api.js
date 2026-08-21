/**
 * Centralized API configuration — no more hardcoded localhost:1337 scattered
 * across every damn JSX file like breadcrumbs from a drunk dev.
 *
 * In production: auto-detects current host via window.location
 * In dev mode:   uses VITE_API_HOST / VITE_WS_HOST env vars (see .env.development)
 * Via Vite proxy: /api and /ws paths are proxied to the backend automatically
 */

import { DASHBOARD_API } from '../generated/dashboard-api';

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
  const websocketPath = DASHBOARD_API.websocket.path;
  if (import.meta.env.VITE_WS_HOST) {
    return `${import.meta.env.VITE_WS_HOST.replace(/\/$/, '')}${websocketPath}`;
  }
  // In production, derive from current page location
  if (import.meta.env.PROD) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}${websocketPath}`;
  }
  // Dev mode: relative WebSocket path, Vite proxy handles /ws → backend
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}${websocketPath}`;
};

export const API_BASE = resolveApiBase();
export const WS_URL   = resolveWsUrl();

export const AUTH_TOKEN_KEY = 'forge_token';
const LEGACY_UNAUTHENTICATED_SENTINEL = '__forge_no_auth__';

export const getAuthToken = () => {
  const token = localStorage.getItem(AUTH_TOKEN_KEY) || '';
  if (token === LEGACY_UNAUTHENTICATED_SENTINEL) {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    return '';
  }
  return token;
};

/** @param {string} token */
export const setAuthToken = (token) => {
  if (token) localStorage.setItem(AUTH_TOKEN_KEY, token);
  else localStorage.removeItem(AUTH_TOKEN_KEY);
};

export const authHeaders = (headers = {}) => {
  const token = getAuthToken();
  return token ? { ...headers, Authorization: `Bearer ${token}` } : headers;
};

/**
 * @param {string} path
 * @param {RequestInit} [options]
 */
export const apiFetch = (path, options = {}) => {
  const headers = authHeaders(options.headers || {});
  return fetch(`${API_BASE}${path}`, { ...options, headers });
};
