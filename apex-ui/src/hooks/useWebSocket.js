import { useState, useEffect, useRef, useCallback } from 'react';
import { WS_URL, getAuthToken } from '../config/api';

/**
 * Dashboard events are intentionally version-tolerant, but the properties the
 * UI reads are typed so `checkJs` still catches misspellings and invalid use.
 * @typedef {Object} DashboardMessage
 * @property {string} [type]
 * @property {string} [event_type]
 * @property {DashboardMessage} [data]
 * @property {string} [id]
 * @property {string} [finding_id]
 * @property {string} [scan_id]
 * @property {string} [scan_status]
 * @property {string} [scan_type]
 * @property {string} [scan_mode]
 * @property {string} [run_id]
 * @property {string} [target]
 * @property {string} [mode]
 * @property {string} [name]
 * @property {string} [phase]
 * @property {number} [progress]
 * @property {string} [severity]
 * @property {string} [title]
 * @property {string} [module]
 * @property {string} [url]
 * @property {string} [timestamp]
 * @property {string} [confidence]
 * @property {string} [verdict]
 * @property {string} [finding]
 * @property {string} [reason]
 * @property {string} [reasoning]
 * @property {string} [log_path]
 * @property {string} [chain_type]
 * @property {string} [source_framework]
 * @property {string} [target_framework]
 * @property {string} [target_module]
 * @property {string} [framework]
 * @property {string} [rationale]
 * @property {boolean} [auto_execute]
 * @property {string} [error]
 * @property {string} [reason_code]
 * @property {DashboardMessage[]} [findings]
 * @property {DashboardMessage[]} [brain_verdicts]
 * @property {DashboardMessage[]} [chain_actions]
 * @property {string} [cve]
 * @property {number} [cvss]
 * @property {number} [vpr]
 * @property {string} [description]
 * @property {string} [repro]
 * @property {string} [evidence]
 * @property {string} [remediation]
 * @property {string} [status]
 */

/**
 * @param {string} [url]
 * @param {string} [authToken]
 */
export const useWebSocket = (url = WS_URL, authToken = getAuthToken()) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState(/** @type {DashboardMessage | null} */ (null));
  const [lastError, setLastError] = useState('');
  const ws = useRef(/** @type {WebSocket | null} */ (null));
  const retryDelay = useRef(1000);
  const retryTimer = useRef(/** @type {ReturnType<typeof setTimeout> | null} */ (null));
  const unmounted = useRef(false);
  const authenticated = useRef(false);

  const sendMessage = useCallback((/** @type {string | DashboardMessage} */ msg) => {
    if (authenticated.current && ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
  }, []);

  const connect = useCallback(() => {
    if (unmounted.current) return;
    if (!authToken) {
      authenticated.current = false;
      setIsConnected(false);
      setLastError('Dashboard authentication is required');
      return;
    }

    ws.current = new WebSocket(url);
    authenticated.current = false;

    ws.current.onopen = () => {
      if (unmounted.current) return;
      ws.current.send(JSON.stringify({ token: authToken }));
    };

    ws.current.onmessage = (event) => {
      try {
        const data = /** @type {DashboardMessage} */ (JSON.parse(event.data));
        if (data?.error) {
          authenticated.current = false;
          setIsConnected(false);
          setLastError(String(data.reason_code || data.error || 'WebSocket authentication failed'));
          ws.current?.close(4001);
          return;
        }
        if (data?.type === 'auth_ack') {
          authenticated.current = true;
          setIsConnected(true);
          setLastError('');
          retryDelay.current = 1000;
        }
        setLastMessage(data);
      } catch (err) {
        console.error('WS parse error', err);
      }
    };

    ws.current.onclose = (event) => {
      if (unmounted.current) return;
      authenticated.current = false;
      setIsConnected(false);
      if ([4001, 4002, 4401, 4403].includes(event?.code)) {
        setLastError('Dashboard authentication was rejected');
        return;
      }
      // Exponential backoff: 1s → 2s → 4s → … → 30s cap
      retryTimer.current = setTimeout(() => {
        retryDelay.current = Math.min(retryDelay.current * 2, 30000);
        connect();
      }, retryDelay.current);
    };

    ws.current.onerror = () => {
      setLastError('WebSocket connection failed');
      ws.current?.close();
    };
  }, [url, authToken]);

  useEffect(() => {
    unmounted.current = false;
    connect();
    return () => {
      unmounted.current = true;
      authenticated.current = false;
      if (retryTimer.current !== null) clearTimeout(retryTimer.current);
      ws.current?.close();
    };
  }, [connect]);

  return { isConnected, lastMessage, lastError, sendMessage };
};
