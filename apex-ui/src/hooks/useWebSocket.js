import { useState, useEffect, useRef, useCallback } from 'react';
import { WS_URL, getAuthToken, NO_AUTH_TOKEN } from '../config/api';

export const useWebSocket = (url = WS_URL, authToken = getAuthToken()) => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState(null);
  const [lastError, setLastError] = useState('');
  const ws = useRef(null);
  const retryDelay = useRef(1000);
  const retryTimer = useRef(null);
  const unmounted = useRef(false);

  const sendMessage = useCallback((msg) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
  }, []);

  const connect = useCallback(() => {
    if (unmounted.current) return;

    ws.current = new WebSocket(url);

    ws.current.onopen = () => {
      if (unmounted.current) return;
      if (authToken && authToken !== NO_AUTH_TOKEN) {
        ws.current.send(JSON.stringify({ token: authToken }));
      }
      setIsConnected(true);
      setLastError('');
      retryDelay.current = 1000;
    };

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setLastMessage(data);
      } catch (err) {
        console.error('WS parse error', err);
      }
    };

    ws.current.onclose = () => {
      if (unmounted.current) return;
      setIsConnected(false);
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
      clearTimeout(retryTimer.current);
      ws.current?.close();
    };
  }, [connect]);

  return { isConnected, lastMessage, lastError, sendMessage };
};
