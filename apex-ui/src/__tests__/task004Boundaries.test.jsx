import React from 'react';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';

import C2Console from '../pages/C2Console';
import { AUTH_TOKEN_KEY, getAuthToken } from '../config/api';
import { useWebSocket } from '../hooks/useWebSocket';


const jsonResponse = (status, payload) => ({
  ok: status >= 200 && status < 300,
  status,
  json: vi.fn().mockResolvedValue(payload),
});


class FakeWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSED = 3;
  static instances = [];

  constructor(url) {
    this.url = url;
    this.readyState = FakeWebSocket.CONNECTING;
    this.send = vi.fn();
    this.close = vi.fn((code) => {
      this.readyState = FakeWebSocket.CLOSED;
      this.closeCode = code;
    });
    FakeWebSocket.instances.push(this);
  }
}


describe('Task 004 dashboard UI trust boundaries', () => {
  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem(AUTH_TOKEN_KEY, 'fixture-dashboard-token');
    FakeWebSocket.instances = [];
    vi.stubGlobal('WebSocket', FakeWebSocket);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders truthful disabled C2 and BOF states without invented active sessions', async () => {
    const fetchMock = vi.fn(async (url) => {
      if (String(url).endsWith('/api/v1/c2/bofs')) {
        return jsonResponse(200, {
          status: 'disabled',
          enabled: false,
          reason_code: 'local_bof_execution_disabled',
          bofs: [],
        });
      }
      return jsonResponse(200, { profiles: [] });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<C2Console />);

    expect(screen.getByText('No listener or beacon runtime is connected to this dashboard')).toBeInTheDocument();
    expect(screen.getByText('c2_runtime_not_connected')).toBeInTheDocument();
    expect(screen.queryByText('GHOST-01')).not.toBeInTheDocument();
    expect(screen.queryByText('HTTP Listener')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /BOF Status/i }));
    expect(await screen.findByText('Dashboard-host BOF execution is disabled')).toBeInTheDocument();
    expect(await screen.findByText('local_bof_execution_disabled')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^RUN$/i })).not.toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/execute'))).toBe(false);
  });

  it('shows a stable forbidden BOF state returned by the API', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).endsWith('/api/v1/c2/bofs')) {
        return jsonResponse(403, {
          status: 'forbidden',
          reason_code: 'dashboard_role_forbidden',
        });
      }
      return jsonResponse(200, { profiles: [] });
    }));

    render(<C2Console />);
    fireEvent.click(screen.getByRole('button', { name: /BOF Status/i }));

    expect(await screen.findByText('FORBIDDEN')).toBeInTheDocument();
    expect(await screen.findByText('dashboard_role_forbidden')).toBeInTheDocument();
  });

  it('does not report WebSocket connectivity until the auth acknowledgement arrives', () => {
    const { result, unmount } = renderHook(() => (
      useWebSocket('ws://fixture.test/ws/dashboard', 'fixture-dashboard-token')
    ));
    const socket = FakeWebSocket.instances[0];

    act(() => {
      socket.readyState = FakeWebSocket.OPEN;
      socket.onopen();
    });

    expect(socket.send).toHaveBeenCalledWith(JSON.stringify({ token: 'fixture-dashboard-token' }));
    expect(result.current.isConnected).toBe(false);

    act(() => {
      socket.onmessage({ data: JSON.stringify({ type: 'state_snapshot', data: {} }) });
    });

    expect(result.current.isConnected).toBe(false);

    act(() => {
      socket.onmessage({ data: JSON.stringify({ type: 'auth_ack', role: 'viewer' }) });
    });

    expect(result.current.isConnected).toBe(true);
    expect(result.current.lastError).toBe('');
    unmount();
  });

  it('keeps missing and rejected WebSocket identities disconnected', () => {
    const missing = renderHook(() => useWebSocket('ws://fixture.test/ws/dashboard', ''));
    expect(missing.result.current.isConnected).toBe(false);
    expect(missing.result.current.lastError).toBe('Dashboard authentication is required');
    expect(FakeWebSocket.instances).toHaveLength(0);
    missing.unmount();

    const rejected = renderHook(() => (
      useWebSocket('ws://fixture.test/ws/dashboard', 'expired-token')
    ));
    const socket = FakeWebSocket.instances[0];
    act(() => {
      socket.readyState = FakeWebSocket.OPEN;
      socket.onopen();
      socket.onmessage({
        data: JSON.stringify({ error: 'unauthorized', reason_code: 'dashboard_auth_required' }),
      });
    });

    expect(rejected.result.current.isConnected).toBe(false);
    expect(rejected.result.current.lastError).toBe('dashboard_auth_required');
    expect(socket.close).toHaveBeenCalledWith(4001);
    rejected.unmount();
  });

  it('purges the legacy unauthenticated sentinel instead of treating it as identity', () => {
    localStorage.setItem(AUTH_TOKEN_KEY, '__forge_no_auth__');
    expect(getAuthToken()).toBe('');
    expect(localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();

    const appSource = readFileSync('src/App.jsx', 'utf8');
    expect(appSource).not.toContain('NO-AUTH DASHBOARD');
    expect(appSource).not.toContain('auth_enabled === false');
  });
});
