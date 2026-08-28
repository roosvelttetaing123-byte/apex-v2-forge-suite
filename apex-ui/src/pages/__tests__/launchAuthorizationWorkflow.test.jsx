import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import AutomatedScans from '../AutomatedScans';
import ScanBuilder from '../ScanBuilder';
import Vulnerabilities from '../Vulnerabilities';

vi.mock('../../hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    isConnected: false,
    lastMessage: null,
    lastError: '',
  }),
}));

const jsonResponse = (status, payload) => ({
  ok: status >= 200 && status < 300,
  status,
  json: vi.fn().mockResolvedValue(payload),
});

const confirmation = (engine = 'webforge', action = 'scan') => ({
  schema_version: 'forge-action-confirmation-v1',
  confirmed: true,
  job_id: 'job-ui-fixture',
  target: `sha256:${'a'.repeat(64)}`,
  engine,
  action,
  issued_at: '2026-07-31T12:00:00Z',
  binding_digest: 'b'.repeat(64),
});

let confirmMock = vi.fn((/** @type {string} */ _message) => true);

describe('dashboard launch authorization workflow', () => {
  beforeEach(() => {
    localStorage.clear();
    confirmMock = vi.fn((/** @type {string} */ _message) => true);
    vi.stubGlobal('confirm', confirmMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('prepares and binds an AutomatedScans confirmation before launch', async () => {
    const calls = [];
    vi.stubGlobal('fetch', vi.fn(async (url, options = {}) => {
      const path = String(url);
      if (path.endsWith('/api/v1/health')) return jsonResponse(200, { tools: [], active_processes: 0 });
      if (path.endsWith('/api/v1/scans/history')) return jsonResponse(200, { scans: [] });
      if (path.endsWith('/api/v1/action-confirmations')) {
        calls.push(['prepare', JSON.parse(options.body)]);
        return jsonResponse(200, {
          job_id: 'job-ui-fixture',
          scope: ['127.0.0.1/32'],
          exclude: [],
          confirmations: [confirmation()],
          authorized: false,
        });
      }
      if (path.endsWith('/api/v1/scans/start')) {
        calls.push(['launch', JSON.parse(options.body)]);
        return jsonResponse(200, { status: 'started', scan_id: 'scan-fixture' });
      }
      return jsonResponse(404, {});
    }));

    render(
      <MemoryRouter>
        <AutomatedScans authToken="fixture" />
      </MemoryRouter>
    );
    fireEvent.change(screen.getByPlaceholderText(/https:\/\/target.com/), {
      target: { value: '127.0.0.1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'INITIATE SCAN' }));

    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[0]).toEqual(['prepare', {
      intent: 'scan.start',
      target: '127.0.0.1',
      scope: ['127.0.0.1'],
      exclude: [],
      scan_type: 'web',
      mode: 'blackbox',
    }]);
    expect(calls[1][0]).toBe('launch');
    expect(calls[1][1]).toMatchObject({
      job_id: 'job-ui-fixture',
      scope: ['127.0.0.1/32'],
      confirmation: confirmation(),
    });
  });

  it('prepares an active retest from persisted finding metadata before POST', async () => {
    const finding = {
      id: 'finding-1',
      title: 'Fixture finding',
      target: '127.0.0.1',
      module: 'sqli_scanner',
      severity: 'high',
      status: 'open',
    };
    const calls = [];
    vi.stubGlobal('fetch', vi.fn(async (url, options = {}) => {
      const path = String(url);
      if (path.includes('/api/v1/findings?')) return jsonResponse(200, { findings: [finding] });
      if (path.endsWith('/api/v1/action-confirmations')) {
        calls.push(['prepare', JSON.parse(options.body)]);
        return jsonResponse(200, {
          job_id: 'job-ui-fixture',
          scope: ['127.0.0.1'],
          exclude: [],
          confirmations: [confirmation('webforge', 'retest')],
          authorized: false,
        });
      }
      if (path.endsWith('/api/v1/findings/finding-1/retest')) {
        calls.push(['retest', JSON.parse(options.body)]);
        return jsonResponse(200, {
          state: 'terminal',
          retest_verdict: 'unsupported',
        });
      }
      return jsonResponse(404, {});
    }));

    render(<Vulnerabilities authToken="fixture" />);
    fireEvent.click(await screen.findByText('Fixture finding'));
    fireEvent.click(await screen.findByRole('button', { name: 'Re-test' }));

    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[0]).toEqual(['prepare', {
      intent: 'finding.retest',
      finding_id: 'finding-1',
      scope: ['127.0.0.1'],
      exclude: [],
    }]);
    expect(calls[1][1]).toMatchObject({
      job_id: 'job-ui-fixture',
      dry_run: false,
      confirmation: confirmation('webforge', 'retest'),
    });
  });

  it('prepares both ScanBuilder actions when selected modules span engines', async () => {
    const networkConfirmation = confirmation('netforge', 'web_to_network');
    const calls = [];
    vi.stubGlobal('fetch', vi.fn(async (url, options = {}) => {
      const path = String(url);
      if (path.endsWith('/api/v1/scan/templates')) return jsonResponse(200, { templates: [] });
      if (path.endsWith('/api/v1/action-confirmations')) {
        calls.push(['prepare', JSON.parse(options.body)]);
        return jsonResponse(200, {
          job_id: 'job-ui-fixture',
          scope: ['app.example.test', '192.0.2.10/32'],
          exclude: [],
          network_target: '192.0.2.10',
          web_scope: ['app.example.test'],
          network_scope: ['192.0.2.10/32'],
          confirmations: [confirmation(), networkConfirmation],
          authorized: false,
        });
      }
      if (path.endsWith('/api/v1/scans/launch')) {
        calls.push(['launch', JSON.parse(options.body)]);
        return jsonResponse(200, {
          scan_id: 'scan-fixture',
          scan_type: 'vapt',
          modules_count: 16,
        });
      }
      return jsonResponse(404, {});
    }));

    render(
      <MemoryRouter>
        <ScanBuilder />
      </MemoryRouter>
    );
    fireEvent.change(screen.getByPlaceholderText('192.168.0.0/16 or https://...'), {
      target: { value: 'app.example.test' },
    });
    fireEvent.change(screen.getByPlaceholderText('Exact separately approved IP'), {
      target: { value: '192.0.2.10' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Launch Scan/ }));

    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[0][0]).toBe('prepare');
    expect(calls[0][1]).toMatchObject({
      intent: 'scan.launch',
      target: 'app.example.test',
      scope: ['app.example.test'],
      network_target: '192.0.2.10',
      network_scope: ['192.0.2.10'],
    });
    expect(calls[1][1]).toMatchObject({
      job_id: 'job-ui-fixture',
      scope: ['app.example.test', '192.0.2.10/32'],
      network_target: '192.0.2.10',
      web_scope: ['app.example.test'],
      network_scope: ['192.0.2.10/32'],
      confirmations: [confirmation(), networkConfirmation],
    });
    expect(confirmMock).toHaveBeenCalledTimes(2);
    expect(confirmMock.mock.calls[1][0]).toContain('192.0.2.10');
    expect(confirmMock.mock.calls[1][0]).toContain('web-to-network');
  });

  it('keeps ScanBuilder launch disabled when no modules are selected', async () => {
    const fetchMock = vi.fn(async (url) => {
      if (String(url).endsWith('/api/v1/scan/templates')) {
        return jsonResponse(200, { templates: [] });
      }
      return jsonResponse(404, {});
    });
    vi.stubGlobal('fetch', fetchMock);

    render(
      <MemoryRouter>
        <ScanBuilder />
      </MemoryRouter>
    );
    fireEvent.change(screen.getByPlaceholderText('192.168.0.0/16 or https://...'), {
      target: { value: 'app.example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Clear All' }));

    const launch = screen.getByRole('button', { name: /Launch Scan/ });
    await waitFor(() => expect(launch).toBeDisabled());
    expect(confirmMock).not.toHaveBeenCalled();
  });
});
