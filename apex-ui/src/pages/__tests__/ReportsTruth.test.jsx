import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import Reports from '../Reports';

const socket = vi.hoisted(() => ({ lastMessage: null }));

vi.mock('../../hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    isConnected: true,
    lastMessage: socket.lastMessage,
    lastError: '',
  }),
}));

const response = (status, payload, extra = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  json: vi.fn().mockResolvedValue(payload),
  ...extra,
});

const finding = (overrides = {}) => ({
  id: 'finding-csp-1',
  title: 'Content-Security-Policy missing',
  target: 'fixture.invalid',
  module: 'header_audit',
  finding_key: 'Content-Security-Policy',
  review_version: 2,
  request_raw: 'RAW_FINDING_CANARY',
  protected_original: 'PROTECTED_FINDING_CANARY',
  ...overrides,
});

const report = (overrides = {}) => ({
  report_id: 'report-html-1',
  version: 3,
  target: 'fixture.invalid',
  source_digest: 'sha256:' + '1'.repeat(64),
  artifact_sha256: 'sha256:' + '2'.repeat(64),
  created_by_operator_id: 'operator-fixture',
  request_raw: 'RAW_REPORT_CANARY',
  protected_original: 'PROTECTED_REPORT_CANARY',
  ...overrides,
});

const confirmation = {
  schema_version: 'forge-action-confirmation-v1',
  confirmed: true,
  job_id: 'job-report-export',
  target: `sha256:${'a'.repeat(64)}`,
  engine: 'forge',
  action: 'report.export',
  issued_at: '2026-08-30T12:00:00Z',
  binding_digest: 'b'.repeat(64),
};

const installReportsApi = (fetchMock, { reports = [], findings = [finding()] } = {}) => {
  fetchMock.mockImplementation(async (url) => {
    if (String(url).startsWith('/api/v1/reports?')) return response(200, { reports });
    if (String(url).startsWith('/api/v1/findings?')) return response(200, { findings });
    return response(404, {});
  });
};

describe('Reports persisted truth contract', () => {
  beforeEach(() => {
    localStorage.clear();
    socket.lastMessage = null;
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it('loads persisted reports and eligible findings while withholding raw/protected payload fields', async () => {
    const fetchMock = vi.fn();
    installReportsApi(fetchMock, { reports: [report()] });
    vi.stubGlobal('fetch', fetchMock);

    render(<Reports authToken="fixture" />);

    expect(await screen.findByText('report-html-1')).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Content-Security-Policy missing/ })).toBeInTheDocument();
    expect(screen.getByText('HTML — persisted and locked')).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('RAW_FINDING_CANARY');
    expect(document.body).not.toHaveTextContent('PROTECTED_FINDING_CANARY');
    expect(document.body).not.toHaveTextContent('RAW_REPORT_CANARY');
    expect(document.body).not.toHaveTextContent('PROTECTED_REPORT_CANARY');
  });

  it('presents HTML as the only functional format and leaves PDF/JSON unsupported', async () => {
    const fetchMock = vi.fn();
    installReportsApi(fetchMock);
    vi.stubGlobal('fetch', fetchMock);

    render(<Reports authToken="fixture" />);

    await screen.findByRole('option', { name: /Content-Security-Policy missing/ });
    expect(screen.getByText(/PDF, JSON, scheduling, custom builders, and compliance reports remain disabled/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /PDF/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /JSON/i })).not.toBeInTheDocument();
  });

  it('uses state_snapshot and report_updated websocket messages only as persisted-state invalidations', async () => {
    let reportReads = 0;
    const fetchMock = vi.fn(async (url) => {
      if (String(url).startsWith('/api/v1/reports?')) {
        reportReads += 1;
        const currentReport = reportReads === 1
          ? report({ report_id: 'report-initial' })
          : report({
            report_id: reportReads === 2 ? 'report-snapshot-refresh' : 'report-event-refresh',
            request_raw: 'UNPERSISTED_REPORT_EVENT_CANARY',
          });
        return response(200, { reports: [currentReport] });
      }
      if (String(url).startsWith('/api/v1/findings?')) return response(200, { findings: [finding()] });
      return response(404, {});
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<Reports authToken="fixture" />);

    expect(await screen.findByText('report-initial')).toBeInTheDocument();
    socket.lastMessage = {
      type: 'state_snapshot',
      data: { reports: [{ report_id: 'TRANSIENT_SNAPSHOT_REPORT_CANARY' }] },
    };
    view.rerender(<Reports authToken="fixture" />);
    expect(await screen.findByText('report-snapshot-refresh')).toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([url]) => String(url).startsWith('/api/v1/reports?'))).toHaveLength(2);
    expect(document.body).not.toHaveTextContent('TRANSIENT_SNAPSHOT_REPORT_CANARY');

    socket.lastMessage = {
      type: 'event',
      event_type: 'report_updated',
      data: { report_id: 'TRANSIENT_EVENT_REPORT_CANARY' },
    };
    view.rerender(<Reports authToken="fixture" />);
    expect(await screen.findByText('report-event-refresh')).toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([url]) => String(url).startsWith('/api/v1/reports?'))).toHaveLength(3);
    expect(document.body).not.toHaveTextContent('TRANSIENT_EVENT_REPORT_CANARY');
  });

  it('generates HTML from the selected persisted finding with only finding_id and format', async () => {
    const calls = [];
    const fetchMock = vi.fn(async (url, options = {}) => {
      const path = String(url);
      if (path.startsWith('/api/v1/reports?')) return response(200, { reports: [] });
      if (path.startsWith('/api/v1/findings?')) return response(200, { findings: [finding()] });
      if (path === '/api/v1/reports') {
        calls.push([path, JSON.parse(options.body)]);
        return response(201, { report_id: 'report-generated' });
      }
      return response(404, {});
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<Reports authToken="fixture" />);

    fireEvent.click(await screen.findByRole('button', { name: 'LOCK HTML REPORT' }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0][1]).toEqual({ finding_id: 'finding-csp-1', format: 'html' });
    expect(Object.keys(calls[0][1])).toEqual(['finding_id', 'format']);
  });

  it('prepares report.export authorization before downloading the backend HTML blob', async () => {
    const calls = [];
    const backendBlob = new Blob(['BACKEND_LOCKED_REPORT_HTML'], { type: 'text/html' });
    const blob = vi.fn().mockResolvedValue(backendBlob);
    const createObjectURL = vi.fn().mockReturnValue('blob:report-export');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL });
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    const fetchMock = vi.fn(async (url, options = {}) => {
      const path = String(url);
      if (path.startsWith('/api/v1/reports?')) return response(200, { reports: [report()] });
      if (path.startsWith('/api/v1/findings?')) return response(200, { findings: [] });
      if (path === '/api/v1/action-confirmations') {
        calls.push(['prepare', JSON.parse(options.body)]);
        return response(200, {
          job_id: 'job-report-export',
          scope: ['fixture.invalid'],
          exclude: [],
          confirmations: [confirmation],
          authorized: false,
        });
      }
      if (path === '/api/v1/reports/download') {
        calls.push(['download', JSON.parse(options.body)]);
        return response(200, {}, { blob });
      }
      return response(404, {});
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<Reports authToken="fixture" />);

    fireEvent.click(await screen.findByRole('button', { name: 'AUTHORIZED EXPORT' }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[0]).toEqual(['prepare', {
      intent: 'report.export',
      report_id: 'report-html-1',
      scope: ['fixture.invalid'],
      exclude: [],
    }]);
    expect(calls[1]).toEqual(['download', {
      report_id: 'report-html-1',
      format: 'html',
      job_id: 'job-report-export',
      scope: ['fixture.invalid'],
      exclude: [],
      confirmation,
    }]);
    expect(blob).toHaveBeenCalledOnce();
    expect(createObjectURL).toHaveBeenCalledWith(backendBlob);
    expect(anchorClick).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:report-export');
    expect(document.body).not.toHaveTextContent('RAW_REPORT_CANARY');
    expect(document.body).not.toHaveTextContent('PROTECTED_REPORT_CANARY');
  });

  it('shows generation conflicts without adding an optimistic locked report', async () => {
    const fetchMock = vi.fn(async (url, options = {}) => {
      const path = String(url);
      if (path.startsWith('/api/v1/reports?')) return response(200, { reports: [] });
      if (path.startsWith('/api/v1/findings?')) return response(200, { findings: [finding()] });
      if (path === '/api/v1/reports') {
        expect(JSON.parse(options.body)).toEqual({ finding_id: 'finding-csp-1', format: 'html' });
        return response(409, { detail: 'report version conflict' });
      }
      return response(404, {});
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<Reports authToken="fixture" />);

    const lockButton = await screen.findByRole('button', { name: 'LOCK HTML REPORT' });
    fireEvent.click(lockButton);
    expect(await screen.findByRole('alert')).toHaveTextContent('report version conflict');
    expect(screen.queryByText('report-generated')).not.toBeInTheDocument();
    expect(screen.queryByText('LOCKING…')).not.toBeInTheDocument();
    expect(lockButton).not.toBeDisabled();
  });

  it('shows unauthorized export errors without POSTing or leaving optimistic export state', async () => {
    const calls = [];
    const fetchMock = vi.fn(async (url, options = {}) => {
      const path = String(url);
      if (path.startsWith('/api/v1/reports?')) return response(200, { reports: [report()] });
      if (path.startsWith('/api/v1/findings?')) return response(200, { findings: [] });
      if (path === '/api/v1/action-confirmations') {
        calls.push(['prepare', JSON.parse(options.body)]);
        return response(403, { detail: { reason_code: 'report export authorization required' } });
      }
      if (path === '/api/v1/reports/download') calls.push(['download', JSON.parse(options.body)]);
      return response(404, {});
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<Reports authToken="fixture" />);

    const exportButton = await screen.findByRole('button', { name: 'AUTHORIZED EXPORT' });
    fireEvent.click(exportButton);
    expect(await screen.findByRole('alert')).toHaveTextContent('report export authorization required');
    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe('prepare');
    expect(screen.queryByText('EXPORTING…')).not.toBeInTheDocument();
    expect(exportButton).not.toBeDisabled();
  });
});
