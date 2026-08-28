import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import Vulnerabilities from '../Vulnerabilities';

const socket = vi.hoisted(() => ({ lastMessage: null }));

vi.mock('../../hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    isConnected: true,
    lastMessage: socket.lastMessage,
    lastError: '',
  }),
}));

const response = (payload, extra = {}) => ({
  ok: true,
  status: 200,
  json: vi.fn().mockResolvedValue(payload),
  ...extra,
});

const persistedEvidence = {
  state: 'persisted',
  request_raw: 'IGNORED_LEGACY_RAW_CANARY',
  original_relative_path: '/private/original.bin',
  observations: [null, 7, {
    observation_id: 'observation-ui-truth',
    artifacts: [null, 'malformed', {
      artifact_id: 'artifact-ui-truth',
      capture_kind: 'response',
      derivative: 'PERSISTED_DERIVATIVE_CANARY',
      derivative_sha256: 'sha256:' + '1'.repeat(64),
      manifest_digest: 'sha256:' + '2'.repeat(64),
    }],
  }],
};

const visibleFinding = (overrides = {}) => ({
  id: 'finding-visible-truth',
  title: 'Visible candidate signal',
  severity: 'high',
  target: 'fixture.invalid',
  status: 'accepted_risk',
  verification_state: 'candidate',
  proof_type: 'version_correlation',
  maturity: 'heuristic',
  ...overrides,
});

describe('Vulnerabilities visible truth contract', () => {
  beforeEach(() => {
    localStorage.clear();
    socket.lastMessage = null;
    vi.stubGlobal('fetch', vi.fn(async () => response({
      findings: [{
        id: 'finding-visible-truth',
        title: 'Visible candidate signal',
        severity: 'high',
        target: 'fixture.invalid',
        status: 'accepted_risk',
        verification_state: 'candidate',
        proof_type: 'version_correlation',
        maturity: 'heuristic',
      }],
    })));
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it('renders persisted derivative evidence while withholding legacy raw and original fields', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response({
      findings: [visibleFinding({ evidence: persistedEvidence })],
    })));
    render(<Vulnerabilities authToken="fixture" />);

    fireEvent.click(await screen.findByText('Visible candidate signal'));
    expect(await screen.findByText(/PERSISTED_DERIVATIVE_CANARY/)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('IGNORED_LEGACY_RAW_CANARY');
    expect(document.body).not.toHaveTextContent('/private/original.bin');
  });

  it('treats live findings as invalidations and renders only refreshed persisted truth', async () => {
    let calls = 0;
    const fetchMock = vi.fn(async () => {
      calls += 1;
      return response({
        findings: calls === 1 ? [] : [visibleFinding({
          title: 'Persisted refreshed signal',
          evidence: persistedEvidence,
        })],
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<Vulnerabilities authToken="fixture" />);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    socket.lastMessage = {
      type: 'event',
      event_type: 'finding_new',
      data: visibleFinding({
        id: 'finding-transient-live',
        title: 'TRANSIENT_WEBSOCKET_CANARY',
        request_raw: 'TRANSIENT_RAW_CANARY',
      }),
    };
    view.rerender(<Vulnerabilities authToken="fixture" />);
    expect(await screen.findByText('Persisted refreshed signal')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(document.body).not.toHaveTextContent('TRANSIENT_WEBSOCKET_CANARY');
    expect(document.body).not.toHaveTextContent('TRANSIENT_RAW_CANARY');
  });

  it('refreshes canonical retest truth after an authenticated reconnect snapshot', async () => {
    let calls = 0;
    const fetchMock = vi.fn(async () => {
      calls += 1;
      return response({
        findings: [visibleFinding({
          retest_state: 'terminal',
          retest_status: calls === 1 ? 'inconclusive' : 'unsupported',
          retest_verdict: calls === 1 ? 'inconclusive' : 'unsupported',
        })],
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<Vulnerabilities authToken="fixture" />);
    expect(await screen.findByText('inconclusive')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    socket.lastMessage = {
      type: 'state_snapshot',
      data: {
        findings: [{
          id: 'finding-visible-truth',
          retest_verdict: 'fixed',
          status: 'Fixed',
        }],
      },
    };
    view.rerender(<Vulnerabilities authToken="fixture" />);

    expect(await screen.findByText('unsupported')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(document.body).not.toHaveTextContent('fixed');
  });

  it('delegates bulk export to the backend with only selected finding IDs', async () => {
    const backendBlob = new Blob(['BACKEND_EXPORT_RESULT_CANARY'], { type: 'application/json' });
    const blob = vi.fn().mockResolvedValue(backendBlob);
    const createObjectURL = vi.fn().mockReturnValue('blob:backend-export');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL });
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    const fetchMock = vi.fn(async (url, _options) => {
      if (url === '/api/v1/findings/export') {
        return response({}, { blob });
      }
      return response({ findings: [visibleFinding({
        description: 'LOCAL_HYDRATED_OBJECT_CANARY',
        evidence: persistedEvidence,
      })] });
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<Vulnerabilities authToken="fixture" />);

    await screen.findByText('Visible candidate signal');
    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[checkboxes.length - 1]);
    fireEvent.click(screen.getByRole('button', { name: 'Export JSON' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/v1/findings/export',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ finding_ids: ['finding-visible-truth'] }),
        }),
      );
    });
    const exportCall = fetchMock.mock.calls.find(([url]) => url === '/api/v1/findings/export');
    if (!exportCall) throw new Error('Expected canonical export request');
    const exportOptions = exportCall[1];
    if (!exportOptions) throw new Error('Expected canonical export request options');
    expect(exportOptions.body).toBe(JSON.stringify({ finding_ids: ['finding-visible-truth'] }));
    expect(exportOptions.body).not.toContain('LOCAL_HYDRATED_OBJECT_CANARY');
    expect(exportOptions.body).not.toContain('IGNORED_LEGACY_RAW_CANARY');
    expect(blob).toHaveBeenCalledTimes(1);
    expect(createObjectURL).toHaveBeenCalledWith(backendBlob);
    expect(anchorClick).toHaveBeenCalledTimes(1);
    expect(await backendBlob.text()).not.toContain('LOCAL_HYDRATED_OBJECT_CANARY');
    expect(await backendBlob.text()).not.toContain('IGNORED_LEGACY_RAW_CANARY');
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:backend-export');
  });

  it('renders API truth in list and detail views with fail-closed defaults', async () => {
    render(<Vulnerabilities authToken="fixture" />);

    expect(await screen.findByText('Visible candidate signal')).toBeInTheDocument();
    expect(screen.getByText('version_correlation / heuristic')).toBeInTheDocument();
    expect(screen.getByText('UNVERIFIED')).toBeInTheDocument();
    expect(screen.getByText('not_retested')).toBeInTheDocument();
    expect(screen.getAllByText('Accepted').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByText('Visible candidate signal'));
    await waitFor(() => {
      expect(screen.getByText(/Verification:/)).toHaveTextContent('candidate');
      expect(screen.getByText(/Proof:/)).toHaveTextContent('version_correlation');
      expect(screen.getByText(/Maturity:/)).toHaveTextContent('heuristic');
      expect(screen.getByText(/Confidence:/)).toHaveTextContent('UNVERIFIED');
      expect(screen.getByText(/Retest:/)).toHaveTextContent('not_retested');
      expect(screen.getByText(/Workflow:/)).toHaveTextContent('Accepted');
    });
  });

  it('preserves normalized persisted refresh truth without optimistic status or retest promotion', async () => {
    let calls = 0;
    vi.stubGlobal('fetch', vi.fn(async () => {
      calls += 1;
      return response({
        findings: calls === 1 ? [visibleFinding()] : [{
          id: 'finding-live-truth',
          title: 'Persisted live candidate signal',
          severity: 'critical',
          target: 'fixture.invalid',
          status: 'false_positive',
          confidence: 'LOW',
          verification_state: 'candidate',
          proof_type: 'passive',
          maturity: 'experimental',
          retest_status: 'inconclusive',
          evidence: persistedEvidence,
        }],
      });
    }));
    const view = render(<Vulnerabilities authToken="fixture" />);
    await screen.findByText('Visible candidate signal');

    socket.lastMessage = {
      type: 'event',
      event_type: 'finding_new',
      data: {
        id: 'finding-live-truth',
        title: 'UNPERSISTED_EVENT_TITLE_CANARY',
        severity: 'critical',
        target: 'fixture.invalid',
        status: 'open',
        request_raw: 'UNPERSISTED_EVENT_RAW_CANARY',
      },
    };
    view.rerender(<Vulnerabilities authToken="fixture" />);

    expect(await screen.findByText('Persisted live candidate signal')).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent('UNPERSISTED_EVENT_TITLE_CANARY');
    expect(document.body).not.toHaveTextContent('UNPERSISTED_EVENT_RAW_CANARY');
    expect(screen.getByText('passive / experimental')).toBeInTheDocument();
    expect(screen.getByText('inconclusive')).toBeInTheDocument();
    expect(screen.getAllByText('False Positive').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByText('Persisted live candidate signal'));
    await waitFor(() => {
      expect(screen.getByText(/Verification:/)).toHaveTextContent('candidate');
      expect(screen.getByText(/Proof:/)).toHaveTextContent('passive');
      expect(screen.getByText(/Maturity:/)).toHaveTextContent('experimental');
      expect(screen.getByText(/Confidence:/)).toHaveTextContent('LOW');
      expect(screen.getByText(/Retest:/)).toHaveTextContent('inconclusive');
      expect(screen.getByText(/Workflow:/)).toHaveTextContent('False Positive');
    });
  });
});
