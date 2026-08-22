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

const response = (payload) => ({
  ok: true,
  status: 200,
  json: vi.fn().mockResolvedValue(payload),
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
    vi.unstubAllGlobals();
    localStorage.clear();
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

  it('preserves normalized WebSocket truth without optimistic status or retest promotion', async () => {
    const view = render(<Vulnerabilities authToken="fixture" />);
    await screen.findByText('Visible candidate signal');

    socket.lastMessage = {
      type: 'event',
      event_type: 'finding_new',
      data: {
        id: 'finding-live-truth',
        title: 'Live candidate signal',
        severity: 'critical',
        target: 'fixture.invalid',
        status: 'false_positive',
        confidence: 'LOW',
        verification_state: 'candidate',
        proof_type: 'passive',
        maturity: 'experimental',
        retest_status: 'inconclusive',
      },
    };
    view.rerender(<Vulnerabilities authToken="fixture" />);

    expect(await screen.findByText('Live candidate signal')).toBeInTheDocument();
    expect(screen.getByText('passive / experimental')).toBeInTheDocument();
    expect(screen.getByText('inconclusive')).toBeInTheDocument();
    expect(screen.getAllByText('False Positive').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByText('Live candidate signal'));
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
