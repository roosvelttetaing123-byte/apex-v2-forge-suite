import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Download, FileCheck, FileText, Shield } from 'lucide-react';

import Badge from '../components/Badge';
import Button from '../components/Button';
import Card from '../components/Card';
import TopBar from '../components/TopBar';
import { apiFetch } from '../config/api';
import { useWebSocket } from '../hooks/useWebSocket';
import {
  applyActionConfirmations,
  dashboardErrorMessage,
  prepareActionConfirmations,
} from '../utils/actionConfirmation';

const Reports = ({ authToken = undefined } = {}) => {
  const { lastMessage } = useWebSocket(undefined, authToken);
  const [reports, setReports] = useState([]);
  const [findings, setFindings] = useState([]);
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [downloading, setDownloading] = useState(null);
  const [error, setError] = useState('');
  const refreshSequence = useRef(0);

  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current;
    setLoading(true);
    try {
      const [reportsResponse, findingsResponse] = await Promise.all([
        apiFetch('/api/v1/reports?fmt=html&framework=webforge&limit=200'),
        apiFetch('/api/v1/findings?limit=200'),
      ]);
      if (!reportsResponse.ok || !findingsResponse.ok) {
        throw new Error('Canonical report state is unavailable');
      }
      const [reportsPayload, findingsPayload] = await Promise.all([
        reportsResponse.json(),
        findingsResponse.json(),
      ]);
      if (sequence !== refreshSequence.current) return;
      const persistedReports = Array.isArray(reportsPayload?.reports)
        ? reportsPayload.reports
        : [];
      const persistedFindings = Array.isArray(findingsPayload?.findings)
        ? findingsPayload.findings.filter(finding => (
          finding?.module === 'header_audit'
          && (
            finding?.finding_key === 'Content-Security-Policy'
            || String(finding?.title || '').includes('Content-Security-Policy')
          )
        ))
        : [];
      setReports(persistedReports);
      setFindings(persistedFindings);
      setSelectedFindingId(current => (
        current && persistedFindings.some(item => item.id === current)
          ? current
          : persistedFindings[0]?.id || ''
      ));
      setError('');
    } catch (refreshError) {
      if (sequence === refreshSequence.current) {
        setError(refreshError instanceof Error ? refreshError.message : 'Report refresh failed');
      }
    } finally {
      if (sequence === refreshSequence.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    return () => { refreshSequence.current += 1; };
  }, [refresh]);

  useEffect(() => {
    if (!lastMessage) return;
    if (lastMessage.type === 'state_snapshot') {
      void refresh();
      return;
    }
    if (
      lastMessage.type === 'event'
      && ['report_updated', 'export_completed', 'finding_updated'].includes(lastMessage.event_type)
    ) {
      void refresh();
    }
  }, [lastMessage, refresh]);

  const selectedFinding = useMemo(
    () => findings.find(item => item.id === selectedFindingId) || null,
    [findings, selectedFindingId],
  );

  const generateReport = useCallback(async () => {
    if (!selectedFinding) return;
    setGenerating(true);
    setError('');
    try {
      const response = await apiFetch('/api/v1/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: selectedFinding.id, format: 'html' }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(dashboardErrorMessage(payload, `Report generation failed (${response.status})`));
      }
      await refresh();
    } catch (generationError) {
      setError(generationError instanceof Error ? generationError.message : 'Report generation failed');
    } finally {
      setGenerating(false);
    }
  }, [refresh, selectedFinding]);

  const downloadReport = useCallback(async (report) => {
    if (!report?.report_id || !report?.target) return;
    setDownloading(report.report_id);
    setError('');
    try {
      const confirmation = await prepareActionConfirmations({
        intent: 'report.export',
        report_id: report.report_id,
        scope: [report.target],
        exclude: [],
      });
      const response = await apiFetch('/api/v1/reports/download', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(applyActionConfirmations({
          report_id: report.report_id,
          format: 'html',
        }, confirmation)),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(dashboardErrorMessage(payload, `Report export failed (${response.status})`));
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `forge-report-v${report.version}.html`;
      anchor.click();
      URL.revokeObjectURL(url);
      await refresh();
    } catch (downloadError) {
      setError(downloadError instanceof Error ? downloadError.message : 'Report export failed');
    } finally {
      setDownloading(null);
    }
  }, [refresh]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar
        title="Locked Reference Reports"
        subtitle="Canonical header_audit CSP source sets, immutable HTML versions, and audited exports"
        actions={
          <Button variant="primary" disabled={!selectedFinding || generating} onClick={generateReport}>
            {generating ? 'LOCKING…' : 'LOCK HTML REPORT'}
          </Button>
        }
      />
      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>
        <div style={{ display: 'flex', gap: '14px' }}>
          <Card style={{ flex: 1 }}>
            <FileText size={20} color="var(--color-info)" />
            <div className="font-mono text-muted" style={{ fontSize: '10px', marginTop: '8px' }}>LOCKED HTML VERSIONS</div>
            <div className="font-heading" style={{ fontSize: '30px' }}>{reports.length}</div>
          </Card>
          <Card style={{ flex: 1 }}>
            <Shield size={20} color="var(--color-medium)" />
            <div className="font-mono text-muted" style={{ fontSize: '10px', marginTop: '8px' }}>ELIGIBLE CSP FINDINGS</div>
            <div className="font-heading" style={{ fontSize: '30px' }}>{findings.length}</div>
          </Card>
          <Card style={{ flex: 2 }}>
            <FileCheck size={20} color="var(--color-success)" />
            <div className="font-mono text-muted" style={{ fontSize: '10px', marginTop: '8px' }}>SUPPORTED FORMAT</div>
            <div style={{ marginTop: '6px' }}><Badge severity="active">HTML — persisted and locked</Badge></div>
            <div className="text-muted" style={{ fontSize: '11px', marginTop: '8px' }}>PDF, JSON, scheduling, custom builders, and compliance reports remain disabled for this slice.</div>
          </Card>
        </div>

        <Card title="Reference Source">
          {findings.length ? (
            <select aria-label="Reference finding" value={selectedFindingId} onChange={event => setSelectedFindingId(event.target.value)} style={{ width: '100%' }}>
              {findings.map(finding => (
                <option key={finding.id} value={finding.id}>
                  {finding.title} — {finding.target} — review v{finding.review_version || 0}
                </option>
              ))}
            </select>
          ) : (
            <div className="text-muted">No persisted header_audit CSP finding is ready for reviewer/retest/report workflow.</div>
          )}
        </Card>

        {error && <div role="alert" style={{ color: 'var(--color-critical)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{error}</div>}

        <Card title="Persisted Report Versions" style={{ flex: 1 }} noPadding>
          <table>
            <thead>
              <tr>
                <th>Version</th><th>Report ID</th><th>Source Digest</th><th>Artifact Hash</th><th>Locked By</th><th>State</th><th>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} style={{ textAlign: 'center', padding: '36px' }}>Loading canonical reports…</td></tr>
              ) : reports.length === 0 ? (
                <tr><td colSpan={7} style={{ textAlign: 'center', padding: '36px' }}>No locked report version exists.</td></tr>
              ) : reports.map(report => (
                <tr key={report.report_id}>
                  <td>v{report.version}</td>
                  <td><code>{report.report_id}</code></td>
                  <td><code>{report.source_digest}</code></td>
                  <td><code>{report.artifact_sha256}</code></td>
                  <td>{report.created_by_operator_id}</td>
                  <td><Badge severity="active">LOCKED</Badge></td>
                  <td>
                    <Button variant="secondary" disabled={downloading === report.report_id} onClick={() => downloadReport(report)}>
                      <Download size={14} /> {downloading === report.report_id ? 'EXPORTING…' : 'AUTHORIZED EXPORT'}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
};

export default Reports;
