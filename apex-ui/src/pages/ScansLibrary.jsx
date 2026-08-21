import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import { RefreshCw, Trash2 } from 'lucide-react';

import { apiFetch } from '../config/api';

const STATUS_COLOR = {
  running:     'var(--color-high)',
  completed:   'var(--color-success)',
  failed:      'var(--color-critical)',
  interrupted: 'var(--color-medium)',
  aborted:     'var(--color-critical)',
  orphaned:    'var(--color-medium)',
};

const SCAN_TEMPLATES = [
  { name: 'Web Application',      desc: 'OWASP Top 10 + custom modules',   type: 'web' },
  { name: 'Network Infrastructure', desc: 'Ports, services, CVEs',          type: 'net' },
  { name: 'Full VAPT',            desc: 'Web + network combined engagement', type: 'vapt' },
  { name: 'API Security',         desc: 'REST, GraphQL, SOAP, OAuth',        type: 'web' },
  { name: 'Cloud Configuration',  desc: 'AWS, Azure, GCP misconfigs',        type: 'net' },
  { name: 'Mobile Application',   desc: 'APK/IPA static + dynamic',          type: 'web' },
];

const ScansLibrary = ({ authToken: _authToken = '' }) => {
  const navigate = useNavigate();
  const [selectedTemplate, setSelectedTemplate] = useState(SCAN_TEMPLATES[0].name);
  const [scanHistory, setScanHistory]           = useState([]);
  const [historyLoading, setHistoryLoading]     = useState(false);
  const [deleteError, setDeleteError]           = useState('');

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await apiFetch('/api/v1/scans/history?limit=100');
      if (res.ok) {
        const data = await res.json();
        setScanHistory(data.history || []);
      }
    } catch {
      // backend offline — history stays empty
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  const deleteScan = useCallback(async (event, scanId) => {
    event.stopPropagation();
    if (!scanId || !window.confirm(`Delete scan ${scanId} from dashboard history?`)) return;
    setDeleteError('');
    try {
      const res = await apiFetch(`/api/v1/scans/${encodeURIComponent(scanId)}`, { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setDeleteError(data.detail || `Delete failed (${res.status})`);
        return;
      }
      setScanHistory(prev => prev.filter(row => row.scan_id !== scanId));
    } catch {
      setDeleteError('Cannot reach backend');
    }
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar
        title="Scan Templates & History"
        subtitle="Reusable scan profiles and full engagement scan history"
        actions={
          <>
            <Button variant="secondary">IMPORT TEMPLATE</Button>
            <Button variant="primary">+ NEW TEMPLATE</Button>
          </>
        }
      />
      <div style={{ padding: '18px 32px', display: 'flex', gap: '14px', flex: 1, minHeight: 0 }}>

        {/* LEFT COLUMN: Templates */}
        <div style={{ width: '300px', display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          {SCAN_TEMPLATES.map(tpl => {
            const isActive = selectedTemplate === tpl.name;
            return (
              <Card
                key={tpl.name}
                style={{
                  backgroundColor: isActive ? 'rgba(255,255,255,0.03)' : 'var(--bg-card)',
                  border: isActive ? '1px solid var(--color-brand-red)' : '1px solid var(--border-color)',
                  cursor: 'pointer',
                }}
                onClick={() => setSelectedTemplate(tpl.name)}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <div style={{ fontWeight: 500, color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                    {tpl.name}
                  </div>
                  <Badge severity="info" style={{ fontSize: '10px', padding: '1px 6px' }}>{tpl.type.toUpperCase()}</Badge>
                </div>
                <div className="text-muted" style={{ fontSize: '12px' }}>{tpl.desc}</div>
              </Card>
            );
          })}
          <Card style={{ border: '1px dashed var(--border-secondary)', backgroundColor: 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', minHeight: '56px' }}>
            <div style={{ color: 'var(--text-muted)', fontWeight: 500 }}>+ Custom Template</div>
          </Card>
        </div>

        {/* RIGHT COLUMN: Scan History */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          <Card
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span>Scan History</span>
                {scanHistory.length > 0 && (
                  <span className="font-mono text-muted" style={{ fontSize: '11px' }}>{scanHistory.length} records</span>
                )}
              </div>
            }
            headerRight={
              <Button variant="secondary" style={{ padding: '4px 10px', fontSize: '12px', gap: '6px' }} onClick={fetchHistory}>
                <RefreshCw size={12} />
                REFRESH
              </Button>
            }
            style={{ flex: 1 }}
            noPadding
          >
            {historyLoading ? (
              <div style={{ padding: '48px 24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                Loading history…
              </div>
            ) : scanHistory.length === 0 ? (
              <div style={{ padding: '64px 24px', textAlign: 'center' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '6px' }}>No scan history yet.</div>
                <div style={{ color: 'var(--text-dimmed)', fontSize: '12px' }}>
                  Completed scans are logged here automatically.
                  <br />
                  Start a scan from the Automated Scanning page.
                </div>
              </div>
            ) : (
              <>
              {deleteError && (
                <div className="font-mono" style={{ padding: '10px 16px', color: 'var(--color-critical)', fontSize: '12px' }}>
                  {deleteError}
                </div>
              )}
              <table>
                <thead>
                  <tr>
                    <th>Scan ID</th>
                    <th>Target</th>
                    <th>Profile</th>
                    <th>Mode</th>
                    <th>Started</th>
                    <th style={{ textAlign: 'center', color: 'var(--color-critical)' }}>C</th>
                    <th style={{ textAlign: 'center', color: 'var(--color-high)' }}>H</th>
                    <th style={{ textAlign: 'center', color: 'var(--color-medium)' }}>M</th>
                    <th style={{ textAlign: 'center', color: 'var(--color-low)' }}>L</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scanHistory.map((row, i) => {
                    const fc      = row.findings_count || {};
                    const started = row.started_at
                      ? new Date(row.started_at).toLocaleString(undefined, { month: 'short', day: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
                      : '—';
                    const status    = row.status || 'unknown';
                    const typeLabel = row.scan_type || row.frameworks?.[0] || '—';
                    return (
                      <tr
                        key={row.scan_id || i}
                        className="clickable-row"
                        tabIndex={0}
                        onClick={() => row.scan_id && navigate(`/scans/${row.scan_id}`)}
                        onKeyDown={(event) => {
                          if ((event.key === 'Enter' || event.key === ' ') && row.scan_id) {
                            event.preventDefault();
                            navigate(`/scans/${row.scan_id}`);
                          }
                        }}
                        title="Open scan details"
                      >
                        <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{row.scan_id}</td>
                        <td className="font-mono" style={{ fontSize: '13px' }}>{row.target}</td>
                        <td>{typeLabel.toUpperCase()}</td>
                        <td className="text-muted" style={{ fontSize: '12px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                          {row.mode || '—'}
                        </td>
                        <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{started}</td>
                        <td className="font-mono" style={{ textAlign: 'center', fontSize: '13px', fontWeight: (fc.critical || 0) > 0 ? 600 : 400, color: (fc.critical || 0) > 0 ? 'var(--color-critical)' : 'var(--text-dimmed)' }}>{fc.critical ?? 0}</td>
                        <td className="font-mono" style={{ textAlign: 'center', fontSize: '13px', fontWeight: (fc.high || 0) > 0 ? 600 : 400, color: (fc.high || 0) > 0 ? 'var(--color-high)' : 'var(--text-dimmed)' }}>{fc.high ?? 0}</td>
                        <td className="font-mono" style={{ textAlign: 'center', fontSize: '13px', color: (fc.medium || 0) > 0 ? 'var(--color-medium)' : 'var(--text-dimmed)' }}>{fc.medium ?? 0}</td>
                        <td className="font-mono" style={{ textAlign: 'center', fontSize: '13px', color: (fc.low || 0) > 0 ? 'var(--color-low)' : 'var(--text-dimmed)' }}>{fc.low ?? 0}</td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            {status === 'running' && <div className="status-dot pulse bg-high" style={{ width: '6px', height: '6px', flexShrink: 0 }} />}
                            <span
                              className="font-mono"
                              style={{
                                fontSize: '11px',
                                textTransform: 'uppercase',
                                color: STATUS_COLOR[status] || 'var(--text-muted)',
                              }}
                            >
                              {status}
                            </span>
                          </div>
                        </td>
                        <td>
                          <Button
                            variant="secondary"
                            style={{ padding: '4px 8px', color: 'var(--color-critical)', borderColor: 'rgba(255,68,68,0.35)' }}
                            onClick={(event) => deleteScan(event, row.scan_id)}
                          >
                            <Trash2 size={13} />
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              </>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
};

export default ScansLibrary;
