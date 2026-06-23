import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, ExternalLink, RefreshCw, Trash2 } from 'lucide-react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import { apiFetch } from '../config/api';

const STATUS_COLOR = {
  running: 'var(--color-high)',
  completed: 'var(--color-success)',
  failed: 'var(--color-critical)',
  interrupted: 'var(--color-medium)',
  aborted: 'var(--color-critical)',
  stopped: 'var(--color-critical)',
  orphaned: 'var(--color-medium)',
};

const formatDate = (value) => {
  if (!value) return '-';
  return new Date(value).toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

const bytes = (value) => {
  if (!Number.isFinite(value)) return '-';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
};

export default function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [deleting, setDeleting] = useState(false);

  const fetchScan = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await apiFetch(`/api/v1/scans/${encodeURIComponent(scanId)}`);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.detail || `Error ${res.status}`);
        return;
      }
      setScan(data);
    } catch {
      setError('Cannot reach backend');
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => { fetchScan(); }, [fetchScan]);

  const deleteScan = useCallback(async () => {
    if (!scanId || !window.confirm(`Delete scan ${scanId} from dashboard history?`)) return;
    setDeleting(true);
    setError('');
    try {
      const res = await apiFetch(`/api/v1/scans/${encodeURIComponent(scanId)}`, { method: 'DELETE' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.detail || `Delete failed (${res.status})`);
        return;
      }
      navigate('/scans');
    } catch {
      setError('Cannot reach backend');
    } finally {
      setDeleting(false);
    }
  }, [scanId, navigate]);

  const counts = scan?.findings_count || {};
  const modules = useMemo(() => scan?.actual_modules?.length ? scan.actual_modules : scan?.requested_modules || [], [scan]);
  const status = scan?.status || 'unknown';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar
        title={scan ? `Scan ${scan.scan_id}` : 'Scan Detail'}
        subtitle={scan ? `${scan.target} · ${scan.scan_type || 'scan'} · ${status}` : 'Loading scan record'}
        actions={
          <div style={{ display: 'flex', gap: '8px' }}>
            <Button variant="secondary" onClick={() => navigate(-1)}>
              <ArrowLeft size={14} />
              BACK
            </Button>
            <Button variant="secondary" onClick={fetchScan}>
              <RefreshCw size={14} />
              REFRESH
            </Button>
            <Button
              variant="secondary"
              onClick={deleteScan}
              disabled={deleting}
              style={{ color: 'var(--color-critical)', borderColor: 'rgba(255,68,68,0.35)' }}
            >
              <Trash2 size={14} />
              {deleting ? 'DELETING' : 'DELETE'}
            </Button>
          </div>
        }
      />

      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>
        {loading ? (
          <Card><div className="text-muted" style={{ textAlign: 'center', padding: '40px' }}>Loading scan...</div></Card>
        ) : error ? (
          <Card><div className="font-mono" style={{ color: 'var(--color-critical)', padding: '24px' }}>{error}</div></Card>
        ) : scan && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '14px' }}>
              {[
                ['Critical', counts.critical || 0, 'critical'],
                ['High', counts.high || 0, 'high'],
                ['Medium', counts.medium || 0, 'medium'],
                ['Low', counts.low || 0, 'low'],
              ].map(([label, value, color]) => (
                <Card key={label}>
                  <div className="font-mono text-muted" style={{ fontSize: '10px', textTransform: 'uppercase' }}>{label}</div>
                  <div className="font-heading" style={{ fontSize: '42px', lineHeight: 1, color: value > 0 ? `var(--color-${color})` : 'var(--text-dimmed)' }}>{value}</div>
                </Card>
              ))}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
              <Card title="Scan Summary">
                <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', rowGap: '10px', columnGap: '16px', fontSize: '13px' }}>
                  <span className="text-muted">Target</span><span className="font-mono">{scan.target}</span>
                  <span className="text-muted">Engagement</span><span>{scan.engagement || '-'}</span>
                  <span className="text-muted">Type</span><span>{(scan.scan_type || '-').toUpperCase()}</span>
                  <span className="text-muted">Mode</span><span>{(scan.mode || '-').toUpperCase()}</span>
                  <span className="text-muted">Started</span><span>{formatDate(scan.started_at)}</span>
                  <span className="text-muted">Status</span>
                  <span className="font-mono" style={{ color: STATUS_COLOR[status] || 'var(--text-muted)', textTransform: 'uppercase' }}>{status}</span>
                </div>
              </Card>

              <Card title="Selected Modules">
                {modules.length === 0 ? (
                  <div className="text-muted" style={{ fontSize: '13px' }}>No explicit module selection was recorded.</div>
                ) : (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                    {modules.map((module) => <Badge key={module} severity="info">{module}</Badge>)}
                  </div>
                )}
              </Card>
            </div>

            <Card title="Framework Processes" noPadding>
              {scan.processes?.length ? (
                <table>
                  <thead>
                    <tr><th>Process</th><th>Framework</th><th>Target</th><th>Started</th><th>Return</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {scan.processes.map((proc) => (
                      <tr key={proc.process_id}>
                        <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{proc.process_id}</td>
                        <td>{(proc.framework || '-').toUpperCase()}</td>
                        <td className="font-mono" style={{ fontSize: '12px' }}>{proc.target}</td>
                        <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{formatDate(proc.started_at)}</td>
                        <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{proc.returncode ?? '-'}</td>
                        <td className="font-mono" style={{ fontSize: '11px', textTransform: 'uppercase', color: STATUS_COLOR[proc.status] || 'var(--text-muted)' }}>{proc.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="text-muted" style={{ padding: '24px', fontSize: '13px' }}>No active subprocess metadata is available for this scan.</div>
              )}
            </Card>

            <Card title="Reports" noPadding>
              {scan.reports?.length ? (
                <table>
                  <thead>
                    <tr><th>Report</th><th>Framework</th><th>Format</th><th>Size</th><th>Modified</th></tr>
                  </thead>
                  <tbody>
                    {scan.reports.map((report) => (
                      <tr key={report.path}>
                        <td className="font-mono" style={{ fontSize: '12px' }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                            {report.path}
                            <ExternalLink size={12} color="var(--text-muted)" />
                          </span>
                        </td>
                        <td>{report.framework}</td>
                        <td>{report.format}</td>
                        <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{bytes(report.size)}</td>
                        <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{formatDate(report.modified_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="text-muted" style={{ padding: '24px', fontSize: '13px' }}>No report artifacts found yet.</div>
              )}
            </Card>

            <Card title="Findings" noPadding>
              {scan.findings?.length ? (
                <table>
                  <thead>
                    <tr><th>Severity</th><th>Title</th><th>Target</th><th>Module</th><th>Framework</th></tr>
                  </thead>
                  <tbody>
                    {scan.findings.map((finding, index) => {
                      const sev = (finding.severity || 'info').toLowerCase();
                      return (
                        <tr key={finding.id || index}>
                          <td><Badge severity={sev}>{sev}</Badge></td>
                          <td>{finding.title || finding.name || finding.description || 'Untitled finding'}</td>
                          <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{finding.url || finding.target || '-'}</td>
                          <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{finding.module || '-'}</td>
                          <td>{finding.framework || '-'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <div className="text-muted" style={{ padding: '24px', fontSize: '13px' }}>No findings recorded for this scan.</div>
              )}
            </Card>

            {scan.processes?.some(proc => proc.log_tail) && (
              <Card title="Log Tail">
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  {scan.processes.filter(proc => proc.log_tail).map((proc) => (
                    <div key={proc.process_id}>
                      <div className="font-mono text-muted" style={{ fontSize: '11px', marginBottom: '6px' }}>{proc.process_id}</div>
                      <pre style={{
                        margin: 0,
                        padding: '12px',
                        maxHeight: '260px',
                        overflow: 'auto',
                        background: 'var(--bg-input)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '4px',
                        color: 'var(--text-secondary)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '12px',
                        whiteSpace: 'pre-wrap',
                      }}>{proc.log_tail}</pre>
                    </div>
                  ))}
                </div>
              </Card>
            )}
          </>
        )}
      </div>
    </div>
  );
}
