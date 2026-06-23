import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import CredentialsCard from '../components/CredentialsCard';
import { Wifi, WifiOff, Brain, CheckCircle, AlertTriangle, XCircle, Square, Pause, Play, RefreshCw, Server, Trash2 } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';

import { apiFetch } from '../config/api';

const STATUS_COLOR = {
  running:     'var(--color-high)',
  complete:    'var(--color-success)',   // scan_complete → replace('scan_','') → 'complete'
  completed:   'var(--color-success)',   // in case backend uses past tense
  failed:      'var(--color-critical)',
  interrupted: 'var(--color-medium)',
  aborted:     'var(--color-critical)',
  orphaned:    'var(--color-medium)',
};

const AutomatedScans = ({ authToken }) => {
  const navigate = useNavigate();
  const { isConnected, lastMessage, lastError: wsError } = useWebSocket(undefined, authToken);
  const scanEndTimer = useRef(null);

  // Clear scan-end timer on unmount to avoid state updates on unmounted component
  useEffect(() => () => clearTimeout(scanEndTimer.current), []);

  // Scan form
  const [target, setTarget]       = useState('');
  const [scanType, setScanType]   = useState('web');
  const [scanMode, setScanMode]   = useState('blackbox');
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState('');

  // Credential state (greybox / whitebox)
  const [authType, setAuthType]           = useState('form');
  const [username, setUsername]           = useState('');
  const [password, setPassword]           = useState('');
  const [showPassword, setShowPassword]   = useState(false);
  const [token, setToken]                 = useState('');
  const [showToken, setShowToken]         = useState(false);
  const [headerName, setHeaderName]       = useState('Authorization');
  const [cookieJar, setCookieJar]         = useState('');
  const [loginUrl, setLoginUrl]           = useState('');
  const [testingCreds, setTestingCreds]   = useState(false);
  const [testResult, setTestResult]       = useState(null);

  // Active scan
  const [activeScan, setActiveScan]       = useState(null);
  const [scanProgress, setScanProgress]   = useState({ module: '', phase: '', pct: 0 });
  const [isPaused, setIsPaused]           = useState(false);

  // Live data — cleared on each new scan_start
  const [liveFindings, setLiveFindings]   = useState([]);
  const [brainVerdicts, setBrainVerdicts] = useState([]);

  // Scan history from backend
  const [scanHistory, setScanHistory]       = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [deleteError, setDeleteError]       = useState('');
  const [connection, setConnection] = useState({
    api: 'checking',
    tools: [],
    activeProcesses: 0,
    dashboardUrl: '',
    error: '',
  });

  const fetchConnection = useCallback(async () => {
    try {
      const res = await apiFetch('/api/v1/health');
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setConnection(prev => ({ ...prev, api: 'down', error: data.detail || `HTTP ${res.status}` }));
        return;
      }
      setConnection({
        api: 'up',
        tools: data.tools || [],
        activeProcesses: data.active_processes || 0,
        dashboardUrl: data.dashboard_url || '',
        error: '',
      });
    } catch {
      setConnection(prev => ({ ...prev, api: 'down', error: 'Dashboard API unreachable' }));
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await apiFetch('/api/v1/scans/history');
      if (res.ok) {
        const data = await res.json();
        setScanHistory(data.history || []);
      } else if (res.status === 401) {
        setLaunchError('Dashboard session expired. Reload and sign in again.');
      }
    } catch {
      // backend offline — history stays empty
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => { fetchHistory(); fetchConnection(); }, [fetchHistory, fetchConnection]);

  // WebSocket event handler
  useEffect(() => {
    if (!lastMessage) return;
    const { type, event_type, data } = lastMessage;

    // On reconnect the server sends a full state snapshot
    if (type === 'state_snapshot') {
      const snap = data || {};
      if (snap.scan_status === 'running' && snap.target) {
        setActiveScan({ target: snap.target, scan_id: snap.run_id, mode: snap.scan_mode });
      }
      if (snap.findings?.length) {
        setLiveFindings(snap.findings.map(f => ({
          severity: (f.severity || 'info').toLowerCase(),
          finding:  f.title || '',
          target:   f.target || '',
          module:   f.module || '',
          url:      f.url || '',
          time:     (f.timestamp || '').slice(11, 19),
        })));
      }
      return;
    }

    if (type !== 'event') return;

    switch (event_type) {
      case 'scan_start':
        setLiveFindings([]);
        setBrainVerdicts([]);
        setScanProgress({ module: '', phase: '', pct: 0 });
        setIsPaused(false);
        setActiveScan({
          scan_id:    data.scan_id || '',
          target:     data.target  || '',
          scan_type:  data.scan_type || '',
          mode:       data.mode   || '',
          started_at: new Date().toISOString(),
        });
        fetchHistory();
        fetchConnection();
        break;

      case 'scan_complete':
      case 'scan_interrupted':
      case 'scan_aborted':
      case 'scan_failed':
        setActiveScan(prev => prev ? {
          ...prev,
          status: event_type.replace('scan_', ''),
          error_log: data?.log_path || '',
        } : null);
        // Notification beep via Web Audio API
        try {
          const ctx = new (window.AudioContext || window.webkitAudioContext)();
          const osc = ctx.createOscillator();
          const gain = ctx.createGain();
          osc.connect(gain);
          gain.connect(ctx.destination);
          osc.frequency.value = event_type === 'scan_complete' ? 880 : 440;
          gain.gain.value = 0.08;
          osc.start();
          osc.stop(ctx.currentTime + 0.15);
          if (event_type === 'scan_complete') {
            // Double beep for success
            const osc2 = ctx.createOscillator();
            osc2.connect(gain);
            osc2.frequency.value = 1100;
            osc2.start(ctx.currentTime + 0.2);
            osc2.stop(ctx.currentTime + 0.35);
          }
        } catch {}
        scanEndTimer.current = setTimeout(() => {
          setActiveScan(null);
          fetchHistory();
          fetchConnection();
        }, 4000);
        break;

      case 'scan_paused':
        setIsPaused(true);
        break;

      case 'scan_resumed':
        setIsPaused(false);
        break;

      case 'module_start':
        setScanProgress(prev => ({
          ...prev,
          module: data.name || '',
          phase: data.phase ? `PHASE ${data.phase}` : prev.phase,
          pct: 0,
        }));
        break;

      case 'module_progress':
        setScanProgress(prev => ({
          ...prev,
          module: data.name || prev.module,
          pct: Math.round(data.progress || prev.pct),
        }));
        break;

      case 'module_complete':
        setScanProgress(prev => ({
          ...prev,
          module: data.name || prev.module,
          pct: 100,
        }));
        break;

      case 'finding_new':
        setLiveFindings(prev => [{
          severity: (data.severity || 'info').toLowerCase(),
          finding:  data.title  || '',
          target:   data.target || '',
          module:   data.module || '',
          url:      data.url    || data.target || '',
          time:     new Date().toISOString().slice(11, 19),
        }, ...prev].slice(0, 100));
        break;

      case 'brain_verdict':
        setBrainVerdicts(prev => [{
          finding:    data.finding    || '',
          verdict:    data.verdict    || 'LIKELY',
          confidence: data.confidence || 0,
          reason:     data.reason     || '',
        }, ...prev].slice(0, 30));
        break;

      default:
        break;
    }
  }, [lastMessage, fetchHistory, fetchConnection]);

  // Severity counts derived from live findings
  const counts = {
    critical: liveFindings.filter(f => f.severity === 'critical').length,
    high:     liveFindings.filter(f => f.severity === 'high').length,
    medium:   liveFindings.filter(f => f.severity === 'medium').length,
    low:      liveFindings.filter(f => f.severity === 'low').length,
  };

  const testCredentials = useCallback(async () => {
    setTestingCreds(true);
    setTestResult(null);
    try {
      const res = await apiFetch('/api/v1/auth/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          auth_type: authType, username, password, token,
          header_name: headerName, cookie_jar: cookieJar, login_url: loginUrl,
        }),
      });
      const data = await res.json().catch(() => ({}));
      setTestResult({
        ok: res.ok && data.success,
        message: data.message || (res.ok ? 'Auth verified' : 'Auth failed'),
      });
    } catch {
      setTestResult({ ok: false, message: 'Cannot reach backend' });
    } finally {
      setTestingCreds(false);
    }
  }, [authType, username, password, token, headerName, cookieJar, loginUrl]);

  const initiateScan = async () => {
    if (!target.trim() || activeScan || launching) return;
    setLaunchError('');
    setLaunching(true);
    try {
      const auth_profile = scanMode === 'blackbox' ? null : {
        auth_type: authType,
        username,
        password,
        token,
        header_name: headerName,
        cookie_jar: cookieJar,
        login_url: loginUrl,
      };
      const res = await apiFetch('/api/v1/scans/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim(), scan_type: scanType, mode: scanMode, auth_profile }),
      });
      if (res.ok) {
        // Clear secrets on success — preserve on failure so user can retry
        setPassword('');
        setToken('');
        setCookieJar('');
        setTestResult(null);
      } else {
        const err = await res.json().catch(() => ({}));
        setLaunchError(err.detail || `Error ${res.status}`);
      }
    } catch {
      setLaunchError('Cannot reach backend — is forge.py dashboard running?');
    } finally {
      setLaunching(false);
    }
  };

  const stopScan = async () => {
    try { await apiFetch('/api/v1/scans/stop', { method: 'POST' }); } catch {}
  };

  const togglePause = async () => {
    try {
      await apiFetch(`/api/v1/control/${isPaused ? 'resume' : 'pause'}`, { method: 'POST' });
    } catch {}
  };

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
      fetchConnection();
    } catch {
      setDeleteError('Cannot reach backend');
    }
  }, [fetchConnection]);

  const scanTypeLabel = { web: 'Web', net: 'Network', vapt: 'Full VAPT' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar
        title="Automated Scanning"
        subtitle="Vulnerability mapping and continuous asset discovery"
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: isConnected ? 'var(--color-success)' : 'var(--text-muted)' }}>
            {isConnected ? <Wifi size={16} /> : <WifiOff size={16} />}
            <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
              {isConnected ? 'LIVE' : 'OFFLINE'}
            </span>
          </div>
        }
      />

      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>

        <Card>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '16px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <Server size={18} color={connection.api === 'up' ? 'var(--color-success)' : 'var(--color-critical)'} />
              <div>
                <div style={{ fontWeight: 500, fontSize: '14px' }}>Dashboard Connections</div>
                <div className="font-mono text-muted" style={{ fontSize: '11px' }}>
                  {connection.dashboardUrl || connection.error || 'Checking backend path'}
                  {wsError ? ` · ${wsError}` : ''}
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <Badge severity={connection.api === 'up' ? 'active' : 'critical'}>API {connection.api}</Badge>
              <Badge severity={isConnected ? 'active' : 'critical'}>WS {isConnected ? 'live' : 'offline'}</Badge>
              <Badge severity={connection.activeProcesses > 0 ? 'high' : 'info'}>{connection.activeProcesses} active</Badge>
              {(connection.tools || []).filter(t => t.dashboard_launch).map(tool => (
                <Badge key={tool.id} severity={tool.ready ? 'active' : 'critical'}>{tool.name}</Badge>
              ))}
              <Button variant="secondary" style={{ padding: '4px 10px', fontSize: '12px', gap: '6px' }} onClick={() => { fetchConnection(); fetchHistory(); }}>
                <RefreshCw size={12} />
                CHECK
              </Button>
            </div>
          </div>
        </Card>

        {/* ── Scan Initiation ── */}
        <Card>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-end' }}>
            <div style={{ flex: 1 }}>
              <label className="text-muted" style={{ display: 'block', marginBottom: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Target</label>
              <input
                type="text"
                placeholder="https://target.com  ·  192.168.1.0/24  ·  10.0.0.5"
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && initiateScan()}
                style={{ width: '100%', boxSizing: 'border-box' }}
              />
            </div>
            <div style={{ minWidth: '150px' }}>
              <label className="text-muted" style={{ display: 'block', marginBottom: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Scan Type</label>
              <select value={scanType} onChange={e => setScanType(e.target.value)} style={{ width: '100%' }}>
                <option value="web">Web Application</option>
                <option value="net">Network / Infra</option>
                <option value="vapt">Full VAPT</option>
              </select>
            </div>
            <div style={{ minWidth: '140px' }}>
              <label className="text-muted" style={{ display: 'block', marginBottom: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Mode</label>
              <select value={scanMode} onChange={e => setScanMode(e.target.value)} style={{ width: '100%' }}>
                <option value="blackbox">Blackbox</option>
                <option value="greybox">Greybox</option>
                <option value="whitebox">Whitebox</option>
              </select>
            </div>
            <Button
              variant="primary"
              onClick={initiateScan}
              disabled={!target.trim() || !!activeScan || launching}
            >
              {launching ? 'LAUNCHING…' : 'INITIATE SCAN'}
            </Button>
          </div>

          {/* Credentials — shown for greybox / whitebox only */}
          {scanMode !== 'blackbox' && (
            <div style={{ marginTop: '12px' }}>
              <CredentialsCard
                mode={scanMode}
                authType={authType}           setAuthType={setAuthType}
                username={username}           setUsername={setUsername}
                password={password}           setPassword={setPassword}
                showPassword={showPassword}   setShowPassword={setShowPassword}
                token={token}                 setToken={setToken}
                showToken={showToken}         setShowToken={setShowToken}
                headerName={headerName}       setHeaderName={setHeaderName}
                cookieJar={cookieJar}         setCookieJar={setCookieJar}
                loginUrl={loginUrl}           setLoginUrl={setLoginUrl}
                onTestCredentials={testCredentials}
                testingCreds={testingCreds}
                testResult={testResult}
              />
            </div>
          )}

          {launchError && (
            <div style={{ marginTop: '10px', fontSize: '12px', color: 'var(--color-critical)', fontFamily: 'var(--font-mono)' }}>
              {launchError}
            </div>
          )}
        </Card>

        {/* ── Active Scan Progress Banner ── */}
        {activeScan && (
          <Card noPadding style={{ flexDirection: 'row', alignItems: 'center', padding: '12px 16px', gap: '16px' }}>
            <div className={`status-dot ${activeScan.status === 'failed' ? 'bg-critical' : isPaused ? 'bg-medium' : 'pulse bg-high'}`} />
            <div style={{ display: 'flex', flexDirection: 'column', minWidth: '220px' }}>
              <span style={{ fontWeight: 500, fontSize: '14px', color: 'var(--text-primary)' }}>{activeScan.target}</span>
              <span className="font-mono text-muted" style={{ fontSize: '11px' }}>
                {activeScan.scan_id || 'scan in progress'} · {scanTypeLabel[activeScan.scan_type] || activeScan.scan_type}
                {activeScan.status ? ` · ${activeScan.status}` : ''}
              </span>
            </div>
            {scanProgress.phase && (
              <span className="font-mono" style={{ color: 'var(--color-medium)', fontSize: '12px' }}>{scanProgress.phase}</span>
            )}
            {scanProgress.module && (
              <span className="font-mono text-muted" style={{ fontSize: '12px' }}>{scanProgress.module}</span>
            )}
            <div style={{ flex: 1, height: '4px', backgroundColor: 'var(--bg-input)', borderRadius: '2px', overflow: 'hidden' }}>
              <div style={{
                width: `${scanProgress.pct}%`,
                height: '100%',
                background: 'linear-gradient(90deg, var(--color-critical), var(--color-high))',
                transition: 'width 0.4s ease',
              }} />
            </div>
            <span className="font-mono" style={{ fontSize: '12px', minWidth: '36px', textAlign: 'right' }}>{scanProgress.pct}%</span>
            <div style={{ display: 'flex', gap: '6px' }}>
              <Button variant="secondary" style={{ padding: '4px 10px' }} onClick={togglePause}>
                {isPaused ? <Play size={14} /> : <Pause size={14} />}
              </Button>
              <Button variant="secondary" style={{ padding: '4px 10px', borderColor: 'var(--color-critical)', color: 'var(--color-critical)' }} onClick={stopScan}>
                <Square size={14} />
              </Button>
            </div>
          </Card>
        )}

        {/* ── Severity Counters ── */}
        <div style={{ display: 'flex', gap: '14px' }}>
          {[
            { label: 'CRITICAL', key: 'critical', color: 'critical' },
            { label: 'HIGH',     key: 'high',     color: 'high' },
            { label: 'MEDIUM',   key: 'medium',   color: 'medium' },
            { label: 'LOW',      key: 'low',      color: 'low' },
          ].map(sev => (
            <Card key={sev.label} style={{ flex: 1 }}>
              <div className="font-mono text-muted" style={{ fontSize: '10px', letterSpacing: '0.5px' }}>{sev.label}</div>
              <div
                className="font-heading"
                style={{
                  fontSize: '52px',
                  fontWeight: 700,
                  lineHeight: 1,
                  color: counts[sev.key] > 0 ? `var(--color-${sev.color})` : 'var(--text-dimmed)',
                  transition: 'color 0.3s',
                }}
              >
                {counts[sev.key]}
              </div>
              <div className="text-muted" style={{ fontSize: '11px', marginTop: '8px' }}>
                {activeScan ? 'findings this scan' : 'no active scan'}
              </div>
            </Card>
          ))}
        </div>

        {/* ── Live Findings ── */}
        <Card
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>Live Findings</span>
              {activeScan && (
                <Badge severity="critical" style={{ padding: '2px 6px', animation: 'pulse 2s infinite' }}>LIVE</Badge>
              )}
              {liveFindings.length > 0 && (
                <span className="font-mono text-muted" style={{ fontSize: '11px' }}>{liveFindings.length} findings</span>
              )}
            </div>
          }
          style={{ flex: 1 }}
          noPadding
        >
          {liveFindings.length === 0 ? (
            <div style={{ padding: '48px 24px', textAlign: 'center' }}>
              <div style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '4px' }}>
                {activeScan ? 'Scanning in progress — findings will appear here as they are discovered.' : 'No active scan.'}
              </div>
              {!activeScan && (
                <div style={{ color: 'var(--text-dimmed)', fontSize: '12px' }}>Initiate a scan above to see live findings.</div>
              )}
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Target / URL</th>
                  <th>Module</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {liveFindings.map((f, i) => (
                  <tr key={i}>
                    <td><Badge severity={f.severity}>{f.severity.toUpperCase()}</Badge></td>
                    <td>{f.finding}</td>
                    <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{f.url || f.target}</td>
                    <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{f.module}</td>
                    <td className="font-mono text-muted" style={{ fontSize: '12px' }}>{f.time}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        {/* ── ForgeBrain Analysis ── */}
        <Card
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Brain size={16} color="var(--color-info)" />
              <span>ForgeBrain Analysis</span>
            </div>
          }
          noPadding
        >
          {brainVerdicts.length === 0 ? (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
              ForgeBrain verdicts will appear here as findings are confirmed or flagged as false positives.
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Verdict</th>
                  <th>Finding</th>
                  <th>Confidence</th>
                  <th>Reasoning</th>
                </tr>
              </thead>
              <tbody>
                {brainVerdicts.map((v, i) => {
                  const isConfirmed = v.verdict === 'CONFIRMED';
                  const isFP = v.verdict === 'FP_SUSPECTED';
                  const verdictColor = isConfirmed
                    ? 'var(--color-success)'
                    : isFP
                    ? 'var(--color-critical)'
                    : 'var(--color-medium)';
                  const VerdictIcon = isConfirmed ? CheckCircle : isFP ? XCircle : AlertTriangle;
                  return (
                    <tr key={i}>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: verdictColor }}>
                          <VerdictIcon size={14} />
                          <span className="font-mono" style={{ fontSize: '11px', fontWeight: 600 }}>{v.verdict}</span>
                        </div>
                      </td>
                      <td style={{ fontSize: '13px' }}>{v.finding}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{ width: '60px', height: '4px', backgroundColor: 'var(--bg-input)', borderRadius: '2px', overflow: 'hidden' }}>
                            <div style={{ width: `${v.confidence}%`, height: '100%', backgroundColor: verdictColor }} />
                          </div>
                          <span className="font-mono" style={{ fontSize: '12px', color: verdictColor }}>{v.confidence}%</span>
                        </div>
                      </td>
                      <td className="text-muted" style={{ fontSize: '12px' }}>{v.reason}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>

        {/* ── Scan History ── */}
        <Card
          title="Scan History"
          headerRight={
            <Button variant="secondary" style={{ padding: '4px 10px', fontSize: '12px', gap: '6px' }} onClick={fetchHistory}>
              <RefreshCw size={12} />
              REFRESH
            </Button>
          }
          noPadding
        >
          {historyLoading ? (
            <div style={{ padding: '32px 24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
              Loading…
            </div>
          ) : scanHistory.length === 0 ? (
            <div style={{ padding: '48px 24px', textAlign: 'center' }}>
              <div style={{ color: 'var(--text-muted)', fontSize: '13px', marginBottom: '4px' }}>No scan history yet.</div>
              <div style={{ color: 'var(--text-dimmed)', fontSize: '12px' }}>Completed scans will appear here with full findings logs.</div>
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
                  <th>Type</th>
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
                    ? new Date(row.started_at).toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
                    : '—';
                  const status  = row.status || 'unknown';
                  const typeLabel = row.scan_type || (row.frameworks?.[0] || '—');
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
                      <td>
                        <Badge severity="info">{typeLabel.toUpperCase()}</Badge>
                      </td>
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
  );
};

export default AutomatedScans;
