import React, { useEffect, useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Button from './components/Button';
import Card from './components/Card';
import { API_BASE, NO_AUTH_TOKEN, getAuthToken, setAuthToken } from './config/api';

// Pages
import AutomatedScans from './pages/AutomatedScans';
import ScanBuilder from './pages/ScanBuilder';
import RedTeaming from './pages/RedTeaming';
import C2Console from './pages/C2Console';
import MobilePentest from './pages/MobilePentest';
import Discovery from './pages/Discovery';
import Targets from './pages/Targets';
import ScansLibrary from './pages/ScansLibrary';
import Scheduling from './pages/Scheduling';
import Reports from './pages/Reports';
import Vulnerabilities from './pages/Vulnerabilities';
import Policies from './pages/Policies';
import Notifications from './pages/Notifications';
import Integrations from './pages/Integrations';
import TeamManagement from './pages/TeamManagement';
import ActivityLogs from './pages/ActivityLogs';
import Agents from './pages/Agents';
import ScanDetail from './pages/ScanDetail';
import CredentialAnalysis from './pages/CredentialAnalysis';

function App() {
  const [token, setToken] = useState(getAuthToken());
  const [checkingAuthMode, setCheckingAuthMode] = useState(!getAuthToken());

  // Handle SSO exchange code in URL on mount
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ssoCode = params.get('sso_code');
    if (ssoCode) {
      // Clean URL immediately
      window.history.replaceState({}, '', window.location.pathname);
      fetch(`${API_BASE}/api/v1/auth/sso/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: ssoCode }),
      })
        .then(r => r.ok ? r.json() : Promise.reject('SSO exchange failed'))
        .then(data => {
          if (data.token) {
            setAuthToken(data.token);
            setToken(data.token);
          }
        })
        .catch(() => {});
      return;
    }
    const ssoError = params.get('sso_error');
    if (ssoError) {
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

  useEffect(() => {
    if (token) {
      setCheckingAuthMode(false);
      return;
    }
    let cancelled = false;
    fetch(`${API_BASE}/api/v1/health`)
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (cancelled) return;
        if (data && data.auth_enabled === false) {
          setAuthToken(NO_AUTH_TOKEN);
          setToken(NO_AUTH_TOKEN);
        }
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setCheckingAuthMode(false);
      });
    return () => { cancelled = true; };
  }, [token]);

  if (checkingAuthMode) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-app)',
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
      }}>
        CONNECTING TO DASHBOARD...
      </div>
    );
  }

  if (!token) {
    return <LoginScreen onLogin={setToken} />;
  }

  return (
    <div className="app-container">
      <Sidebar />
      <main className="main-content">
        <Routes>
          <Route path="/" element={<AutomatedScans authToken={token} />} />
          <Route path="/scan-builder" element={<ScanBuilder authToken={token} />} />
          <Route path="/red-teaming" element={<RedTeaming />} />
          <Route path="/c2-console" element={<C2Console />} />
          <Route path="/mobile" element={<MobilePentest />} />
          <Route path="/discovery" element={<Discovery />} />
          <Route path="/targets" element={<Targets />} />
          <Route path="/scans" element={<ScansLibrary authToken={token} />} />
          <Route path="/scans/:scanId" element={<ScanDetail />} />
          <Route path="/scheduling" element={<Scheduling />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities authToken={token} />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/integrations" element={<Integrations />} />
          <Route path="/team" element={<TeamManagement />} />
          <Route path="/activity" element={<ActivityLogs />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/credential-analysis" element={<CredentialAnalysis authToken={token} />} />
        </Routes>
      </main>
    </div>
  );
}

function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState('operator');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [ssoConfig, setSsoConfig] = useState(null);
  const [ssoLoading, setSsoLoading] = useState(false);

  // Check if SSO is available
  useEffect(() => {
    fetch(`${API_BASE}/api/v1/auth/sso/config`)
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.enabled) setSsoConfig(data); })
      .catch(() => {});
  }, []);

  // Check URL for SSO error
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ssoError = params.get('sso_error');
    if (ssoError) {
      setError(`SSO error: ${ssoError}`);
      window.history.replaceState({}, '', window.location.pathname);
    }
  }, []);

  const login = async () => {
    if (!username.trim() || !password) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.token) {
        setError(data.detail || 'Login failed');
        return;
      }
      setAuthToken(data.token);
      onLogin(data.token);
    } catch {
      setError('Cannot reach dashboard backend');
    } finally {
      setLoading(false);
    }
  };

  const startSSO = () => {
    setSsoLoading(true);
    window.location.href = `${API_BASE}/api/v1/auth/sso/start?next=${encodeURIComponent(window.location.pathname)}`;
  };

  const continueWithoutAuth = () => {
    setAuthToken(NO_AUTH_TOKEN);
    onLogin(NO_AUTH_TOKEN);
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-app)',
      padding: '24px',
    }}>
      <Card title="Dashboard Login" style={{ width: '360px' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* SSO button — shown when configured */}
          {ssoConfig && (
            <>
              <Button variant="primary" onClick={startSSO} disabled={ssoLoading} fullWidth>
                {ssoLoading ? 'REDIRECTING…' : `SIGN IN WITH ${ssoConfig.provider_name || 'SSO'}`}
              </Button>
              <div style={{
                display: 'flex', alignItems: 'center', gap: '12px',
                color: 'var(--text-very-dim)', fontSize: '11px', fontFamily: 'var(--font-mono)',
              }}>
                <div style={{ flex: 1, height: '1px', background: 'var(--border-color)' }} />
                OR
                <div style={{ flex: 1, height: '1px', background: 'var(--border-color)' }} />
              </div>
            </>
          )}

          <label className="font-mono text-muted" style={{ fontSize: '11px', textTransform: 'uppercase' }}>Username</label>
          <input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" />
          <label className="font-mono text-muted" style={{ fontSize: '11px', textTransform: 'uppercase' }}>Password</label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && login()}
            autoComplete="current-password"
            autoFocus
          />
          {error && <div className="font-mono" style={{ color: 'var(--color-critical)', fontSize: '12px' }}>{error}</div>}
          <Button variant="primary" onClick={login} disabled={loading || !username.trim() || !password} fullWidth>
            {loading ? 'CONNECTING...' : 'CONNECT'}
          </Button>
          <Button variant="secondary" onClick={continueWithoutAuth} fullWidth>
            NO-AUTH DASHBOARD
          </Button>
          <div className="text-muted" style={{ fontSize: '12px' }}>
            Use the Forge dashboard account. Default user is operator unless configured otherwise.
          </div>
        </div>
      </Card>
    </div>
  );
}

export default App;
