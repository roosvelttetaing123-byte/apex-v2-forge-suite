import React, { useState, useMemo, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import CredentialsCard from '../components/CredentialsCard';

import { apiFetch } from '../config/api';
import { DASHBOARD_API } from '../generated/dashboard-api';
import { applyActionConfirmations, dashboardErrorMessage, prepareActionConfirmations } from '../utils/actionConfirmation';


const MODULES = {
  web: [
    { id: 'sqli',          name: 'SQL Injection',           severity: 'critical', desc: 'Detect SQLi via error-based, blind, and time-based payloads' },
    { id: 'xss',           name: 'Cross-Site Scripting',    severity: 'high',     desc: 'Reflected, stored, and DOM-based XSS via fuzzing' },
    { id: 'lfi',           name: 'LFI / RFI',              severity: 'critical', desc: 'Path traversal for local/remote file inclusion' },
    { id: 'ssrf',          name: 'SSRF',                    severity: 'high',     desc: 'Server-Side Request Forgery via URL-accepting params' },
    { id: 'xxe',           name: 'XXE Injection',           severity: 'high',     desc: 'XML External Entity injection in XML endpoints' },
    { id: 'ssti',          name: 'SSTI',                    severity: 'critical', desc: 'Server-Side Template Injection across major engines' },
    { id: 'rce',           name: 'Remote Code Execution',   severity: 'critical', desc: 'OS command injection and RCE chain detection' },
    { id: 'csrf',          name: 'CSRF Token Bypass',       severity: 'medium',   desc: 'Missing/weak CSRF protections on state-changing requests' },
    { id: 'redirect',      name: 'Open Redirect',           severity: 'medium',   desc: 'Unvalidated redirects exploitable for phishing' },
    { id: 'dirtraversal',  name: 'Directory Traversal',     severity: 'high',     desc: 'Web-root escapes via ../ sequences in path params' },
    { id: 'subdtakeover',  name: 'Subdomain Takeover',      severity: 'high',     desc: 'Dangling DNS records pointing to unclaimed services' },
    { id: 'jwt',           name: 'JWT Manipulation',        severity: 'high',     desc: 'None-alg, weak secrets, and kid injection attacks' },
    { id: 'oauth',         name: 'OAuth Misconfiguration',  severity: 'high',     desc: 'Redirect URI abuse, PKCE bypass, state fixation' },
    { id: 'massassign',    name: 'Mass Assignment',         severity: 'medium',   desc: 'Unprotected object binding exposing privileged fields' },
    { id: 'deserial',      name: 'Insecure Deserialization',severity: 'critical', desc: 'Java/PHP/Python object deserialization gadget chains' },
    { id: 'bof',           name: 'Buffer Overflow',         severity: 'high',     desc: 'Stack/heap overflow detection in native web components' },
  ],
  network: [
    { id: 'portscan',      name: 'Port Scanning',           severity: 'info',     desc: 'TCP/UDP port enumeration with service detection' },
    { id: 'svcfp',         name: 'Service Fingerprinting',  severity: 'info',     desc: 'Banner grabbing and version fingerprinting per port' },
    { id: 'ssltls',        name: 'SSL/TLS Analysis',        severity: 'medium',   desc: 'Weak ciphers, expired certs, BEAST/POODLE/CRIME checks' },
    { id: 'smb',           name: 'SMB Enumeration',         severity: 'high',     desc: 'Shares, sessions, EternalBlue exposure on SMB' },
    { id: 'dns',           name: 'DNS Zone Transfer',       severity: 'medium',   desc: 'AXFR requests against authoritative DNS servers' },
    { id: 'snmp',          name: 'SNMP Enumeration',        severity: 'medium',   desc: 'Community string brute-force and MIB walking' },
    { id: 'netsweep',      name: 'Network Sweep',           severity: 'info',     desc: 'ICMP/ARP host discovery across target CIDR range' },
    { id: 'vulsvc',        name: 'Vulnerable Services',     severity: 'critical', desc: 'CVE matching against discovered service versions' },
  ],
  api: [
    { id: 'apikey',        name: 'API Key Exposure',        severity: 'critical', desc: 'Keys leaked in responses, headers, or JS bundles' },
    { id: 'graphql',       name: 'GraphQL Introspection',   severity: 'medium',   desc: 'Schema exposure and batch query abuse' },
    { id: 'bola',          name: 'Broken Object Level Auth',severity: 'critical', desc: 'IDOR via object ID manipulation across REST endpoints' },
    { id: 'ratelimit',     name: 'Rate Limit Testing',      severity: 'medium',   desc: 'Absence of throttling on auth and sensitive endpoints' },
    { id: 'cors',          name: 'CORS Misconfiguration',   severity: 'medium',   desc: 'Wildcard or origin-reflected CORS policies' },
    { id: 'parampollu',    name: 'Parameter Pollution',     severity: 'medium',   desc: 'HTTP parameter pollution for logic bypass' },
    { id: 'apiversion',    name: 'API Versioning Issues',   severity: 'low',      desc: 'Deprecated versions exposing removed security controls' },
  ],
  auth: [
    { id: 'bruteforce',    name: 'Brute Force',             severity: 'high',     desc: 'Login endpoint brute-force with lockout detection' },
    { id: 'defaultcreds',  name: 'Default Credentials',    severity: 'critical', desc: 'Vendor default username/password pairs across services' },
    { id: 'sessfixation',  name: 'Session Fixation',        severity: 'high',     desc: 'Session token reuse before/after authentication' },
    { id: 'mfabypass',     name: 'MFA Bypass',              severity: 'critical', desc: 'OTP reuse, backup code abuse, response manipulation' },
    { id: 'tokenentropy',  name: 'Token Entropy',           severity: 'medium',   desc: 'Low-entropy session tokens vulnerable to prediction' },
    { id: 'pwspray',       name: 'Password Spraying',       severity: 'high',     desc: 'Low-volume credential spray to evade lockout policies' },
  ],
  cloud: [
    { id: 's3',            name: 'S3 Bucket Exposure',      severity: 'critical', desc: 'Public read/write access on AWS S3 buckets' },
    { id: 'iam',           name: 'IAM Misconfiguration',    severity: 'critical', desc: 'Overprivileged roles, trust policy abuse' },
    { id: 'metadata',      name: 'Metadata Service Abuse',  severity: 'critical', desc: 'IMDS v1 exploitation for credential theft' },
    { id: 'snapshot',      name: 'Public Snapshot',         severity: 'high',     desc: 'Publicly exposed EBS/RDS snapshots' },
    { id: 'serverless',    name: 'Serverless Injection',    severity: 'high',     desc: 'Event injection in Lambda/Cloud Functions' },
    { id: 'container',     name: 'Container Escape',        severity: 'critical', desc: 'Privileged container and socket mount abuse' },
  ],
  activedirectory: [
    { id: 'adcs',          name: 'ADCS Certificate Abuse',  severity: 'critical', desc: 'ESC1-ESC8 certificate template misconfigurations enabling domain takeover' },
    { id: 'kerberoast',    name: 'Kerberoasting / ASREPRoast', severity: 'high',  desc: 'SPNs with crackable tickets and accounts without pre-auth' },
    { id: 'adenum',        name: 'AD Enumeration & Policy', severity: 'high',     desc: 'Delegation abuse, LAPS gaps, password policy, privileged group sprawl' },
  ],
  compliance: [
    { id: 'cisbench',      name: 'CIS Benchmark (Linux)',   severity: 'medium',   desc: 'CIS Level 1/2 hardening checks for Linux servers' },
    { id: 'wincis',        name: 'CIS Benchmark (Windows)', severity: 'medium',   desc: 'CIS Level 1/2 hardening checks for Windows servers' },
    { id: 'pcidss',        name: 'PCI DSS v4.0 Audit',      severity: 'high',     desc: 'PCI DSS v4.0 technical control validation' },
    { id: 'iis',           name: 'IIS Deep Audit',          severity: 'high',     desc: 'IIS configuration, virtual directory, handler, and auth weaknesses' },
    { id: 'exchange',      name: 'Exchange Server Audit',   severity: 'critical', desc: 'ProxyLogon, ProxyShell, ProxyNotShell, OWA exposure' },
    { id: 'mssqldeep',     name: 'MSSQL Deep Audit',        severity: 'critical', desc: 'xp_cmdshell, SA account, CLR assembly, linked server abuse' },
    { id: 'macos',         name: 'macOS Patch & Security',  severity: 'medium',   desc: 'SIP, Gatekeeper, FileVault, kext signing, patch status' },
    { id: 'macosusers',    name: 'macOS User Audit',        severity: 'medium',   desc: 'Admin accounts, NOPASSWD sudo, setuid binaries' },
  ],
};

const DEFAULT_SELECTED = new Set([
  'sqli','xss','lfi','ssrf','xxe','ssti','rce','csrf','redirect',
  'dirtraversal','subdtakeover','jwt','oauth',
  'portscan','svcfp','ssltls',
  'bola','cors',
  'defaultcreds','mfabypass',
  'metadata',
  'adcs','kerberoast','adenum',
]);

// Keep the UI's early mixed-plan check aligned with the implemented NetForge
// entries in the server's UI_MODULE_MAP. The server remains authoritative.
const NETWORK_ACTION_IDS = new Set([
  ...MODULES.network.map(module => module.id),
  'pwspray', 'metadata', 'container',
  ...MODULES.activedirectory.map(module => module.id),
  ...MODULES.compliance.map(module => module.id),
]);

const INTENSITY_LEVELS = ['Passive', 'Low', 'Moderate', 'Aggressive', 'Maximum'];

const PROFILES = [
  'Standard (OWASP Top 10)',
  'Stealth Recon',
  'Full Spectrum',
  'API Security Audit',
  'Auth & Access Control',
  'Cloud Security Posture',
];

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const severityColor = {
  critical: 'var(--color-critical)',
  high:     'var(--color-high)',
  medium:   'var(--color-medium)',
  low:      'var(--color-low)',
  info:     'var(--color-info)',
};

export default function ScanBuilder({ authToken: _authToken = '' }) {
  const [activeTab, setActiveTab]       = useState('web');
  const [selected, setSelected]         = useState(new Set(DEFAULT_SELECTED));
  const [intensity, setIntensity]       = useState(2);
  const [followRedirects, setFollowRedirects] = useState(true);
  const [schedule, setSchedule]         = useState('now');
  const [search, setSearch]             = useState('');
  const [profile, setProfile]           = useState(PROFILES[0]);
  const [maxThreads, setMaxThreads]     = useState(20);
  const [timeout, setTimeout_]          = useState(30);
  const [rateLimit, setRateLimit]       = useState(1000);
  const [maxDepth, setMaxDepth]         = useState(5);
  const [targetScope, setTargetScope]   = useState('');
  const [networkTarget, setNetworkTarget] = useState('');
  const [sourceRoot, setSourceRoot] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  // Scan mode + credential state
  const [scanMode, setScanMode]           = useState('blackbox');
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

  const allModules = useMemo(() => Object.values(MODULES).flat(), []);
  const totalSelected = useMemo(() => [...allModules].filter(m => selected.has(m.id)).length, [allModules, selected]);
  const mixedEngineSelection = useMemo(() => {
    const ids = [...selected];
    return ids.some(id => NETWORK_ACTION_IDS.has(id))
      && ids.some(id => !NETWORK_ACTION_IDS.has(id));
  }, [selected]);

  const tabModules = useMemo(() => {
    let mods = MODULES[activeTab] || [];
    if (search.trim()) {
      const q = search.toLowerCase();
      mods = Object.values(MODULES).flat().filter(m =>
        m.name.toLowerCase().includes(q) || m.desc.toLowerCase().includes(q)
      );
    } else if (severityFilter !== 'all') {
      mods = mods.filter(m => m.severity === severityFilter);
    }
    return [...mods].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  }, [activeTab, search, severityFilter]);

  const toggle = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const tabAllSelected = tabModules.length > 0 && tabModules.every(m => selected.has(m.id));

  const toggleTabAll = () => {
    setSelected(prev => {
      const next = new Set(prev);
      if (tabAllSelected) tabModules.forEach(m => next.delete(m.id));
      else                 tabModules.forEach(m => next.add(m.id));
      return next;
    });
  };

  const selectBySeverity = (sev) => {
    setSelected(prev => {
      const next = new Set(prev);
      allModules.filter(m => m.severity === sev).forEach(m => next.add(m.id));
      return next;
    });
  };

  const TABS = ['web','network','api','auth','cloud','activedirectory','compliance'];

  const TAB_LABELS = {
    web: 'Web', network: 'Network', api: 'API', auth: 'Auth',
    cloud: 'Cloud', activedirectory: 'Active Directory', compliance: 'Compliance',
  };

  const tabCount = (tab) => MODULES[tab].filter(m => selected.has(m.id)).length;

  // ── DA-1: Backend wiring ──
  const navigate = useNavigate();
  const [launching, setLaunching]     = useState(false);
  const [saving, setSaving]           = useState(false);
  const [toast, setToast]             = useState(null);   // { type: 'success'|'error', msg }
  const [launchError, setLaunchError] = useState('');
  const [savedTemplates, setSavedTemplates] = useState([]);
  const [showSaveModal, setShowSaveModal]   = useState(false);
  const [templateName, setTemplateName]     = useState('');

  // Load saved templates on mount
  useEffect(() => {
    apiFetch(DASHBOARD_API.scanTemplates.path)
      .then(r => r.ok ? r.json() : { templates: [] })
      .then(d => setSavedTemplates(d.templates || []))
      .catch(() => {});
  }, []);

  // Auto-dismiss toast
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  const testCredentials = useCallback(async () => {
    setTestingCreds(true);
    setTestResult(null);
    try {
      const res = await apiFetch(DASHBOARD_API.authTest.path, {
        method: DASHBOARD_API.authTest.method,
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

  const launchScan = useCallback(async () => {
    if (launching || !targetScope.trim()) return;
    const requestedTarget = targetScope.trim();
    const requestedNetworkTarget = networkTarget.trim();
    if (selected.size === 0) {
      setLaunchError('Select at least one implemented module before launch.');
      return;
    }
    if (scanMode === 'whitebox' && !sourceRoot.trim()) {
      setLaunchError('Whitebox scans require an absolute canonical source root.');
      return;
    }
    if (mixedEngineSelection && !requestedNetworkTarget) {
      setLaunchError('Mixed WebForge/NetForge plans require a separately approved exact network IP.');
      return;
    }
    if (!window.confirm(`Confirm launching ${selected.size} selected modules against exact target ${requestedTarget}?`)) return;
    setLaunching(true);
    setLaunchError('');
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
      const payload = {
        target: requestedTarget,
        profile,
        modules: [...selected],
        intensity,
        maxThreads,
        timeout,
        rateLimit,
        maxDepth,
        followRedirects,
        schedule,
        mode: scanMode,
        auth_profile,
        ...(scanMode === 'whitebox' ? { source_root: sourceRoot.trim() } : {}),
      };
      const confirmationBundle = await prepareActionConfirmations({
        intent: 'scan.launch',
        target: requestedTarget,
        scope: [requestedTarget],
        exclude: [],
        modules: [...selected],
        mode: scanMode,
        ...(scanMode === 'whitebox' ? { source_root: sourceRoot.trim() } : {}),
        ...(requestedNetworkTarget ? {
          network_target: requestedNetworkTarget,
          network_scope: [requestedNetworkTarget],
        } : {}),
      });
      if (
        confirmationBundle.network_target
        && !window.confirm(
          `Separately approve NetForge web-to-network escalation to exact IP ${confirmationBundle.network_target}?`
        )
      ) return;
      const res = await apiFetch(DASHBOARD_API.launchScan.path, {
        method: DASHBOARD_API.launchScan.method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(applyActionConfirmations(payload, confirmationBundle)),
      });
      if (res.ok) {
        const data = await res.json();
        // Clear secrets on success only — preserve on failure so user can retry
        setPassword('');
        setToken('');
        setCookieJar('');
        setTestResult(null);
        setToast({ type: 'success', msg: `Scan queued — ${data.scan_id} (${data.scan_type} / ${data.modules_count} modules)` });
        setTimeout(() => navigate('/'), 1500);
      } else {
        const err = await res.json().catch(() => ({}));
        const message = dashboardErrorMessage(err, `Error ${res.status}`);
        setLaunchError(message);
        setToast({ type: 'error', msg: message });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Cannot reach backend — is forge.py dashboard running?';
      setLaunchError(message);
      setToast({ type: 'error', msg: message });
    } finally {
      setLaunching(false);
    }
  }, [targetScope, networkTarget, profile, selected, mixedEngineSelection, sourceRoot, intensity, maxThreads, timeout, rateLimit, maxDepth, followRedirects, schedule, scanMode, authType, username, password, token, headerName, cookieJar, loginUrl, launching, navigate]);

  const saveTemplate = useCallback(async () => {
    if (saving || !templateName.trim()) return;
    setSaving(true);
    try {
      // Strip secrets — never persist password, token, or cookie_jar to disk
      const auth_profile = scanMode === 'blackbox' ? null : {
        auth_type: authType,
        username,
        login_url: loginUrl,
        header_name: headerName,
      };
      const payload = {
        name: templateName.trim(),
        target: targetScope,
        profile,
        modules: [...selected],
        intensity,
        maxThreads,
        timeout,
        rateLimit,
        maxDepth,
        followRedirects,
        schedule,
        mode: scanMode,
        auth_profile,
      };
      const res = await apiFetch(DASHBOARD_API.saveScanTemplate.path, {
        method: DASHBOARD_API.saveScanTemplate.method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data = await res.json();
        setSavedTemplates(prev => [data.template, ...prev]);
        setToast({ type: 'success', msg: `Template "${templateName}" saved` });
        setShowSaveModal(false);
        setTemplateName('');
      } else {
        setToast({ type: 'error', msg: 'Failed to save template' });
      }
    } catch {
      setToast({ type: 'error', msg: 'Cannot reach backend' });
    } finally {
      setSaving(false);
    }
  }, [templateName, targetScope, profile, selected, intensity, maxThreads, timeout, rateLimit, maxDepth, followRedirects, schedule, saving, scanMode, authType, username, loginUrl, headerName]);

  const loadTemplate = useCallback((tpl) => {
    // backend may return flat { name, target, ... } or nested { name, config: { target, ... } }
    const c = tpl.config || tpl || {};
    if (c.target)              setTargetScope(c.target);
    if (c.profile)             setProfile(c.profile);
    if (c.modules?.length)     setSelected(new Set(c.modules));
    if (c.intensity != null)   setIntensity(c.intensity);
    if (c.maxThreads != null)  setMaxThreads(c.maxThreads);
    if (c.timeout != null)     setTimeout_(c.timeout);
    if (c.rateLimit != null)   setRateLimit(c.rateLimit);
    if (c.maxDepth != null)    setMaxDepth(c.maxDepth);
    if (c.followRedirects != null) setFollowRedirects(c.followRedirects);
    if (c.schedule)            setSchedule(c.schedule);
    // Restore mode + non-secret auth fields only — never restore password/token/cookieJar
    if (c.mode)                          setScanMode(c.mode);
    if (c.auth_profile?.auth_type)       setAuthType(c.auth_profile.auth_type);
    if (c.auth_profile?.username)        setUsername(c.auth_profile.username);
    if (c.auth_profile?.login_url)       setLoginUrl(c.auth_profile.login_url);
    if (c.auth_profile?.header_name)     setHeaderName(c.auth_profile.header_name);
    setToast({ type: 'success', msg: `Loaded "${tpl.name}" — re-enter credentials if needed` });
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* ── Toast Notification ── */}
      {toast && (
        <div style={{
          position: 'fixed', top: '16px', right: '16px', zIndex: 9999,
          padding: '12px 20px', borderRadius: '6px',
          background: toast.type === 'success' ? 'rgba(0,200,83,0.15)' : 'rgba(255,68,68,0.15)',
          border: `1px solid ${toast.type === 'success' ? 'rgba(0,200,83,0.4)' : 'rgba(255,68,68,0.4)'}`,
          color: toast.type === 'success' ? 'var(--color-success)' : 'var(--color-critical)',
          fontFamily: 'var(--font-mono)', fontSize: '12px',
          backdropFilter: 'blur(12px)',
          boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
          animation: 'slideIn 0.3s ease',
          display: 'flex', alignItems: 'center', gap: '8px',
          maxWidth: '420px',
        }}>
          <span style={{ fontSize: '16px' }}>{toast.type === 'success' ? '✓' : '✕'}</span>
          {toast.msg}
        </div>
      )}

      {/* ── Save Template Modal ── */}
      {showSaveModal && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9998,
          background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }} onClick={() => setShowSaveModal(false)}>
          <div style={{
            background: 'var(--bg-card)', border: '1px solid var(--border-color)',
            borderRadius: '8px', padding: '24px', width: '380px',
            boxShadow: '0 24px 64px rgba(0,0,0,0.5)',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ fontFamily: 'var(--font-heading)', fontSize: '16px', fontWeight: 700, marginBottom: '16px', color: 'var(--text-primary)' }}>
              Save Scan Template
            </div>
            <input
              type="text"
              placeholder="Template name..."
              value={templateName}
              onChange={e => setTemplateName(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && saveTemplate()}
              autoFocus
              style={{ width: '100%', marginBottom: '12px', boxSizing: 'border-box' }}
            />
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '16px' }}>
              {totalSelected} modules · {INTENSITY_LEVELS[intensity]} intensity · {targetScope || 'no target'}
            </div>
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <Button variant="secondary" onClick={() => setShowSaveModal(false)}>Cancel</Button>
              <Button variant="primary" onClick={saveTemplate} disabled={saving || !templateName.trim()}>
                {saving ? 'Saving…' : 'Save'}
              </Button>
            </div>
          </div>
        </div>
      )}
      <TopBar
        title="New Scan Configuration"
        subtitle="Configure target, modules, and scan intensity"
        actions={
          <>
            <Button variant="secondary" onClick={() => setShowSaveModal(true)}>Save Template</Button>
            <Button
              variant="primary"
              onClick={launchScan}
              disabled={
                launching
                || !targetScope.trim()
                || totalSelected === 0
                || (mixedEngineSelection && !networkTarget.trim())
                || (scanMode === 'whitebox' && !sourceRoot.trim())
              }
            >
              {launching ? (
                <>
                  <svg viewBox="0 0 24 24" style={{ width: 14, height: 14, animation: 'spin 1s linear infinite' }}>
                    <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="32" strokeLinecap="round" />
                  </svg>
                  Launching…
                </>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 14, height: 14 }}>
                    <polygon points="5 3 19 12 5 21 5 3" fill="currentColor" stroke="none"/>
                  </svg>
                  Launch Scan
                </>
              )}
            </Button>
          </>
        }
      />

      {/* Error banner */}
      {launchError && (
        <div style={{
          margin: '0 28px', padding: '10px 16px', borderRadius: '4px',
          background: 'rgba(255,68,68,0.08)', border: '1px solid rgba(255,68,68,0.2)',
          color: 'var(--color-critical)', fontFamily: 'var(--font-mono)', fontSize: '12px',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span>⚠ {launchError}</span>
          <button onClick={() => setLaunchError('')} style={{
            background: 'none', border: 'none', color: 'var(--color-critical)',
            cursor: 'pointer', fontSize: '16px', padding: '0 4px',
          }}>×</button>
        </div>
      )}

      <div style={{ padding: '18px 28px', display: 'flex', gap: '14px', flex: 1, minHeight: 0 }}>

        {/* ── LEFT PANEL ── */}
        <div style={{ width: '320px', flexShrink: 0, display: 'flex', flexDirection: 'column', gap: '12px', overflowY: 'auto' }}>

          {/* Target */}
          <Card title="Target">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <Field label="Scope / CIDR">
                <input
                  type="text"
                  value={targetScope}
                  onChange={e => setTargetScope(e.target.value)}
                  placeholder="192.168.0.0/16 or https://..."
                  style={{ width: '100%' }}
                />
              </Field>
              <Field label="Network Escalation IP (when mixed)">
                <input
                  type="text"
                  value={networkTarget}
                  onChange={e => setNetworkTarget(e.target.value)}
                  placeholder="Exact separately approved IP"
                  style={{ width: '100%' }}
                />
              </Field>
              {scanMode === 'whitebox' && (
                <Field label="Canonical Whitebox Source Root">
                  <input
                    type="text"
                    value={sourceRoot}
                    onChange={e => setSourceRoot(e.target.value)}
                    placeholder="/absolute/path/to/source"
                  />
                </Field>
              )}
              <Field label="Scan Profile">
                <select value={profile} onChange={e => setProfile(e.target.value)} style={{ width: '100%' }}>
                  {PROFILES.map(p => <option key={p}>{p}</option>)}
                </select>
              </Field>
              <Field label="Scan Mode">
                <select value={scanMode} onChange={e => setScanMode(e.target.value)} style={{ width: '100%' }}>
                  <option value="blackbox">Blackbox</option>
                  <option value="greybox">Greybox (Authenticated)</option>
                  <option value="whitebox">Whitebox (Source + Creds)</option>
                </select>
              </Field>
            </div>
          </Card>

          {/* Parameters */}
          <Card title="Parameters">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <NumField label="Max Threads"  value={maxThreads}  onChange={setMaxThreads}  min={1}  max={500} />
              <NumField label="Timeout (s)"  value={timeout}     onChange={setTimeout_}    min={5}  max={300} />
              <NumField label="Rate (req/s)" value={rateLimit}   onChange={setRateLimit}   min={1}  max={10000} />
              <NumField label="Max Depth"    value={maxDepth}    onChange={setMaxDepth}    min={1}  max={20} />
            </div>
          </Card>

          {/* Credentials (greybox / whitebox only) */}
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

          {/* Intensity */}
          <Card title="Intensity">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: intensityColor(intensity) }}>
                  {INTENSITY_LEVELS[intensity]}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {intensity + 1} / 5
                </span>
              </div>
              <div style={{ position: 'relative', paddingBottom: '4px' }}>
                <div style={{
                  height: '6px',
                  background: 'linear-gradient(90deg, var(--color-success), var(--color-medium), var(--color-critical))',
                  borderRadius: '3px',
                  position: 'relative',
                }}>
                  <div style={{
                    position: 'absolute',
                    left: `${intensity * 25}%`,
                    top: '50%',
                    transform: 'translate(-50%, -50%)',
                    width: '14px', height: '14px',
                    backgroundColor: '#fff',
                    borderRadius: '50%',
                    border: `2px solid ${intensityColor(intensity)}`,
                    transition: 'left 0.15s ease',
                    pointerEvents: 'none',
                  }} />
                </div>
                <input
                  type="range" min={0} max={4} value={intensity}
                  onChange={e => setIntensity(Number(e.target.value))}
                  style={{
                    position: 'absolute', top: 0, left: 0, width: '100%', height: '6px',
                    opacity: 0, cursor: 'pointer', margin: 0,
                  }}
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                {INTENSITY_LEVELS.map((l, i) => (
                  <span key={l} style={{ fontSize: '9px', fontFamily: 'var(--font-mono)', color: i === intensity ? intensityColor(i) : 'var(--text-dimmed)', textTransform: 'uppercase' }}>
                    {l.slice(0, 3)}
                  </span>
                ))}
              </div>
            </div>
          </Card>

          {/* Schedule */}
          <Card title="Schedule">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: '6px' }}>
                {[['now','Run Now'],['once','Schedule'],['recurring','Recurring']].map(([val, label]) => (
                  <button
                    key={val}
                    onClick={() => setSchedule(val)}
                    style={{
                      padding: '7px 4px',
                      borderRadius: '4px',
                      border: `1px solid ${schedule === val ? 'var(--color-brand-red)' : 'var(--border-color)'}`,
                      backgroundColor: schedule === val ? 'rgba(229,57,53,0.12)' : 'transparent',
                      color: schedule === val ? 'var(--color-brand-red)' : 'var(--text-secondary)',
                      fontFamily: 'var(--font-heading)',
                      fontSize: '11px',
                      letterSpacing: '0.8px',
                      textTransform: 'uppercase',
                      cursor: 'pointer',
                      transition: 'all 0.15s',
                    }}
                  >{label}</button>
                ))}
              </div>

              {/* Follow Redirects */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '4px', borderTop: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Follow Redirects</span>
                <Toggle value={followRedirects} onChange={setFollowRedirects} />
              </div>
            </div>
          </Card>

          {/* Scan Summary */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-color)',
            borderRadius: '4px',
            padding: '12px 14px',
            display: 'flex',
            flexDirection: 'column',
            gap: '8px',
          }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>Scan Summary</span>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
              <SummaryItem label="Modules" value={`${totalSelected} / ${allModules.length}`} accent="var(--color-brand-red)" />
              <SummaryItem label="Intensity" value={INTENSITY_LEVELS[intensity]} accent={intensityColor(intensity)} />
              <SummaryItem label="Target" value={targetScope || '—'} />
              <SummaryItem label="Schedule" value={schedule === 'now' ? 'Immediate' : schedule === 'once' ? 'Scheduled' : 'Recurring'} />
            </div>
          </div>
        </div>

        {/* ── RIGHT PANEL ── */}
        <Card title="Module Selection" style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }} noPadding
          headerRight={
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                {totalSelected} / {allModules.length} selected
              </span>
            </div>
          }
        >
          {/* Tabs row */}
          <div style={{ padding: '0 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '0', alignItems: 'flex-end' }}>
            {TABS.map(tab => {
              const cnt = tabCount(tab);
              const total = MODULES[tab].length;
              const active = activeTab === tab && !search;
              return (
                <button
                  key={tab}
                  onClick={() => { setActiveTab(tab); setSearch(''); setSeverityFilter('all'); }}
                  style={{
                    padding: '10px 14px',
                    background: 'transparent',
                    border: 'none',
                    borderBottom: `2px solid ${active ? 'var(--color-brand-red)' : 'transparent'}`,
                    color: active ? 'var(--text-primary)' : 'var(--text-muted)',
                    fontFamily: 'var(--font-heading)',
                    fontSize: '12px',
                    letterSpacing: '1px',
                    textTransform: 'uppercase',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    transition: 'color 0.15s',
                    marginBottom: '-1px',
                  }}
                >
                  {TAB_LABELS[tab] || tab}
                  <span style={{
                    background: cnt === total ? 'rgba(229,57,53,0.2)' : 'var(--bg-input)',
                    color: cnt === total ? 'var(--color-brand-red)' : 'var(--text-muted)',
                    borderRadius: '10px',
                    padding: '1px 6px',
                    fontSize: '10px',
                    fontFamily: 'var(--font-mono)',
                    fontWeight: 600,
                  }}>{cnt}/{total}</span>
                </button>
              );
            })}
            {/* spacer + search */}
            <div style={{ flex: 1 }} />
            <div style={{ padding: '6px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ position: 'relative' }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                  style={{ width: 13, height: 13, position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }}>
                  <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
                <input
                  type="text"
                  placeholder="Search modules..."
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  style={{ paddingLeft: '28px', width: '160px', fontSize: '12px', height: '28px', padding: '4px 8px 4px 28px' }}
                />
              </div>
            </div>
          </div>

          {/* Severity quick-filter pills */}
          {!search && (
            <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', gap: '6px', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-dimmed)', fontFamily: 'var(--font-mono)', marginRight: '4px' }}>FILTER:</span>
              {['all','critical','high','medium','low','info'].map(sev => {
                const active = severityFilter === sev && !search;
                return (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    style={{
                      padding: '2px 9px',
                      borderRadius: '10px',
                      border: `1px solid ${active ? (sev === 'all' ? 'var(--border-secondary)' : severityColor[sev]) : 'var(--border-color)'}`,
                      background: active ? (sev === 'all' ? 'var(--bg-input)' : `${severityColor[sev]}22`) : 'transparent',
                      color: active ? (sev === 'all' ? 'var(--text-primary)' : severityColor[sev]) : 'var(--text-muted)',
                      fontSize: '10px',
                      fontFamily: 'var(--font-mono)',
                      textTransform: 'uppercase',
                      cursor: 'pointer',
                      letterSpacing: '0.5px',
                      transition: 'all 0.15s',
                    }}
                  >{sev}</button>
                );
              })}
              <div style={{ flex: 1 }} />
              <button
                onClick={() => selectBySeverity('critical')}
                style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', background: 'transparent', border: 'none', color: 'var(--color-critical)', cursor: 'pointer', letterSpacing: '0.3px' }}
              >+ all critical</button>
            </div>
          )}

          {/* Module list */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
            {tabModules.length === 0 ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '120px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '13px' }}>
                No modules match "{search}"
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {tabModules.map(mod => {
                  const checked = selected.has(mod.id);
                  return (
                    <label
                      key={mod.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                        padding: '9px 12px',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        background: checked ? 'rgba(229,57,53,0.05)' : 'transparent',
                        border: `1px solid ${checked ? 'rgba(229,57,53,0.15)' : 'transparent'}`,
                        transition: 'all 0.1s',
                      }}
                    >
                      {/* Checkbox */}
                      <div
                        onClick={() => toggle(mod.id)}
                        style={{
                          width: '16px', height: '16px', flexShrink: 0,
                          border: checked ? 'none' : '1px solid var(--border-secondary)',
                          backgroundColor: checked ? 'var(--color-brand-red)' : 'var(--bg-input)',
                          borderRadius: '3px',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          transition: 'all 0.15s',
                        }}
                      >
                        {checked && (
                          <svg viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" style={{ width: '10px', height: '10px' }}>
                            <polyline points="20 6 9 17 4 12"/>
                          </svg>
                        )}
                      </div>

                      {/* Severity dot */}
                      <div style={{
                        width: '6px', height: '6px', borderRadius: '50%', flexShrink: 0,
                        backgroundColor: severityColor[mod.severity],
                        boxShadow: checked ? `0 0 6px ${severityColor[mod.severity]}88` : 'none',
                      }} />

                      {/* Name + desc */}
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{
                            fontSize: '13px',
                            color: checked ? 'var(--text-primary)' : 'var(--text-secondary)',
                            fontWeight: checked ? 500 : 400,
                            transition: 'color 0.15s',
                          }}>{mod.name}</span>
                          <span style={{
                            fontSize: '9px',
                            fontFamily: 'var(--font-mono)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                            color: severityColor[mod.severity],
                            opacity: 0.8,
                          }}>{mod.severity}</span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '1px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {mod.desc}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            )}
          </div>

          {/* Footer */}
          <div style={{ padding: '10px 16px', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                {search ? `${tabModules.length} result${tabModules.length !== 1 ? 's' : ''}` : `${tabCount(activeTab)} / ${MODULES[activeTab].length} in tab`}
              </span>
              <div style={{ width: '1px', height: '14px', background: 'var(--border-color)' }} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--color-brand-red)' }}>
                {totalSelected} total selected
              </span>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <Button
                variant="secondary"
                style={{ padding: '4px 12px', fontSize: '11px' }}
                onClick={toggleTabAll}
              >{tabAllSelected && !search ? 'Deselect Tab' : 'Select Tab'}</Button>
              <Button
                variant="secondary"
                style={{ padding: '4px 12px', fontSize: '11px' }}
                onClick={() => setSelected(new Set())}
              >Clear All</Button>
              <Button
                variant="secondary"
                style={{ padding: '4px 12px', fontSize: '11px' }}
                onClick={() => setSelected(new Set(allModules.map(m => m.id)))}
              >Select All</Button>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

/* ── Small helpers ── */

function Field({ label, children }) {
  return (
    <div>
      <label style={{ display: 'block', marginBottom: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        {label}
      </label>
      {children}
    </div>
  );
}

function NumField({ label, value, onChange, min, max }) {
  return (
    <Field label={label}>
      <input
        type="number" min={min} max={max}
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        style={{ width: '100%' }}
      />
    </Field>
  );
}

function Toggle({ value, onChange }) {
  return (
    <div
      onClick={() => onChange(!value)}
      style={{
        width: '36px', height: '20px',
        backgroundColor: value ? 'var(--color-brand-red)' : 'var(--bg-input)',
        borderRadius: '10px',
        position: 'relative',
        cursor: 'pointer',
        border: `1px solid ${value ? 'var(--color-brand-red)' : 'var(--border-secondary)'}`,
        transition: 'all 0.2s',
        flexShrink: 0,
      }}
    >
      <div style={{
        width: '14px', height: '14px',
        backgroundColor: '#fff',
        borderRadius: '50%',
        position: 'absolute',
        top: '2px',
        left: value ? '18px' : '2px',
        transition: 'left 0.2s',
        boxShadow: '0 1px 3px rgba(0,0,0,0.4)',
      }} />
    </div>
  );
}

function SummaryItem({ label, value, accent = undefined }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
      <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dimmed)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</span>
      <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: accent || 'var(--text-secondary)', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{value}</span>
    </div>
  );
}

function intensityColor(i) {
  return ['var(--color-success)','var(--color-low)','var(--color-medium)','var(--color-high)','var(--color-critical)'][i];
}
