import React, { useState, useEffect, useCallback } from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import { Shield, Wifi, Layers, RefreshCw, ChevronDown, ChevronRight, Crosshair, Globe } from 'lucide-react';
import { apiFetch } from '../config/api';

const C2Console = () => {
  /* ── State ────────────────────────────────────────────────── */
  const [bofs, setBofs] = useState([]);
  const [bofCapability, setBofCapability] = useState({ status: 'loading', enabled: false, reason_code: '' });
  const [profiles, setProfiles] = useState([]);
  const [profileDetail, setProfileDetail] = useState(null);
  const [activeTab, setActiveTab] = useState('beacons'); // beacons | bofs | profiles
  const [expandedProfile, setExpandedProfile] = useState(null);

  /* ── API calls ────────────────────────────────────────────── */
  const fetchBofs = useCallback(async () => {
    try {
      const res = await apiFetch('/api/v1/c2/bofs');
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setBofs(data.enabled ? (data.bofs || []) : []);
        setBofCapability({
          status: data.status || (data.enabled ? 'available' : 'disabled'),
          enabled: data.enabled === true,
          reason_code: data.reason_code || '',
        });
      } else {
        setBofs([]);
        setBofCapability({
          status: res.status === 401 ? 'unauthorized' : (res.status === 403 ? 'forbidden' : 'unavailable'),
          enabled: false,
          reason_code: data?.detail?.reason_code || data.reason_code || `http_${res.status}`,
        });
      }
    } catch (e) {
      setBofs([]);
      setBofCapability({ status: 'unavailable', enabled: false, reason_code: 'dashboard_unreachable' });
    }
  }, []);

  const fetchProfiles = useCallback(async () => {
    try {
      const res = await apiFetch('/api/v1/c2/profiles');
      if (res.ok) {
        const data = await res.json();
        setProfiles(data.profiles || []);
      }
    } catch (e) { console.error('Failed to fetch profiles:', e); }
  }, []);

  const fetchProfileDetail = useCallback(async (name) => {
    try {
      const res = await apiFetch(`/api/v1/c2/profiles/${encodeURIComponent(name)}`);
      if (res.ok) {
        const data = await res.json();
        setProfileDetail(data.profile);
      }
    } catch (e) { console.error('Failed to fetch profile detail:', e); }
  }, []);

  useEffect(() => {
    fetchBofs();
    fetchProfiles();
  }, [fetchBofs, fetchProfiles]);

  const profileIcons = {
    office365: '📧', amazon: '☁️', slack: '💬', cloudfront: '🌍', generic_cdn: '📦',
  };

  /* ── Render ───────────────────────────────────────────────── */
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar 
        title="C2 Command & Control Console" 
        actions={
          <>
            <Button variant="secondary" disabled title="Control-plane action unavailable">ADD LISTENER — DISABLED</Button>
            <Button variant="primary" disabled title="Artifact action unavailable">GENERATE PAYLOAD — DISABLED</Button>
          </>
        }
      />

      {/* Tab Bar */}
      <div style={{
        display: 'flex', gap: '0', padding: '0 32px', borderBottom: '1px solid var(--border-color)',
        background: 'var(--bg-card)',
      }}>
        {[
          { id: 'beacons', label: 'Beacons & Listeners', icon: <Wifi size={14} /> },
          { id: 'bofs', label: 'BOF Status', icon: <Crosshair size={14} /> },
          { id: 'profiles', label: 'Malleable Profiles', icon: <Globe size={14} /> },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              padding: '12px 20px',
              border: 'none',
              background: 'none',
              color: activeTab === tab.id ? 'var(--color-accent)' : 'var(--text-muted)',
              borderBottom: activeTab === tab.id ? '2px solid var(--color-accent)' : '2px solid transparent',
              cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: '8px',
              fontFamily: 'var(--font-mono)',
              fontSize: '13px',
              fontWeight: activeTab === tab.id ? 600 : 400,
              transition: 'all 0.2s ease',
            }}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {/* ════════════════ BEACONS TAB ════════════════ */}
      {activeTab === 'beacons' && (
        <div style={{ padding: '18px 32px', flex: 1 }}>
          <Card title="C2 Runtime Status">
            <div
              role="status"
              aria-live="polite"
              style={{
                minHeight: '260px', display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center', gap: '12px',
                textAlign: 'center', color: 'var(--text-muted)',
              }}
            >
              <Wifi size={42} style={{ color: 'var(--color-medium)' }} />
              <Badge severity="medium">DISABLED</Badge>
              <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                No listener or beacon runtime is connected to this dashboard
              </div>
              <div style={{ maxWidth: '620px', fontSize: '12px', lineHeight: 1.6 }}>
                Listener and beacon rows appear only when backed by an authenticated,
                canonical control-plane source. This page does not simulate active sessions.
              </div>
              <code style={{ fontSize: '11px' }}>c2_runtime_not_connected</code>
            </div>
          </Card>
        </div>
      )}

      {/* ════════════════ BOF EXECUTION BOUNDARY ════════════════ */}
      {activeTab === 'bofs' && (
        <div style={{ padding: '18px 32px', flex: 1 }}>
          <Card title="BOF Execution">
            <div
              role="status"
              aria-live="polite"
              style={{
                minHeight: '260px', display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center', gap: '12px',
                textAlign: 'center', color: 'var(--text-muted)',
              }}
            >
              <Shield size={42} style={{ color: 'var(--color-medium)' }} />
              <Badge severity="medium">{bofCapability.status.toUpperCase()}</Badge>
              <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                Dashboard-host BOF execution is disabled
              </div>
              <div style={{ maxWidth: '620px', fontSize: '12px', lineHeight: 1.6 }}>
                The ordinary dashboard API does not execute BOFs or inspect this host.
                Use a separately reviewed local-lab workflow when that capability is available.
              </div>
              <code style={{ fontSize: '11px' }}>
                {bofCapability.reason_code || 'local_bof_execution_disabled'}
              </code>
              <Button
                variant="secondary"
                style={{ padding: '5px 12px', fontSize: '11px' }}
                onClick={fetchBofs}
              >
                <RefreshCw size={12} /> REFRESH STATUS
              </Button>
              {bofs.length > 0 && bofCapability.enabled && (
                <div>Capability metadata is available, but execution remains outside this page.</div>
              )}
            </div>
          </Card>
        </div>
      )}

      {/* ════════════════ PROFILES TAB ════════════════ */}
      {activeTab === 'profiles' && (
        <div style={{ padding: '18px 32px', display: 'flex', gap: '14px', flex: 1, minHeight: 0 }}>
          {/* Profile List */}
          <div style={{ width: '420px', display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
            <Card title={`Malleable C2 Profiles (${profiles.length})`} noPadding>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {profiles.length === 0 ? (
                  <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    <Globe size={32} style={{ opacity: 0.3, marginBottom: '8px' }} />
                    <div>No profiles loaded</div>
                  </div>
                ) : profiles.map((p, i) => (
                  <div key={p.name}
                    onClick={() => {
                      setExpandedProfile(expandedProfile === p.name ? null : p.name);
                      fetchProfileDetail(p.name);
                    }}
                    style={{
                      padding: '14px 16px', borderBottom: '1px solid var(--border-color)',
                      cursor: 'pointer',
                      background: expandedProfile === p.name ? 'rgba(var(--accent-rgb, 99,102,241), 0.08)' : 'transparent',
                      transition: 'background 0.15s ease',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div style={{
                          width: '36px', height: '36px', borderRadius: '8px',
                          background: 'linear-gradient(135deg, var(--color-accent)22, var(--color-accent)44)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: '18px', border: '1px solid var(--color-accent)33',
                        }}>
                          {profileIcons[p.name] || '🔧'}
                        </div>
                        <div>
                          <div className="font-mono" style={{ fontWeight: 600, fontSize: '13px' }}>{p.name}</div>
                          <div className="text-muted" style={{ fontSize: '11px' }}>
                            {p.source === 'built-in' ? '📦 Built-in' : '📄 Custom'}
                            {p.author ? ` · ${p.author}` : ''}
                          </div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Badge>{p.source}</Badge>
                        {expandedProfile === p.name ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </div>
                    </div>
                    <div className="text-muted" style={{ fontSize: '11px', marginTop: '6px', lineHeight: '1.4' }}>
                      {p.description?.substring(0, 80)}{p.description?.length > 80 ? '...' : ''}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* Profile Detail */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
            {profileDetail ? (
              <>
                <Card title={`Profile: ${profileDetail.name}`}
                      headerRight={<Badge severity="active">LOADED</Badge>}>
                  <div style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '16px' }}>
                    {profileDetail.description}
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
                    <div style={{
                      padding: '14px', borderRadius: '8px',
                      background: 'var(--bg-surface, rgba(0,0,0,0.2))',
                      border: '1px solid var(--border-color)',
                    }}>
                      <div className="text-muted" style={{ fontSize: '11px', marginBottom: '4px' }}>SLEEP</div>
                      <div className="font-mono" style={{ fontSize: '20px', fontWeight: 700 }}>
                        {profileDetail.beacon?.sleep}s
                      </div>
                    </div>
                    <div style={{
                      padding: '14px', borderRadius: '8px',
                      background: 'var(--bg-surface, rgba(0,0,0,0.2))',
                      border: '1px solid var(--border-color)',
                    }}>
                      <div className="text-muted" style={{ fontSize: '11px', marginBottom: '4px' }}>JITTER</div>
                      <div className="font-mono" style={{ fontSize: '20px', fontWeight: 700 }}>
                        {profileDetail.beacon?.jitter}%
                      </div>
                    </div>
                    <div style={{
                      padding: '14px', borderRadius: '8px',
                      background: 'var(--bg-surface, rgba(0,0,0,0.2))',
                      border: '1px solid var(--border-color)',
                    }}>
                      <div className="text-muted" style={{ fontSize: '11px', marginBottom: '4px' }}>USER-AGENTS</div>
                      <div className="font-mono" style={{ fontSize: '20px', fontWeight: 700 }}>
                        {profileDetail.beacon?.user_agents?.length || 0}
                      </div>
                    </div>
                  </div>
                </Card>

                <Card title="HTTP GET Configuration" noPadding>
                  <div style={{ padding: '16px' }}>
                    <div className="text-muted" style={{ fontSize: '11px', marginBottom: '6px' }}>URIs</div>
                    {profileDetail.http_get?.uri?.map((uri, i) => (
                      <div key={i} className="font-mono" style={{
                        fontSize: '12px', padding: '6px 10px', marginBottom: '4px',
                        borderRadius: '4px', background: 'var(--bg-input)',
                        border: '1px solid var(--border-color)',
                      }}>{uri}</div>
                    ))}
                    <div className="text-muted" style={{ fontSize: '11px', margin: '12px 0 6px' }}>Transform</div>
                    <Badge>{profileDetail.http_get?.body_transform || 'none'}</Badge>
                    {profileDetail.http_get?.data_location !== 'body' && (
                      <Badge style={{ marginLeft: '6px' }}>data: {profileDetail.http_get?.data_location}</Badge>
                    )}
                  </div>
                </Card>

                <Card title="HTTP POST Configuration" noPadding>
                  <div style={{ padding: '16px' }}>
                    <div className="text-muted" style={{ fontSize: '11px', marginBottom: '6px' }}>URIs</div>
                    {profileDetail.http_post?.uri?.map((uri, i) => (
                      <div key={i} className="font-mono" style={{
                        fontSize: '12px', padding: '6px 10px', marginBottom: '4px',
                        borderRadius: '4px', background: 'var(--bg-input)',
                        border: '1px solid var(--border-color)',
                      }}>{uri}</div>
                    ))}
                    <div className="text-muted" style={{ fontSize: '11px', margin: '12px 0 6px' }}>Transform</div>
                    <Badge>{profileDetail.http_post?.body_transform || 'none'}</Badge>
                  </div>
                </Card>

                {profileDetail.ssl?.cert_cn && (
                  <Card title="SSL/TLS Certificate">
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '12px' }}>
                      <div><span className="text-muted">CN: </span><span className="font-mono">{profileDetail.ssl.cert_cn}</span></div>
                      <div><span className="text-muted">Org: </span><span className="font-mono">{profileDetail.ssl.cert_org}</span></div>
                    </div>
                  </Card>
                )}
              </>
            ) : (
              <Card style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <div style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                  <Layers size={48} style={{ opacity: 0.15, marginBottom: '16px' }} />
                  <div style={{ fontSize: '14px' }}>Select a profile to view configuration</div>
                  <div style={{ fontSize: '12px', marginTop: '6px', opacity: 0.6 }}>
                    Malleable profiles control how beacon traffic looks on the wire
                  </div>
                </div>
              </Card>
            )}
          </div>
        </div>
      )}

      <style>{`
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
};

export default C2Console;
