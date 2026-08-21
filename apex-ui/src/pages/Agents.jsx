import React, { useState } from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const agents = [];

const platforms = ['Windows', 'Linux', 'macOS', 'Android', 'iOS'];
const beaconTypes = ['HTTP', 'HTTPS', 'DNS', 'SMB'];

const Agents = () => {
  const [platform, setPlatform] = useState('Windows');
  const [beacon, setBeacon] = useState('HTTP');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar title="Agent Deployment & Management" />
      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>

        {/* ROW 1: Stat Cards */}
        <div style={{ display: 'flex', gap: '14px' }}>
          {[
            { label: 'ONLINE', value: 0, color: '#00c853' },
            { label: 'IDLE', value: 0, color: '#ffc400' },
            { label: 'OFFLINE', value: 0, color: 'var(--text-dimmed)' },
            { label: 'PLATFORMS', value: 0, color: '#2979ff' },
          ].map(s => (
            <Card key={s.label} style={{ flex: 1 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>{s.label}</div>
              <div style={{ fontFamily: 'var(--font-heading)', fontSize: '40px', fontWeight: 700, color: s.color, lineHeight: 1.2, marginTop: '4px' }}>{s.value}</div>
            </Card>
          ))}
        </div>

        {/* ROW 2: Two panels */}
        <div style={{ display: 'flex', gap: '14px', flex: 1 }}>
          {/* Active Agents Table */}
          <Card title="Active Agents" style={{ flex: 1 }} noPadding>
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>OS / Platform</th>
                  <th>IP</th>
                  <th>Version</th>
                  <th>Sleep</th>
                  <th>Type</th>
                  <th>Operator</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {agents.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                      No agents deployed — generate a payload to begin
                    </td>
                  </tr>
                ) : agents.map(a => (
                  <tr key={a.name}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 600, color: 'var(--color-brand-red)' }}>{a.name}</td>
                    <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{a.os}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{a.ip}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{a.ver}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{a.sleep}</td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{a.type}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-secondary)' }}>{a.op}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <div style={{
                          width: '8px', height: '8px', borderRadius: '50%',
                          backgroundColor: a.statusColor, flexShrink: 0,
                          boxShadow: a.status === 'ONLINE' ? `0 0 6px ${a.statusColor}` : 'none'
                        }} />
                        <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: a.statusColor }}>{a.status}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          {/* Deploy New Agent */}
          <Card title="Deploy New Agent" style={{ width: '340px', flexShrink: 0 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {/* Platform Picker */}
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>Platform</div>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  {platforms.map(p => (
                    <button
                      key={p}
                      onClick={() => setPlatform(p)}
                      style={{
                        padding: '5px 12px', borderRadius: '3px', cursor: 'pointer', border: 'none',
                        fontFamily: 'var(--font-mono)', fontSize: '11px',
                        backgroundColor: platform === p ? 'var(--color-brand-red)' : 'var(--bg-input)',
                        color: platform === p ? '#fff' : 'var(--text-muted)',
                        transition: 'all 0.2s'
                      }}
                    >{p}</button>
                  ))}
                </div>
              </div>

              {/* Beacon Type */}
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>Beacon Type</div>
                <div style={{ display: 'flex', gap: '6px' }}>
                  {beaconTypes.map(b => (
                    <button
                      key={b}
                      onClick={() => setBeacon(b)}
                      style={{
                        padding: '5px 12px', borderRadius: '3px', cursor: 'pointer', border: 'none',
                        fontFamily: 'var(--font-mono)', fontSize: '11px',
                        backgroundColor: beacon === b ? 'var(--color-brand-red)' : 'var(--bg-input)',
                        color: beacon === b ? '#fff' : 'var(--text-muted)',
                        transition: 'all 0.2s'
                      }}
                    >{b}</button>
                  ))}
                </div>
              </div>

              {/* Fields */}
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>Sleep Interval</div>
                <input type="text" defaultValue="" style={{ width: '100%', height: '36px' }} />
              </div>

              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>Evasion Profile</div>
                <select style={{ width: '100%', height: '36px' }}>
                  <option>Memory-only (no disk write)</option>
                  <option>Standard</option>
                  <option>Aggressive Evasion</option>
                </select>
              </div>

              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>Campaign</div>
                <select style={{ width: '100%', height: '36px' }}>
                  <option value="">Select campaign...</option>
                </select>
              </div>

              <Button variant="primary" fullWidth>Generate Payload</Button>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Agents;
