import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import { Play } from 'lucide-react';

const C2Console = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar 
        title="C2 Command & Control Console" 
        actions={
          <>
            <Button variant="secondary">ADD LISTENER</Button>
            <Button variant="primary">GENERATE PAYLOAD</Button>
          </>
        }
      />
      <div style={{ padding: '18px 32px', display: 'flex', gap: '14px', flex: 1, minHeight: 0 }}>
        {/* LEFT COLUMN */}
        <div style={{ width: '520px', display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          <Card title="C2 Listeners" noPadding>
            <table>
              <tbody>
                {[
                  { name: 'HTTP Listener', addr: '0.0.0.0:80', type: 'HTTP', status: 'ACTIVE', color: 'active' },
                  { name: 'HTTPS Listener', addr: '0.0.0.0:443', type: 'HTTPS', status: 'ACTIVE', color: 'active' },
                  { name: 'DNS Beacon', addr: '0.0.0.0:53', type: 'DNS', status: 'ACTIVE', color: 'active' },
                  { name: 'SMB Named Pipe', addr: 'PIPE\\apex_svc', type: 'SMB', status: 'STANDBY', color: 'paused' },
                ].map((lst, i) => (
                  <tr key={i}>
                    <td style={{ width: '20px', paddingRight: 0 }}><div className={`status-dot bg-${lst.color}`}></div></td>
                    <td className="font-mono">{lst.name}</td>
                    <td className="font-mono text-muted">{lst.addr}</td>
                    <td><Badge>{lst.type}</Badge></td>
                    <td><Badge severity={lst.color}>{lst.status}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <Card title="Active Beacons" style={{ flex: 1 }} noPadding>
            <table>
              <thead>
                <tr>
                  <th style={{ width: '20px', paddingRight: 0 }}>●</th>
                  <th>Name</th>
                  <th>IP Address</th>
                  <th>OS</th>
                  <th>Proto</th>
                  <th>Sleep</th>
                  <th>Operator</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { name: 'GHOST-01', ip: '192.168.1.45', os: 'Windows 10 x64', proto: 'HTTP', sleep: '45s', op: 'Op_Carter', color: 'active' },
                  { name: 'SPECTER-02', ip: '10.0.1.12', os: 'Windows Server 2019', proto: 'HTTPS', sleep: '2m', op: 'Op_Torres', color: 'active' },
                  { name: 'WRAITH-03', ip: '172.16.8.3', os: 'Ubuntu 22.04', proto: 'DNS', sleep: '5m', op: 'Op_Carter', color: 'paused' },
                  { name: 'SHADE-04', ip: '192.168.1.201', os: 'macOS 14.2 Sonoma', proto: 'HTTP', sleep: '60s', op: 'Op_Reeves', color: 'active' },
                  { name: 'PHANTOM-05', ip: '10.10.5.22', os: 'Android 14', proto: 'HTTP', sleep: '10m', op: 'Op_Chen', color: 'active' },
                ].map((b, i) => (
                  <tr key={i}>
                    <td style={{ width: '20px', paddingRight: 0 }}><div className={`status-dot bg-${b.color}`}></div></td>
                    <td className="font-mono">{b.name}</td>
                    <td className="font-mono text-muted">{b.ip}</td>
                    <td className="text-muted" style={{ fontSize: '12px' }}>{b.os}</td>
                    <td><Badge>{b.proto}</Badge></td>
                    <td className="font-mono text-muted">{b.sleep}</td>
                    <td className="text-muted" style={{ fontSize: '12px' }}>{b.op}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>

        {/* RIGHT COLUMN */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          <Card title="MITRE ATT&CK Coverage">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px 24px' }}>
              {[
                { name: 'Initial Access', pct: 75, color: 'var(--color-high)' },
                { name: 'Execution', pct: 68, color: 'var(--color-high)' },
                { name: 'Persistence', pct: 82, color: 'var(--color-critical)' },
                { name: 'Privilege Escalation', pct: 60, color: 'var(--color-medium)' },
                { name: 'Defense Evasion', pct: 70, color: 'var(--color-high)' },
                { name: 'Credential Access', pct: 55, color: 'var(--color-info)' },
                { name: 'Discovery', pct: 90, color: 'var(--color-critical)' },
                { name: 'Lateral Movement', pct: 55, color: 'var(--color-info)' },
                { name: 'Collection', pct: 48, color: 'var(--color-info)' },
                { name: 'C&C', pct: 85, color: 'var(--color-critical)' },
                { name: 'Exfiltration', pct: 45, color: 'var(--color-info)' },
              ].map(item => (
                <div key={item.name}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '12px' }}>
                    <span className="text-muted">{item.name}</span>
                    <span className="font-mono">{item.pct}%</span>
                  </div>
                  <div style={{ height: '6px', backgroundColor: 'var(--bg-input)', borderRadius: '3px', overflow: 'hidden', position: 'relative', boxShadow: 'inset 0 1px 3px rgba(0,0,0,0.2)' }}>
                    <div style={{ width: `${item.pct}%`, height: '100%', background: `linear-gradient(90deg, transparent, ${item.color})`, position: 'relative' }}>
                      <div style={{ position: 'absolute', right: 0, top: 0, bottom: 0, width: '4px', backgroundColor: '#fff', opacity: 0.8, boxShadow: `0 0 8px ${item.color}` }}></div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
          <Card title="Post-Exploitation Modules" style={{ flex: 1 }} noPadding>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {[
                { name: 'Mimikatz', color: 'critical' },
                { name: 'BloodHound', color: 'high' },
                { name: 'Rubeus', color: 'high' },
                { name: 'Certify', color: 'medium' },
                { name: 'SharpHound', color: 'info' },
                { name: 'PowerShell TCP Shell', color: 'success' },
                { name: 'Covenant C2', color: 'default' },
                { name: 'SeatBelt', color: 'low' },
              ].map((mod, i) => (
                <div key={i} style={{ 
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between', 
                  padding: '12px 16px', borderBottom: '1px solid var(--border-color)',
                  cursor: 'pointer'
                }} className="hover-bg-subtle">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div className={`status-dot bg-${mod.color} ${mod.color === 'active' || mod.color === 'critical' ? 'pulse' : ''}`}></div>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span className="font-mono">{mod.name}</span>
                      <span className="text-muted font-mono" style={{ fontSize: '10px' }}>Privilege: {['Mimikatz', 'SeatBelt'].includes(mod.name) ? 'SYSTEM' : 'User'}</span>
                    </div>
                  </div>
                  <Button variant="secondary" style={{ padding: '6px 12px', fontSize: '12px', display: 'flex', gap: '6px', alignItems: 'center', border: '1px solid var(--border-secondary)' }}>
                    <Play size={12} /> <span style={{ fontFamily: 'var(--font-mono)' }}>EXECUTE</span>
                  </Button>
                </div>
              ))}
              <style>{`.hover-bg-subtle:hover { background-color: rgba(255,255,255,0.02); }`}</style>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default C2Console;
