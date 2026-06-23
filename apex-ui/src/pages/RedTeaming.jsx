import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const RedTeaming = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar 
        title="Red Team Operations" 
        subtitle="Managed adversarial simulation campaigns aligned with MITRE ATT&CK"
        actions={
          <>
            <Button variant="secondary">IMPORT CAMPAIGN</Button>
            <Button variant="primary">+ NEW CAMPAIGN</Button>
          </>
        }
      />
      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>
        {/* ROW 1: Stat Cards */}
        <div style={{ display: 'flex', gap: '14px' }}>
          {[
            { label: 'ACTIVE CAMPAIGNS', value: '3', color: 'var(--color-brand-red)' },
            { label: 'COMPROMISED HOSTS', value: '47', color: 'var(--color-critical)' },
            { label: 'TTPs EXECUTED', value: '124', color: 'var(--color-medium)' },
            { label: 'DAYS ACTIVE', value: '18', color: 'var(--color-low)' }
          ].map(stat => (
            <Card key={stat.label} style={{ flex: 1 }}>
              <div className="font-mono text-muted" style={{ fontSize: '10px' }}>{stat.label}</div>
              <div className="font-heading" style={{ fontSize: '32px', fontWeight: 600, color: stat.color }}>{stat.value}</div>
            </Card>
          ))}
        </div>

        {/* ROW 2: Campaigns Table */}
        <Card title="Campaigns" style={{ flex: 1 }} noPadding>
          <table>
            <thead>
              <tr>
                <th>Operation</th>
                <th>Target Organization</th>
                <th>Phase</th>
                <th>Operator</th>
                <th>Duration</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="font-mono">PHANTOM REACH</td>
                <td>Apex Bank Group</td>
                <td><div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div className="status-dot bg-high"></div> Lateral Movement</div></td>
                <td>Op_Carter</td>
                <td className="font-mono text-muted">12 days</td>
                <td><Badge severity="active">ACTIVE</Badge></td>
              </tr>
              <tr>
                <td className="font-mono">SILVER FOX</td>
                <td>NexusCorp Industries</td>
                <td><div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div className="status-dot bg-critical"></div> Initial Access</div></td>
                <td>Op_Torres</td>
                <td className="font-mono text-muted">5 days</td>
                <td><Badge severity="active">ACTIVE</Badge></td>
              </tr>
              <tr>
                <td className="font-mono">IRON VEIL</td>
                <td>GovDept Healthcare</td>
                <td><div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div className="status-dot bg-info"></div> Persistence</div></td>
                <td>Op_Reeves</td>
                <td className="font-mono text-muted">31 days</td>
                <td><Badge severity="active">ACTIVE</Badge></td>
              </tr>
              <tr>
                <td className="font-mono text-muted">DARK HARBOR</td>
                <td className="text-muted">RetailCo Global</td>
                <td className="text-muted"><div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div className="status-dot bg-dimmed"></div> Reconnaissance</div></td>
                <td className="text-muted">Op_Chen</td>
                <td className="font-mono text-muted">3 days</td>
                <td><Badge severity="paused">PAUSED</Badge></td>
              </tr>
              <tr>
                <td className="font-mono text-muted">GHOST WIRE</td>
                <td className="text-muted">TechVault Systems</td>
                <td className="text-muted"><div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div className="status-dot bg-dimmed"></div> Complete</div></td>
                <td className="text-muted">Op_Park</td>
                <td className="font-mono text-muted">45 days</td>
                <td><Badge severity="default">COMPLETED</Badge></td>
              </tr>
            </tbody>
          </table>
        </Card>

        {/* ROW 3: Side-by-side cards */}
        <div style={{ display: 'flex', gap: '14px', minHeight: '300px' }}>
          <Card title="ATT&CK Phase Coverage" style={{ flex: 1 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {[
                { phase: 'Reconnaissance', pct: 90 },
                { phase: 'Initial Access', pct: 75 },
                { phase: 'Execution', pct: 68 },
                { phase: 'Persistence', pct: 82 },
                { phase: 'Privilege Escalation', pct: 60 },
                { phase: 'Lateral Movement', pct: 55 },
                { phase: 'Exfiltration', pct: 45 }
              ].map(item => (
                <div key={item.phase}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '12px' }}>
                    <span className="text-muted">{item.phase}</span>
                    <span className="font-mono">{item.pct}%</span>
                  </div>
                  <div style={{ height: '6px', backgroundColor: 'var(--bg-input)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{ width: `${item.pct}%`, height: '100%', backgroundColor: item.pct > 80 ? 'var(--color-critical)' : item.pct > 60 ? 'var(--color-high)' : 'var(--color-info)' }}></div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
          <Card title="Recent Activity Feed" style={{ flex: 1 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {[
                { time: '14:32:01', op: 'PHANTOM REACH', action: 'New service created on 10.0.1.12', color: 'critical' },
                { time: '14:15:44', op: 'SILVER FOX', action: 'Spearphishing payload downloaded', color: 'high' },
                { time: '13:58:22', op: 'IRON VEIL', action: 'Scheduled task established (Persistence)', color: 'info' },
                { time: '13:44:11', op: 'PHANTOM REACH', action: 'Kerberoasting attack initiated', color: 'medium' },
                { time: '13:21:03', op: 'SILVER FOX', action: 'Initial callback received from target', color: 'active' }
              ].map((log, i) => (
                <div key={i} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                  <div className={`status-dot bg-${log.color}`} style={{ marginTop: '4px' }}></div>
                  <div>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'baseline' }}>
                      <span className="font-mono text-muted" style={{ fontSize: '11px' }}>{log.time}</span>
                      <span className="font-mono" style={{ fontSize: '11px', color: `var(--color-${log.color})` }}>[{log.op}]</span>
                    </div>
                    <div style={{ fontSize: '13px' }}>{log.action}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default RedTeaming;
