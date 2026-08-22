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
            { label: 'ACTIVE CAMPAIGNS', value: '0', color: 'var(--color-brand-red)' },
            { label: 'COMPROMISED HOSTS', value: '0', color: 'var(--color-critical)' },
            { label: 'TTPs EXECUTED', value: '0', color: 'var(--color-medium)' },
            { label: 'DAYS ACTIVE', value: '0', color: 'var(--color-low)' }
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
                <td colSpan={6} style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                  No campaigns — create a new campaign to begin
                </td>
              </tr>
            </tbody>
          </table>
        </Card>

        {/* ROW 3: Side-by-side cards */}
        <div style={{ display: 'flex', gap: '14px', minHeight: '300px' }}>
          <Card title="ATT&CK Phase Coverage" style={{ flex: 1 }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {[
                { phase: 'Reconnaissance', pct: 0 },
                { phase: 'Initial Access', pct: 0 },
                { phase: 'Execution', pct: 0 },
                { phase: 'Persistence', pct: 0 },
                { phase: 'Privilege Escalation', pct: 0 },
                { phase: 'Lateral Movement', pct: 0 },
                { phase: 'Exfiltration', pct: 0 }
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
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
              No recent activity
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default RedTeaming;
