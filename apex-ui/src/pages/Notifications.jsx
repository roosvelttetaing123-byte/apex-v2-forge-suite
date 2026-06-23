import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const channels = [
  { name: 'Email', desc: 'SMTP delivery for alerts and digests', status: 'Connected', dotColor: '#00c853' },
  { name: 'Slack', desc: 'Real-time channel notifications', status: 'Connected', dotColor: '#00c853' },
  { name: 'PagerDuty', desc: 'On-call escalation and incident management', status: 'Connected', dotColor: '#00c853' },
  { name: 'Webhook', desc: 'Custom HTTP POST endpoint delivery', status: 'Connected', dotColor: '#00c853' },
  { name: 'MS Teams', desc: 'Microsoft Teams channel integration', status: 'Configured', dotColor: '#ffc400' },
  { name: 'Jira', desc: 'Auto-create tickets on new findings', status: 'Configured', dotColor: '#ffc400' },
];

const rules = [
  { trigger: 'New CRITICAL Finding', via: 'Slack, PagerDuty', freq: 'Immediate', scope: 'All scans', active: true },
  { trigger: 'Scan Completed', via: 'Email, Slack', freq: 'Immediate', scope: 'All scans', active: true },
  { trigger: 'New HIGH Finding', via: 'Email, Slack', freq: 'Hourly Digest', scope: 'All scans', active: true },
  { trigger: 'New Asset Discovered', via: 'Slack', freq: 'Daily Digest', scope: 'Discovery scans', active: true },
  { trigger: 'Scan Failed / Aborted', via: 'PagerDuty, Email', freq: 'Immediate', scope: 'All scans', active: true },
  { trigger: 'Beacon Connected (C2)', via: 'Slack, PagerDuty', freq: 'Immediate', scope: 'Red Team ops', active: true },
];

const Notifications = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar title="Alert Management" />
      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>

        {/* ROW 1: Channel Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '14px' }}>
          {channels.map(ch => (
            <Card key={ch.name}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: ch.dotColor, flexShrink: 0 }} />
                  <span style={{ fontFamily: 'var(--font-heading)', fontSize: '15px', fontWeight: 600 }}>{ch.name}</span>
                  <Badge severity={ch.status === 'Connected' ? 'active' : 'medium'} style={{ marginLeft: 'auto' }}>
                    {ch.status}
                  </Badge>
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>{ch.desc}</p>
                <Button variant="secondary" style={{ fontSize: '12px', padding: '5px 10px', alignSelf: 'flex-start' }}>
                  Configure
                </Button>
              </div>
            </Card>
          ))}
        </div>

        {/* ROW 2: Alert Rules Table */}
        <Card title="Alert Rules" style={{ flex: 1 }} noPadding>
          <table>
            <thead>
              <tr>
                <th>Trigger Condition</th>
                <th>Notify Via</th>
                <th>Frequency</th>
                <th>Scope</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 500 }}>{r.trigger}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-secondary)' }}>{r.via}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{r.freq}</td>
                  <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{r.scope}</td>
                  <td><Badge severity="active">Active</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
};

export default Notifications;
