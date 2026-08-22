import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const channels = [
  { name: 'Email', desc: 'SMTP delivery for alerts and digests', status: 'Disconnected', dotColor: '#3d4f6e' },
  { name: 'Slack', desc: 'Real-time channel notifications', status: 'Disconnected', dotColor: '#3d4f6e' },
  { name: 'PagerDuty', desc: 'On-call escalation and incident management', status: 'Disconnected', dotColor: '#3d4f6e' },
  { name: 'Webhook', desc: 'Custom HTTP POST endpoint delivery', status: 'Disconnected', dotColor: '#3d4f6e' },
  { name: 'MS Teams', desc: 'Microsoft Teams channel integration', status: 'Disconnected', dotColor: '#3d4f6e' },
  { name: 'Jira', desc: 'Auto-create tickets on new findings', status: 'Disconnected', dotColor: '#3d4f6e' },
];

const rules = [];

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
                  <Badge severity={ch.status === 'Connected' ? 'active' : ch.status === 'Configured' ? 'medium' : 'default'} style={{ marginLeft: 'auto' }}>
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
              {rules.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                    No alert rules configured — connect a channel and create rules
                  </td>
                </tr>
              ) : rules.map((r, i) => (
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
