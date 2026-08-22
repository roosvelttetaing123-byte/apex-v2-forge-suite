import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';

const categories = [
  {
    label: 'SIEM Platforms',
    items: [
      { name: 'Splunk', desc: 'Forward findings and events to Splunk SIEM', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'Elastic SIEM', desc: 'Elasticsearch / Kibana SIEM integration', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'IBM QRadar', desc: 'QRadar offense and log source ingestion', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'MS Sentinel', desc: 'Azure Sentinel connector and analytics', status: 'Disconnected', dotColor: '#3d4f6e' },
    ]
  },
  {
    label: 'Ticketing & Alerting',
    items: [
      { name: 'Jira', desc: 'Auto-create and update issues from findings', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'ServiceNow', desc: 'ITSM ticket creation for remediation', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'GitHub Issues', desc: 'Create GitHub issues for dev team remediation', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'PagerDuty', desc: 'Critical finding escalation and on-call routing', status: 'Disconnected', dotColor: '#3d4f6e' },
    ]
  },
  {
    label: 'CI/CD & DevSecOps',
    items: [
      { name: 'Jenkins', desc: 'Trigger security scans in Jenkins pipelines', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'GitHub Actions', desc: 'APEX scan step for GitHub Actions workflows', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'GitLab CI', desc: 'GitLab CI/CD security stage integration', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'DefectDojo', desc: 'Push findings to DefectDojo for deduplication', status: 'Disconnected', dotColor: '#3d4f6e' },
    ]
  },
  {
    label: 'Security Tools & Threat Intel',
    items: [
      { name: 'Burp Suite', desc: 'Import Burp findings and sync scan configs', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'Metasploit', desc: 'Trigger Metasploit modules for confirmed vulns', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'Shodan', desc: 'Asset discovery via Shodan internet scan data', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'VirusTotal', desc: 'Reputation lookup for payloads and domains', status: 'Disconnected', dotColor: '#3d4f6e' },
    ]
  },
];

const statusColor = (s) => {
  if (s === 'Connected') return 'active';
  if (s === 'Configured') return 'medium';
  return 'default';
};

const Integrations = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar title="Third-Party Integrations" />
      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '24px', flex: 1, overflowY: 'auto' }}>
        {categories.map(cat => (
          <div key={cat.label}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px'
            }}>
              {cat.label}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
              {cat.items.map(item => (
                <Card key={item.name} style={{ opacity: item.status === 'Disconnected' ? 0.5 : 1 }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: item.dotColor, flexShrink: 0 }} />
                      <span style={{ fontFamily: 'var(--font-heading)', fontSize: '14px', fontWeight: 600, flex: 1 }}>{item.name}</span>
                    </div>
                    <p style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>{item.desc}</p>
                    <Badge severity={statusColor(item.status)} style={{ alignSelf: 'flex-start' }}>{item.status}</Badge>
                  </div>
                </Card>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Integrations;
