import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';

const categories = [
  {
    label: 'SIEM Platforms',
    items: [
      { name: 'Splunk', desc: 'Forward findings and events to Splunk SIEM', status: 'Connected', dotColor: '#00c853' },
      { name: 'Elastic SIEM', desc: 'Elasticsearch / Kibana SIEM integration', status: 'Connected', dotColor: '#00c853' },
      { name: 'IBM QRadar', desc: 'QRadar offense and log source ingestion', status: 'Configured', dotColor: '#ffc400' },
      { name: 'MS Sentinel', desc: 'Azure Sentinel connector and analytics', status: 'Configured', dotColor: '#ffc400' },
    ]
  },
  {
    label: 'Ticketing & Alerting',
    items: [
      { name: 'Jira', desc: 'Auto-create and update issues from findings', status: 'Connected', dotColor: '#00c853' },
      { name: 'ServiceNow', desc: 'ITSM ticket creation for remediation', status: 'Connected', dotColor: '#00c853' },
      { name: 'GitHub Issues', desc: 'Create GitHub issues for dev team remediation', status: 'Configured', dotColor: '#ffc400' },
      { name: 'PagerDuty', desc: 'Critical finding escalation and on-call routing', status: 'Connected', dotColor: '#00c853' },
    ]
  },
  {
    label: 'CI/CD & DevSecOps',
    items: [
      { name: 'Jenkins', desc: 'Trigger security scans in Jenkins pipelines', status: 'Configured', dotColor: '#ffc400' },
      { name: 'GitHub Actions', desc: 'APEX scan step for GitHub Actions workflows', status: 'Configured', dotColor: '#ffc400' },
      { name: 'GitLab CI', desc: 'GitLab CI/CD security stage integration', status: 'Disconnected', dotColor: '#3d4f6e' },
      { name: 'DefectDojo', desc: 'Push findings to DefectDojo for deduplication', status: 'Connected', dotColor: '#00c853' },
    ]
  },
  {
    label: 'Security Tools & Threat Intel',
    items: [
      { name: 'Burp Suite', desc: 'Import Burp findings and sync scan configs', status: 'Connected', dotColor: '#00c853' },
      { name: 'Metasploit', desc: 'Trigger Metasploit modules for confirmed vulns', status: 'Configured', dotColor: '#ffc400' },
      { name: 'Shodan', desc: 'Asset discovery via Shodan internet scan data', status: 'Connected', dotColor: '#00c853' },
      { name: 'VirusTotal', desc: 'Reputation lookup for payloads and domains', status: 'Connected', dotColor: '#00c853' },
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
