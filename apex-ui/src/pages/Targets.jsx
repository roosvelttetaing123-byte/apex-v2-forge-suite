import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const Targets = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar
        title="Target Management"
        subtitle="Define scope, manage asset groups, and configure engagement parameters"
        actions={
          <>
            <Button variant="secondary">IMPORT SCOPE</Button>
            <Button variant="primary">+ ADD TARGET</Button>
          </>
        }
      />
      <div style={{ padding: '18px 32px', display: 'flex', gap: '14px', flex: 1, minHeight: 0 }}>
        {/* LEFT COLUMN: Target Groups */}
        <div style={{ width: '320px', display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          <Card title="Target Groups" noPadding>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {[
                { name: 'Corporate Infrastructure', badge: 'CRITICAL', count: 3, active: true, color: 'critical' },
                { name: 'Cloud Assets AWS', badge: 'HIGH', count: 12, active: false, color: 'high' },
                { name: 'External Web Apps', badge: 'HIGH', count: 5, active: false, color: 'high' },
                { name: 'Mobile Applications', badge: 'MEDIUM', count: 4, active: false, color: 'medium' },
                { name: 'Partner Network', badge: 'LOW', count: 8, active: false, color: 'low' },
              ].map(group => (
                <div key={group.name} style={{ 
                  padding: '12px 16px', 
                  borderBottom: '1px solid var(--border-color)',
                  backgroundColor: group.active ? 'rgba(255,255,255,0.03)' : 'transparent',
                  borderLeft: group.active ? '3px solid var(--color-brand-red)' : '3px solid transparent',
                  cursor: 'pointer'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span style={{ fontWeight: group.active ? 600 : 400, color: group.active ? 'var(--text-primary)' : 'var(--text-secondary)' }}>{group.name}</span>
                  </div>
                  <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    <Badge severity={group.color}>{group.badge}</Badge>
                    <span className="font-mono text-muted" style={{ fontSize: '11px' }}>{group.count} assets</span>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* RIGHT COLUMN: Detail View */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          <Card>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '24px' }}>
              <h3 style={{ fontSize: '20px', fontWeight: 600, margin: 0 }}>Corporate Infrastructure</h3>
              <Badge severity="critical">CRITICAL</Badge>
              <span className="text-muted" style={{ fontSize: '12px', marginLeft: 'auto' }}>Last assessed 14 days ago</span>
            </div>
            
            <div style={{ display: 'flex', gap: '24px', flex: 1 }}>
              {/* Assets List */}
              <div style={{ flex: 1 }}>
                <h4 style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '12px', fontFamily: 'var(--font-mono)' }}>Assets</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {[
                    { name: 'web-prod-01.internal', os: 'Linux Ubuntu 22.04', dot: 'critical' },
                    { name: 'db-cluster-main', os: 'Windows Server 2019', dot: 'critical' },
                    { name: 'endpoint-subnet-A', os: '172.16.0.0/22', dot: 'medium' },
                    { name: 'backup-server-01', os: 'Linux Debian 11', dot: 'success' },
                  ].map(asset => (
                    <div key={asset.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px', backgroundColor: 'var(--bg-input)', borderRadius: '4px', border: '1px solid var(--border-color)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div className={`status-dot bg-${asset.dot}`}></div>
                        <span className="font-mono">{asset.name}</span>
                      </div>
                      <span className="text-muted" style={{ fontSize: '12px' }}>{asset.os}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Scope & Rules */}
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <Card title="Scope Definition" style={{ backgroundColor: 'var(--bg-input)' }}>
                  <div style={{ marginBottom: '12px' }}>
                    <div className="text-success font-mono" style={{ fontSize: '11px', marginBottom: '4px' }}>IN-SCOPE</div>
                    <div className="font-mono" style={{ fontSize: '13px', lineHeight: 1.6 }}>
                      10.0.1.0/24<br/>
                      *.corp.local<br/>
                      api.corp.com<br/>
                      admin.corp.com
                    </div>
                  </div>
                  <div>
                    <div className="text-critical font-mono" style={{ fontSize: '11px', marginBottom: '4px' }}>OUT-OF-SCOPE</div>
                    <div className="font-mono" style={{ fontSize: '13px', lineHeight: 1.6, color: 'var(--text-muted)' }}>
                      10.0.2.0/24<br/>
                      prod-backup-01<br/>
                      *.payment.corp.com
                    </div>
                  </div>
                </Card>
                <Card title="Rules of Engagement" style={{ backgroundColor: 'var(--bg-input)' }}>
                  <ul style={{ color: 'var(--text-muted)', fontSize: '13px', lineHeight: 1.6, margin: 0, paddingLeft: '20px' }}>
                    <li>No destructive payloads without prior approval</li>
                    <li>Testing windows: Mon-Fri 02:00–06:00 UTC</li>
                    <li>Max 4h continuous scan per target</li>
                    <li>Escalate any production impact immediately</li>
                    <li>DoS/DDoS testing strictly prohibited</li>
                  </ul>
                </Card>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Targets;
