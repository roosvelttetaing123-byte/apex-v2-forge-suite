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
              <div style={{ 
                padding: '32px 16px', 
                textAlign: 'center',
                color: 'var(--text-muted)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
              }}>
                No target groups defined — add a target to begin
              </div>
            </div>
          </Card>
        </div>

        {/* RIGHT COLUMN: Detail View */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          <Card>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '200px', color: 'var(--text-muted)', flexDirection: 'column', gap: '12px' }}>
              <div style={{ fontSize: '16px' }}>Select or create a target group</div>
              <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)' }}>Use "+ ADD TARGET" to define your engagement scope</div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Targets;
