import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const Scheduling = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar
        title="Scan Scheduling & Automation"
        subtitle="Calendar-driven scan scheduling with recurrence and operator assignment"
        actions={<Button variant="primary">+ SCHEDULE SCAN</Button>}
      />
      <div style={{ padding: '18px 32px', display: 'flex', gap: '14px', flex: 1, minHeight: 0 }}>
        {/* LEFT COLUMN: Calendar */}
        <div style={{ width: '360px', display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          <Card>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <Button variant="secondary" style={{ padding: '4px 8px' }}>&lt;</Button>
              <h3 style={{ fontSize: '16px', fontWeight: 600, margin: 0 }}>June 2026</h3>
              <Button variant="secondary" style={{ padding: '4px 8px' }}>&gt;</Button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: '4px', textAlign: 'center' }}>
              {['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'].map(day => (
                <div key={day} className="font-mono text-muted" style={{ fontSize: '10px', paddingBottom: '8px' }}>{day}</div>
              ))}
              {/* June 2026 starts on Monday — offset 1 empty Sunday cell */}
              <div />
              {Array.from({ length: 30 }).map((_, i) => {
                const date = i + 1;
                const today = new Date();
                const isToday = date === today.getDate() && today.getMonth() === 5;
                return (
                  <div key={i} style={{ 
                    aspectRatio: '1', 
                    display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                    backgroundColor: isToday ? 'var(--color-brand-red)' : 'var(--bg-input)',
                    color: isToday ? '#fff' : 'var(--text-primary)',
                    borderRadius: '4px',
                    position: 'relative',
                    cursor: 'pointer',
                    border: '1px solid var(--border-color)'
                  }}>
                    <span style={{ fontSize: '12px' }}>{date}</span>
                  </div>
                )
              })}
            </div>
          </Card>
        </div>

        {/* RIGHT COLUMN */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          <Card title="Upcoming Scans" noPadding>
            <table>
              <tbody>
                <tr>
                  <td colSpan={4} style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                    No scans scheduled — use the form below to schedule one
                  </td>
                </tr>
              </tbody>
            </table>
          </Card>

          <Card title="New Scheduled Scan">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
              <div>
                <label className="text-muted" style={{ display: 'block', marginBottom: '8px', fontSize: '12px' }}>Target</label>
                <select style={{ width: '100%' }}>
                  <option>Select Target...</option>
                </select>
              </div>
              <div>
                <label className="text-muted" style={{ display: 'block', marginBottom: '8px', fontSize: '12px' }}>Scan Profile</label>
                <select style={{ width: '100%' }}>
                  <option>Select Profile...</option>
                </select>
              </div>
              <div>
                <label className="text-muted" style={{ display: 'block', marginBottom: '8px', fontSize: '12px' }}>Date & Time</label>
                <input type="text" defaultValue="" placeholder="YYYY-MM-DD HH:MM" style={{ width: '100%' }} />
              </div>
              <div>
                <label className="text-muted" style={{ display: 'block', marginBottom: '8px', fontSize: '12px' }}>Recurrence</label>
                <select style={{ width: '100%' }}>
                  <option>One-time</option>
                  <option>Weekly</option>
                  <option>Monthly</option>
                </select>
              </div>
            </div>
            <Button variant="primary" fullWidth>SCHEDULE SCAN</Button>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Scheduling;
