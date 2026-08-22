import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const events = [];

const ActivityLogs = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar title="Audit & Activity Log" />
      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>

        {/* Filter Bar */}
        <Card noPadding style={{ flexDirection: 'row', alignItems: 'center', padding: '12px 16px', gap: '12px' }}>
          <input
            type="text"
            placeholder="Search events..."
            style={{ flex: 1, height: '36px' }}
          />
          <select style={{ height: '36px', width: '140px' }}>
            <option>All Users</option>
          </select>
          <select style={{ height: '36px', width: '140px' }}>
            <option>All Events</option>
            <option>Scan Started</option>
            <option>Login Failed</option>
            <option>Beacon Connected</option>
          </select>
          <select style={{ height: '36px', width: '120px' }}>
            <option>Last 24h</option>
            <option>Last 7 days</option>
            <option>Last 30 days</option>
          </select>
          <Button variant="secondary" style={{ fontSize: '12px', padding: '6px 14px', flexShrink: 0 }}>Export Log</Button>
        </Card>

        {/* Event Log Table */}
        <Card style={{ flex: 1 }} noPadding>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>User</th>
                <th>Event</th>
                <th>Detail</th>
                <th>Source IP</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                    No activity recorded yet
                  </td>
                </tr>
              ) : events.map((e, i) => (
                <tr
                  key={i}
                  style={{
                    backgroundColor: e.blocked ? 'rgba(255,68,68,0.04)' : undefined,
                  }}
                >
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{e.time}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: e.user === 'unknown' ? 'var(--color-critical)' : 'var(--text-secondary)', fontWeight: 500 }}>{e.user}</td>
                  <td style={{ fontWeight: 500, fontSize: '13px' }}>{e.event}</td>
                  <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{e.detail}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{e.ip}</td>
                  <td>
                    <Badge severity={e.blocked ? 'critical' : 'active'}>{e.result}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
};

export default ActivityLogs;
