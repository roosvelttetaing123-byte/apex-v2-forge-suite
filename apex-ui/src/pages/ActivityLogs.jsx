import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const events = [
  { time: '14:32:01', user: 'Op_Carter', event: 'Scan Started', detail: 'SC-1043 on web-prod-01', ip: '192.168.1.5', result: 'SUCCESS', blocked: false },
  { time: '14:15:44', user: 'Op_Torres', event: 'Report Generated', detail: 'RPT-2041 Executive Summary', ip: '10.0.1.8', result: 'SUCCESS', blocked: false },
  { time: '13:58:22', user: 'System', event: 'Auto-Scan Triggered', detail: 'SC-1044 Cloud Config AWS', ip: 'internal', result: 'SUCCESS', blocked: false },
  { time: '13:44:11', user: 'Op_Reeves', event: 'Target Added', detail: 'production-db-02 to Corp Infra', ip: '192.168.1.12', result: 'SUCCESS', blocked: false },
  { time: '13:21:03', user: 'admin', event: 'User Created', detail: 'op_reeves@company.com (Operator)', ip: '10.0.0.2', result: 'SUCCESS', blocked: false },
  { time: '12:55:34', user: 'Op_Carter', event: 'Beacon Connected', detail: 'GHOST-01 @ 192.168.1.45', ip: 'C2 Server', result: 'SUCCESS', blocked: false },
  { time: '12:33:48', user: 'Op_Chen', event: 'Policy Updated', detail: 'OWASP Top 10 rules modified', ip: '10.0.1.15', result: 'SUCCESS', blocked: false },
  { time: '11:47:29', user: 'unknown', event: 'Login Failed (×3)', detail: '3 failed attempts detected', ip: '185.220.101.4', result: 'BLOCKED', blocked: true },
];

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
            <option>Op_Carter</option>
            <option>Op_Torres</option>
            <option>System</option>
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
              {events.map((e, i) => (
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
