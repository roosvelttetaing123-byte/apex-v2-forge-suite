import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';

const users = [];

const permissions = [
  { name: 'Manage Users',    cols: [true, true, false, false, false] },
  { name: 'Manage Policies', cols: [true, true, false, false, false] },
  { name: 'Launch Scans',    cols: [true, true, true, false, false] },
  { name: 'View Findings',   cols: [true, true, true, true, true] },
  { name: 'Create Reports',  cols: [true, true, true, true, false] },
  { name: 'Manage Targets',  cols: [true, true, true, false, false] },
  { name: 'Red Team Ops',    cols: [true, false, true, false, false] },
  { name: 'Manage Agents',   cols: [true, false, true, false, false] },
];

const roles = ['Super Admin', 'Admin', 'Operator', 'Analyst', 'Read-Only'];

const Tick = ({ ok }) => (
  <span style={{ color: ok ? '#00c853' : 'var(--text-very-dim)', fontSize: '14px' }}>
    {ok ? '✓' : '—'}
  </span>
);

const TeamManagement = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar
        title="Team & Access Management"
        actions={<Button variant="primary">+ Invite User</Button>}
      />
      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>

        {/* ROW 1: Stat Cards */}
        <div style={{ display: 'flex', gap: '14px' }}>
          {[
            { label: 'TOTAL USERS', value: 0, color: '#2979ff' },
            { label: 'OPERATORS', value: 0, color: '#e53935' },
            { label: 'API KEYS', value: 0, color: '#ffc400' },
            { label: 'FAILED LOGINS', value: 0, color: '#00c853' },
          ].map(s => (
            <Card key={s.label} style={{ flex: 1 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>{s.label}</div>
              <div style={{ fontFamily: 'var(--font-heading)', fontSize: '40px', fontWeight: 700, color: s.color, lineHeight: 1.2, marginTop: '4px' }}>{s.value}</div>
            </Card>
          ))}
        </div>

        {/* ROW 2: Two panels */}
        <div style={{ display: 'flex', gap: '14px', flex: 1 }}>
          {/* Users Table */}
          <Card title="Users" style={{ flex: 1 }} noPadding>
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Email</th>
                  <th>Last Active</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {users.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '48px 0', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                      No users configured — invite a user to begin
                    </td>
                  </tr>
                ) : users.map(u => (
                  <tr key={u.username}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 500 }}>{u.username}</td>
                    <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{u.role}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{u.email}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--text-muted)' }}>{u.lastActive}</td>
                    <td><Badge severity="active">{u.status}</Badge></td>
                    <td>
                      <Button variant="secondary" style={{ fontSize: '11px', padding: '3px 10px' }}>Edit</Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          {/* Permissions Matrix */}
          <Card title="Role Permissions" style={{ width: '420px', flexShrink: 0 }} noPadding>
            <table>
              <thead>
                <tr>
                  <th>Permission</th>
                  {roles.map(r => (
                    <th key={r} style={{ textAlign: 'center', fontSize: '10px' }}>{r.replace(' ', '\n')}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {permissions.map(p => (
                  <tr key={p.name}>
                    <td style={{ fontSize: '12px' }}>{p.name}</td>
                    {p.cols.map((ok, i) => (
                      <td key={i} style={{ textAlign: 'center' }}><Tick ok={ok} /></td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default TeamManagement;
