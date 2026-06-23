import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Activity, Search, Shield, Target, Calendar,
  FileText, AlertTriangle, FileCheck, Bell,
  Layers, Users, Clock, Server,
  Smartphone, Crosshair, Terminal, Settings2
} from 'lucide-react';

const Sidebar = () => {
  const sections = [
    {
      label: 'OPERATIONS',
      items: [
        { path: '/', icon: Activity, label: 'Automated Scans', end: true },
        { path: '/red-teaming', icon: Crosshair, label: 'Red Teaming' },
        { path: '/c2-console', icon: Terminal, label: 'C2 Console' },
        { path: '/mobile', icon: Smartphone, label: 'Mobile Pentest' },
      ]
    },
    {
      label: 'RECON',
      items: [
        { path: '/scan-builder', icon: Settings2, label: 'Scan Builder' },
        { path: '/discovery', icon: Search, label: 'Discovery' },
        { path: '/targets', icon: Target, label: 'Targets' },
        { path: '/scans', icon: Shield, label: 'Scans' },
        { path: '/scheduling', icon: Calendar, label: 'Scheduling' },
      ]
    },
    {
      label: 'REPORTING',
      items: [
        { path: '/reports', icon: FileText, label: 'Reports' },
        { path: '/vulnerabilities', icon: AlertTriangle, label: 'Vulnerabilities' },
        { path: '/policies', icon: FileCheck, label: 'Policies' },
      ]
    },
    {
      label: 'PLATFORM',
      items: [
        { path: '/notifications', icon: Bell, label: 'Notifications' },
        { path: '/integrations', icon: Layers, label: 'Integrations' },
        { path: '/team', icon: Users, label: 'Team' },
        { path: '/activity', icon: Clock, label: 'Activity' },
        { path: '/agents', icon: Server, label: 'Agents' },
      ]
    }
  ];

  return (
    <aside style={{
      width: '240px',
      backgroundColor: 'var(--bg-sidebar)',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      flexShrink: 0,
      borderRight: '1px solid var(--border-color)',
    }}>
      {/* Top: Logo */}
      <div style={{ padding: '24px 20px', borderBottom: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ 
            width: '40px', height: '40px', 
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            position: 'relative'
          }}>
            <svg viewBox="0 0 24 24" fill="rgba(229,57,53,0.1)" stroke="var(--color-brand-red)" strokeWidth="1.5" style={{ position: 'absolute', width: '100%', height: '100%' }}>
              <polygon points="12 2 22 8 22 16 12 22 2 16 2 8 12 2" />
            </svg>
            <span style={{ color: 'var(--color-brand-red)', fontFamily: 'var(--font-heading)', fontSize: '20px', fontWeight: 700, zIndex: 1 }}>A</span>
          </div>
          <div>
            <h1 style={{ fontFamily: 'var(--font-heading)', letterSpacing: '2px', fontSize: '22px', margin: 0, lineHeight: 1 }}>APEX</h1>
            <div style={{ fontSize: '8px', color: '#4a5f80', marginTop: '4px', letterSpacing: '0.5px', lineHeight: 1.2 }}>
              ADVANCED<br/>PERSISTENT<br/>EXPLOITATION
            </div>
          </div>
        </div>
      </div>

      {/* Middle: Navigation */}
      <nav style={{ flex: 1, overflowY: 'auto', padding: '16px 0' }}>
        {sections.map((sec, idx) => (
          <div key={idx} style={{ marginBottom: '24px' }}>
            <div style={{ 
              fontFamily: 'var(--font-mono)', 
              fontSize: '10px', 
              color: 'var(--text-very-dim)', 
              padding: '0 24px', 
              marginBottom: '12px',
              textTransform: 'uppercase',
              letterSpacing: '1px'
            }}>
              {sec.label}
            </div>
            {sec.items.map((item, i) => (
              <NavLink
                key={i}
                to={item.path}
                end={item.end}
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                style={({ isActive }) => ({
                  display: 'flex',
                  alignItems: 'center',
                  padding: '10px 22px', // Adjusted for 2px border
                  color: isActive ? 'var(--text-primary)' : 'var(--text-dimmed)',
                  backgroundColor: isActive ? 'rgba(229,57,53,0.08)' : 'transparent',
                  borderLeft: isActive ? '2px solid var(--color-brand-red)' : '2px solid transparent',
                  textDecoration: 'none',
                  fontSize: '14px',
                  fontWeight: isActive ? 500 : 400,
                  transition: 'all 0.2s',
                  gap: '16px'
                })}
              >
                {({ isActive }) => {
                  const Icon = item.icon;
                  return (
                    <>
                      <Icon size={16} color={isActive ? 'var(--color-brand-red)' : 'var(--text-dimmed)'} />
                      <span>{item.label}</span>
                    </>
                  );
                }}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Bottom: User Avatar */}
      <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{ width: '32px', height: '32px', borderRadius: '50%', backgroundColor: 'var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Users size={16} color="var(--text-muted)" />
        </div>
        <div>
          <div style={{ fontFamily: 'var(--font-heading)', fontSize: '14px', fontWeight: 600 }}>OPERATOR_01</div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>ADMIN · GLOBAL SCOPE</div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
