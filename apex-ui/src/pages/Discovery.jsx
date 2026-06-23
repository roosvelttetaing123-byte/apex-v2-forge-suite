import React from 'react';
import TopBar from '../components/TopBar';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import { Server, Activity, Layers, AlertTriangle } from 'lucide-react';

const Discovery = () => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <TopBar 
        title="Network Reconnaissance & Asset Discovery" 
        subtitle="Host enumeration, port scanning, service fingerprinting, OS detection"
        actions={
          <>
            <Button variant="secondary">EXPORT</Button>
            <Button variant="primary">SCAN NETWORK</Button>
          </>
        }
      />
      <div style={{ padding: '18px 32px', display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, overflowY: 'auto' }}>
        {/* ROW 1: Input Bar */}
        <div style={{ display: 'flex', gap: '12px' }}>
          <input 
            type="text" 
            defaultValue="10.0.0.0/16, 192.168.0.0/24" 
            style={{ flex: 1, height: '40px' }} 
          />
          <select style={{ height: '40px', width: '200px' }}>
            <option>Top 1000 Ports</option>
            <option>All 65535 Ports</option>
          </select>
          <Button variant="primary">SCAN NETWORK</Button>
        </div>

        {/* ROW 2: Stat Cards */}
        <div style={{ display: 'flex', gap: '14px' }}>
          {[
            { label: 'HOSTS ONLINE', value: '247', color: 'var(--color-success)', icon: Server, sparkline: [20, 30, 45, 60, 40, 80, 75] },
            { label: 'OPEN PORTS', value: '1,482', color: 'var(--color-info)', icon: Activity, sparkline: [50, 40, 60, 80, 70, 90, 85] },
            { label: 'SERVICES', value: '31', color: 'var(--color-medium)', icon: Layers, sparkline: [10, 15, 20, 25, 22, 30, 31] },
            { label: 'POTENTIAL VULNS', value: '14', color: 'var(--color-critical)', icon: AlertTriangle, sparkline: [2, 4, 3, 8, 5, 12, 14] }
          ].map(stat => (
            <Card key={stat.label} style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div className="font-mono text-muted" style={{ fontSize: '10px' }}>{stat.label}</div>
                  <div className="font-heading" style={{ fontSize: '32px', fontWeight: 600, color: stat.color, marginTop: '4px' }}>{stat.value}</div>
                </div>
                <div style={{ padding: '8px', borderRadius: '8px', backgroundColor: 'var(--bg-input)' }}>
                  <stat.icon size={20} color={stat.color} />
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-end', height: '24px', gap: '2px', marginTop: '12px' }}>
                {stat.sparkline.map((val, i) => (
                  <div key={i} style={{ 
                    flex: 1, 
                    backgroundColor: stat.color, 
                    height: `${val}%`,
                    opacity: 0.3 + (i * 0.1)
                  }}></div>
                ))}
              </div>
            </Card>
          ))}
        </div>

        {/* ROW 3: Host Table */}
        <Card title="Discovered Hosts" headerRight={
          <div style={{ display: 'flex', gap: '8px' }}>
            <Button variant="secondary" style={{ padding: '4px 8px', fontSize: '12px' }}>Export CSV</Button>
            <Button variant="secondary" style={{ padding: '4px 8px', fontSize: '12px' }}>Add to Targets</Button>
          </div>
        } style={{ flex: 1 }} noPadding>
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>OS / Fingerprint</th>
                <th>Open Ports</th>
                <th>Services</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {[
                { ip: '10.0.1.1', host: 'gateway.corp.local', os: 'Cisco IOS 15.6', ports: '22,80,443,8080', svcs: 'HTTP,SSH,HTTPS', risk: 'MEDIUM', color: 'medium' },
                { ip: '10.0.1.10', host: 'web-prod-01.corp.local', os: 'Ubuntu 22.04', ports: '22,80,443', svcs: 'HTTP,SSH,HTTPS', risk: 'CRITICAL', color: 'critical' },
                { ip: '10.0.1.12', host: 'db-master.corp.local', os: 'Windows Server 2019', ports: '1433,3389,445', svcs: 'MSSQL,RDP,SMB', risk: 'CRITICAL', color: 'critical' },
                { ip: '10.0.1.20', host: 'mail.corp.local', os: 'Ubuntu 20.04', ports: '25,110,143,993', svcs: 'SMTP,POP3,IMAP', risk: 'HIGH', color: 'high' },
                { ip: '10.0.1.34', host: 'fileserver.corp.local', os: 'Windows Server 2016', ports: '445,139,3389', svcs: 'SMB,NetBIOS,RDP', risk: 'HIGH', color: 'high' },
                { ip: '192.168.1.1', host: 'router.internal', os: 'OpenWRT 22.03', ports: '22,80,8080', svcs: 'SSH,HTTP', risk: 'MEDIUM', color: 'medium' },
                { ip: '192.168.1.45', host: 'workstation-04', os: 'Windows 10 22H2', ports: '135,445,3389', svcs: 'RPC,SMB,RDP', risk: 'MEDIUM', color: 'medium' },
              ].map((row, i) => (
                <tr key={i}>
                  <td className="font-mono">{row.ip}</td>
                  <td className="text-muted">{row.host}</td>
                  <td className="text-muted" style={{ fontSize: '12px' }}>{row.os}</td>
                  <td className="font-mono text-muted">{row.ports}</td>
                  <td className="text-muted" style={{ fontSize: '12px' }}>{row.svcs}</td>
                  <td><Badge severity={row.color}>{row.risk}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
};

export default Discovery;
